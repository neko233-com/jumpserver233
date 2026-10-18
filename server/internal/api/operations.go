package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"

	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
)

var errJobLoginPending = errors.New("job login review pending")

func jobOwnerSnapshot(d Dependencies, user coreauth.User) (coreauth.User, bool) {
	current, ok := jobOwner(d, user.ID)
	return current, ok && current.AuthGeneration == user.AuthGeneration
}

func jobOwner(d Dependencies, id string) (coreauth.User, bool) {
	user, ok := d.Auth.ActiveUserByID(id)
	if !ok && ((id == "admin-token" && d.AdminToken != "") || (id == "loopback-admin" && d.AdminToken == "" && d.Auth.BootstrapRequired())) {
		return coreauth.User{ID: id, Username: "admin", Role: coreauth.RoleAdmin}, true
	}
	return user, ok
}
func registerOperationRoutes(mux *http.ServeMux, d Dependencies, authorize func(coreauth.User, string, string, accesspolicies.Origin) (string, string, commandfilters.Decision, int), accessMu *sync.RWMutex) {
	registerCalendarRoutes(mux, d, authorize, accessMu)
	registerPlaybookRoutes(mux, d, authorize, accessMu)
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	visible := func(r *http.Request, user coreauth.User, owner, permission string) bool {
		return hasPermission(r, permission) || user.ID == owner
	}
	mux.Handle("GET /api/v1/ops/templates", protect(func(w http.ResponseWriter, r *http.Request) {
		user, _ := PrincipalFromContext(r.Context())
		writeJSON(w, http.StatusOK, d.Operations.Templates(user.ID))
	}))
	saveTemplate := func(w http.ResponseWriter, r *http.Request) {
		var in operations.TemplateInput
		if decodeRequestJSON(w, r, &in) != nil {
			writeJobError(w, operations.ErrInvalid)
			return
		}
		user, _ := PrincipalFromContext(r.Context())
		t, err := d.Operations.SaveTemplate(r.PathValue("templateID"), user.ID, user.Username, in)
		if err != nil {
			writeJobError(w, err)
			return
		}
		status := http.StatusOK
		if r.Method == http.MethodPost {
			status = http.StatusCreated
		}
		writeJSON(w, status, t)
	}
	mux.Handle("POST /api/v1/ops/templates", protect(saveTemplate))
	mux.Handle("PUT /api/v1/ops/templates/{templateID}", protect(saveTemplate))
	mux.Handle("DELETE /api/v1/ops/templates/{templateID}", protect(func(w http.ResponseWriter, r *http.Request) {
		revision, err := strconv.Atoi(r.URL.Query().Get("revision"))
		if err != nil || revision < 1 {
			writeJobError(w, operations.ErrInvalid)
			return
		}
		user, _ := PrincipalFromContext(r.Context())
		if err := d.Operations.DeleteTemplate(r.PathValue("templateID"), user.ID, revision); err != nil {
			writeJobError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.Handle("GET /api/v1/ops/plans", protect(func(w http.ResponseWriter, r *http.Request) {
		user, _ := PrincipalFromContext(r.Context())
		owner := user.ID
		if hasPermission(r, "plans.view_all") || hasPermission(r, "plans.manage_all") {
			owner = ""
		}
		if r.URL.Query().Has("offset") || r.URL.Query().Has("limit") {
			offset, e := strconv.Atoi(defaultQuery(r, "offset", "0"))
			limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "50"))
			if e != nil || e2 != nil {
				writeJobError(w, operations.ErrInvalid)
				return
			}
			rows, total, e := d.Operations.PlanPage(owner, offset, limit)
			if e != nil {
				writeJobError(w, e)
				return
			}
			writeJSON(w, 200, map[string]any{"results": rows, "total": total})
			return
		}
		writeJSON(w, http.StatusOK, d.Operations.Plans(owner))
	}))
	mux.Handle("POST /api/v1/ops/plans", protect(func(w http.ResponseWriter, r *http.Request) {
		var in operations.PlanInput
		if decodeRequestJSON(w, r, &in) != nil {
			writeJobError(w, operations.ErrInvalid)
			return
		}
		user, _ := PrincipalFromContext(r.Context())
		in.Origin = accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "scheduled_exec"}
		if in.Kind == "batch" {
			in.Origin.Method = "exec"
		}
		if prior, found, e := d.Operations.ReplayPlan(user.ID, in); found {
			if e != nil {
				writeJobError(w, e)
				return
			}
			writeJSON(w, http.StatusCreated, prior)
			return
		}
		prepared, revision, err := d.Operations.Prepare(user.ID, in)
		if err != nil {
			writeJobError(w, err)
			return
		}
		prepared.Origin = accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "scheduled_exec"}
		if prepared.PlaybookID != "" {
			prepared.Inventory = map[string]string{}
			for _, id := range prepared.AssetIDs {
				if asset, e := d.Assets.Get(id); e == nil {
					prepared.Inventory[id] = asset.Name
				}
			}
		}
		if prepared.Kind == "batch" {
			prepared.Origin.Method = "exec"
		}
		accessMu.RLock()
		defer accessMu.RUnlock()
		for _, assetID := range prepared.AssetIDs {
			_, _, _, status := authorize(user, assetID, prepared.Command, prepared.Origin)
			if status != http.StatusOK {
				writeJobError(w, operations.ErrDenied)
				return
			}
		}
		p, err := d.Operations.CreatePlan(user.ID, user.Username, prepared, revision)
		if err != nil {
			writeJobError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, p)
	}))
	mux.Handle("PUT /api/v1/ops/plans/{planID}", protect(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Enabled  *bool `json:"enabled"`
			Revision int   `json:"revision"`
		}
		if decodeRequestJSON(w, r, &in) != nil || in.Enabled == nil {
			writeJobError(w, operations.ErrInvalid)
			return
		}
		p, err := d.Operations.Plan(r.PathValue("planID"))
		user, _ := PrincipalFromContext(r.Context())
		if err != nil || !visible(r, user, p.OwnerID, "plans.manage_all") {
			writeJobError(w, operations.ErrNotFound)
			return
		}
		if p.Discovery != nil {
			accessMu.Lock()
			defer accessMu.Unlock()
			if *in.Enabled && !canResumeDiscoveryPlan(d, r, p) {
				writeJobError(w, operations.ErrDenied)
				return
			}
			updated, e := d.Operations.UpdateDiscoveryCollector(p.ID, in.Revision, *in.Enabled, p.IntervalSeconds)
			if e != nil {
				writeJobError(w, e)
				return
			}
			if !updated.Enabled {
				if e := cancelDiscoveryApprovals(d, updated); e != nil {
					writeJSON(w, 503, map[string]string{"detail": "access review cancellation unavailable"})
					return
				}
			}
			writeJSON(w, 200, updated)
			return
		}
		release := lockCalendarAccess(d, accessMu)
		defer release()
		if *in.Enabled && !authorizeCalendarOwner(d, p, authorize) {
			writeJobError(w, operations.ErrDenied)
			return
		}
		updated, updateError := d.Operations.SetEnabledRevision(p.ID, *in.Enabled, in.Revision, operations.ScheduleActor{ID: user.ID, Name: user.Username})
		if updateError != nil {
			writeJobError(w, updateError)
			return
		}
		writeJSON(w, http.StatusOK, updated)
	}))
	mux.Handle("GET /api/v1/ops/runs", protect(func(w http.ResponseWriter, r *http.Request) {
		limit, offset := 50, 0
		var err error
		if v := r.URL.Query().Get("limit"); v != "" {
			limit, err = strconv.Atoi(v)
		}
		if err == nil {
			if v := r.URL.Query().Get("offset"); v != "" {
				offset, err = strconv.Atoi(v)
			}
		}
		if err != nil || limit < 1 || limit > 100 || offset < 0 {
			writeJobError(w, operations.ErrInvalid)
			return
		}
		user, _ := PrincipalFromContext(r.Context())
		owner := user.ID
		if hasPermission(r, "plans.view_all") {
			owner = ""
		}
		items, total := d.Operations.Runs(owner, offset, limit)
		for i := range items {
			items[i] = operations.PublicRun(items[i])
		}
		writeJSON(w, http.StatusOK, map[string]any{"results": items, "total": total})
	}))
	getRun := func(w http.ResponseWriter, r *http.Request) (operations.Run, bool) {
		run, err := d.Operations.Run(r.PathValue("runID"))
		if err != nil && r.Method == http.MethodGet && d.AgentEvents != nil {
			if receipt, ok := d.AgentEvents.LatestReceipt(r.PathValue("runID")); ok {
				err = json.Unmarshal(receipt.Run, &run)
			}
		}
		if err != nil && r.Method == http.MethodGet && d.AccountDiscovery != nil {
			if receipt, ok := d.AccountDiscovery.LatestCollection(r.PathValue("runID")); ok {
				err = json.Unmarshal(receipt.Run, &run)
			}
		}
		user, _ := PrincipalFromContext(r.Context())
		permission := "plans.view_all"
		if r.Method == http.MethodPost {
			permission = "plans.manage_all"
		}
		if err != nil || !visible(r, user, run.OwnerID, permission) {
			writeJobError(w, operations.ErrNotFound)
			return operations.Run{}, false
		}
		return run, true
	}
	mux.Handle("GET /api/v1/ops/runs/{runID}", protect(func(w http.ResponseWriter, r *http.Request) {
		if run, ok := getRun(w, r); ok {
			writeJSON(w, http.StatusOK, operations.PublicRun(run))
		}
	}))
	mux.Handle("POST /api/v1/ops/runs/{runID}/cancel", protect(func(w http.ResponseWriter, r *http.Request) {
		run, ok := getRun(w, r)
		if !ok {
			return
		}
		if err := d.Operations.CancelRun(run.ID); err != nil {
			writeJobError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
}
