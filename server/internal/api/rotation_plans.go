package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/core/rotationplans"
)

func rotationPlanError(w http.ResponseWriter, e error) {
	status, code := 503, "unavailable"
	switch {
	case errors.Is(e, rotationplans.ErrInvalid), errors.Is(e, assets.ErrInvalidInput):
		status, code = 400, "invalid"
	case errors.Is(e, rotationplans.ErrNotFound), errors.Is(e, assets.ErrNotFound):
		status, code = 404, "not_found"
	case errors.Is(e, rotationplans.ErrConflict), errors.Is(e, assets.ErrCredentialChanged):
		status, code = 409, "conflict"
	case errors.Is(e, rotationplans.ErrDenied), errors.Is(e, accesspolicies.ErrDenied):
		status, code = 403, "denied"
	case errors.Is(e, rotationplans.ErrBusy), errors.Is(e, assets.ErrRotationInProgress):
		status, code = 409, "busy"
	case errors.Is(e, rotationplans.ErrCapacity):
		status, code = 429, "capacity"
	}
	writeJSON(w, status, map[string]string{"error_code": code})
}
func registerRotationPlanRoutes(mux *http.ServeMux, d Dependencies, mu *sync.RWMutex) {
	if d.RotationPlans == nil || d.Assets == nil || d.Auth == nil {
		return
	}
	service := d.RotationPlans
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	current := func(id, permission string) (coreauth.User, rbac.Snapshot, error) {
		u, ok := jobOwner(d, id)
		if !ok || d.OrganizationAllowed != nil && !d.OrganizationAllowed(u) {
			return u, rbac.Snapshot{}, rotationplans.ErrDenied
		}
		p := effectivePermissions(u, d.RBAC, d.Groups)
		if !p.Allows(permission) || !p.Allows("assets.view_all") {
			return u, p, rotationplans.ErrDenied
		}
		return u, p, nil
	}
	actor := func(u coreauth.User) rotationplans.Actor { return rotationplans.Actor{ID: u.ID, Name: u.Username} }
	requestUser := func(w http.ResponseWriter, r *http.Request, permission string) (coreauth.User, rbac.Snapshot, bool) {
		setNoStore(w)
		principal, ok := PrincipalFromContext(r.Context())
		if !ok {
			rotationPlanError(w, rotationplans.ErrDenied)
			return principal, rbac.Snapshot{}, false
		}
		if _, live := jobOwnerSnapshot(d, principal); !live {
			rotationPlanError(w, rotationplans.ErrDenied)
			return principal, rbac.Snapshot{}, false
		}
		u, p, e := current(principal.ID, permission)
		if e != nil {
			rotationPlanError(w, e)
			return u, p, false
		}
		return u, p, true
	}
	lockAccess := func() func() {
		global := d.GlobalAccessMu
		if global != nil && global != mu {
			global.RLock()
		}
		mu.RLock()
		return func() {
			mu.RUnlock()
			if global != nil && global != mu {
				global.RUnlock()
			}
		}
	}
	authorize := func(a rotationplans.Actor) error {
		_, p, e := current(a.ID, "accounts.rotation.execute")
		if e != nil || !p.Allows("assets.rotate") {
			return rotationplans.ErrDenied
		}
		return nil
	}
	credentialStep := func(ctx context.Context, in rotationplans.Intent, as rotationplans.Actor, guard func() error, recover bool) (rotationplans.Outcome, error) {
		// Serialize publication of role/org changes with a single credential step.
		// Locks are released between accounts; plan result persistence takes no lock.
		release := lockAccess()
		defer release()
		check := func() error {
			if e := ctx.Err(); e != nil {
				return e
			}
			if e := guard(); e != nil {
				return e
			}
			u, p, e := current(as.ID, "accounts.rotation.execute")
			if e != nil || !p.Allows("assets.rotate") {
				return rotationplans.ErrDenied
			}
			if in.FixedSecretID != "" && !p.Allows("accounts.rotation.fixed_password") {
				return rotationplans.ErrDenied
			}
			if in.Target.CollectorID != "" && !p.Allows("accounts.rotation.privileged") {
				return rotationplans.ErrDenied
			}
			for _, id := range []string{in.Target.AccountID, in.Target.CollectorID} {
				if id == "" {
					continue
				}
				a, e := d.Assets.Get(id)
				if e != nil {
					return e
				}
				decision, e := checkAccessPolicies(d, u, a, in.Origin, false)
				if e != nil || !decision.Allowed {
					return rotationplans.ErrDenied
				}
			}
			return nil
		}
		if e := check(); e != nil {
			return rotationplans.Outcome{State: "denied", Code: "denied"}, e
		}
		if recover {
			return d.Assets.RecoverManagedRotation(ctx, in, as, check)
		}
		return d.Assets.ExecuteManagedRotation(ctx, in, check)
	}
	service.SetRunner(rotationplans.Runner{
		Authorize: authorize,
		AuthorizeCheck: func(a rotationplans.Actor) error {
			_, p, e := current(a.ID, "accounts.rotation.check")
			if e != nil || !p.Allows("assets.probe") || !p.Allows("accounts.rotation.view") {
				return rotationplans.ErrDenied
			}
			return nil
		},
		Check: func(ctx context.Context, in rotationplans.Intent, guard func() error) (rotationplans.Outcome, error) {
			release := lockAccess()
			defer release()
			check := func() error {
				if e := guard(); e != nil {
					return e
				}
				u, p, e := current(in.Actor.ID, "accounts.rotation.check")
				if e != nil || !p.Allows("assets.probe") || !p.Allows("accounts.rotation.view") {
					return rotationplans.ErrDenied
				}
				a, e := d.Assets.Get(in.Target.AccountID)
				if e != nil {
					return e
				}
				decision, e := checkAccessPolicies(d, u, a, in.Origin, false)
				if e != nil || !decision.Allowed {
					return rotationplans.ErrDenied
				}
				return nil
			}
			return d.Assets.CheckManagedAccount(ctx, in, check)
		},
		AuthorizeTargets: func(a rotationplans.Actor, selected []rotationplans.Selection) error {
			_, p, e := current(a.ID, "accounts.rotation.execute")
			if e != nil || !p.Allows("assets.rotate") {
				return rotationplans.ErrDenied
			}
			for _, target := range selected {
				if target.CollectorID != "" && target.CollectorID != target.AccountID && !p.Allows("accounts.rotation.privileged") {
					return rotationplans.ErrDenied
				}
			}
			return nil
		},
		AuthorizeFixed: func(a rotationplans.Actor) error {
			_, _, e := current(a.ID, "accounts.rotation.fixed_password")
			return e
		},
		Prepare: func(ctx context.Context, a rotationplans.Actor, selected []rotationplans.Selection) ([]rotationplans.Prepared, error) {
			if _, _, e := current(a.ID, "accounts.rotation.view"); e != nil {
				return nil, e
			}
			return d.Assets.PrepareManagedRotations(ctx, selected)
		},
		Inspect: d.Assets.InspectManagedRotation,
		Execute: func(ctx context.Context, in rotationplans.Intent, guard func() error) (rotationplans.Outcome, error) {
			return credentialStep(ctx, in, in.Actor, guard, false)
		},
		Recover: func(ctx context.Context, in rotationplans.Intent, as rotationplans.Actor, guard func() error) (rotationplans.Outcome, error) {
			return credentialStep(ctx, in, as, guard, true)
		},
	})
	paging := func(r *http.Request) (int, int, error) {
		offset, e := strconv.Atoi(defaultQuery(r, "offset", "0"))
		limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "50"))
		if e != nil || e2 != nil || offset < 0 || limit < 1 || limit > 100 {
			return 0, 0, rotationplans.ErrInvalid
		}
		return offset, limit, nil
	}
	const base = "/api/v1/accounts/rotation-plans"
	mux.Handle("GET /api/v1/accounts/rotation-targets", protect(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := requestUser(w, r, "accounts.rotation.view"); !ok {
			return
		}
		offset, limit, e := paging(r)
		if e != nil {
			rotationPlanError(w, e)
			return
		}
		rows, total, e := d.Assets.RotationCandidates(r.URL.Query().Get("q"), r.URL.Query().Get("collector_for"), offset, limit)
		if e != nil {
			rotationPlanError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": total})
	}))
	mux.Handle("GET "+base, protect(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := requestUser(w, r, "accounts.rotation.view"); !ok {
			return
		}
		offset, limit, e := paging(r)
		if e != nil {
			rotationPlanError(w, e)
			return
		}
		rows, total, e := service.Plans(offset, limit)
		if e != nil {
			rotationPlanError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": total})
	}))
	save := func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := requestUser(w, r, "accounts.rotation.manage")
		if !ok {
			return
		}
		var in rotationplans.SaveInput
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF {
			rotationPlanError(w, rotationplans.ErrInvalid)
			return
		}
		release := lockAccess()
		defer release()
		u, p, ok = requestUser(w, r, "accounts.rotation.manage")
		if !ok {
			return
		}
		in.Origin = accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "credential_rotation"}
		if in.Enabled {
			if e := authorize(actor(u)); e != nil {
				rotationPlanError(w, e)
				return
			}
			for _, target := range in.Targets {
				if target.CollectorID != "" && target.CollectorID != target.AccountID && !p.Allows("accounts.rotation.privileged") {
					rotationPlanError(w, rotationplans.ErrDenied)
					return
				}
			}
		}
		if in.CheckEnabled && (!p.Allows("accounts.rotation.check") || !p.Allows("assets.probe")) {
			rotationPlanError(w, rotationplans.ErrDenied)
			return
		}
		out, e := service.SaveRequest(r.Context(), actor(u), r.PathValue("planID"), in, p.Allows("accounts.rotation.manage_all"), p.Allows("accounts.rotation.fixed_password"))
		if e != nil {
			rotationPlanError(w, e)
			return
		}
		status := 200
		if r.Method == "POST" {
			status = 201
		}
		writeJSON(w, status, out)
	}
	mux.Handle("POST "+base, protect(save))
	mux.Handle("PUT "+base+"/{planID}", protect(save))
	mux.Handle("GET "+base+"/{planID}", protect(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := requestUser(w, r, "accounts.rotation.view"); !ok {
			return
		}
		out, e := service.Plan(r.PathValue("planID"))
		if e != nil {
			rotationPlanError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("DELETE "+base+"/{planID}", protect(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := requestUser(w, r, "accounts.rotation.manage")
		if !ok {
			return
		}
		revision, e := strconv.Atoi(r.URL.Query().Get("revision"))
		if e != nil || revision < 1 {
			rotationPlanError(w, rotationplans.ErrInvalid)
			return
		}
		if e := service.Delete(r.PathValue("planID"), revision, actor(u), p.Allows("accounts.rotation.manage_all")); e != nil {
			rotationPlanError(w, e)
			return
		}
		w.WriteHeader(204)
	}))
	mux.Handle("POST "+base+"/{planID}/runs", protect(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := requestUser(w, r, "accounts.rotation.execute")
		if !ok {
			return
		}
		var in struct {
			RequestID string `json:"request_id"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			rotationPlanError(w, rotationplans.ErrInvalid)
			return
		}
		plan, e := service.Plan(r.PathValue("planID"))
		if e != nil {
			rotationPlanError(w, e)
			return
		}
		for _, target := range plan.Refs {
			if target.CollectorID != "" && !p.Allows("accounts.rotation.privileged") {
				rotationPlanError(w, rotationplans.ErrDenied)
				return
			}
		}
		out, e := service.Submit(r.Context(), actor(u), plan.ID, in.RequestID, p.Allows("accounts.rotation.manage_all"), accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "credential_rotation"})
		if e != nil {
			rotationPlanError(w, e)
			return
		}
		writeJSON(w, 202, out)
	}))
	mux.Handle("POST "+base+"/{planID}/checks", protect(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := requestUser(w, r, "accounts.rotation.check")
		if !ok {
			return
		}
		var in struct {
			RequestID string `json:"request_id"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			rotationPlanError(w, rotationplans.ErrInvalid)
			return
		}
		out, e := service.Check(r.Context(), actor(u), r.PathValue("planID"), in.RequestID, p.Allows("accounts.rotation.manage_all"), accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "credential_rotation"})
		if e != nil {
			rotationPlanError(w, e)
			return
		}
		writeJSON(w, 202, out)
	}))
	mux.Handle("GET /api/v1/accounts/rotation-runs", protect(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := requestUser(w, r, "accounts.rotation.view"); !ok {
			return
		}
		offset, limit, e := paging(r)
		if e != nil {
			rotationPlanError(w, e)
			return
		}
		rows, total, e := service.Runs(r.URL.Query().Get("plan_id"), offset, limit)
		if e != nil {
			rotationPlanError(w, e)
			return
		}
		for i := range rows {
			rows[i].Items = nil
			rows[i].RetryItemIDs = nil
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": total})
	}))
	mux.Handle("GET /api/v1/accounts/rotation-runs/{runID}", protect(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := requestUser(w, r, "accounts.rotation.view"); !ok {
			return
		}
		out, e := service.Run(r.PathValue("runID"))
		if e != nil {
			rotationPlanError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("POST /api/v1/accounts/rotation-runs/{runID}/retry", protect(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := requestUser(w, r, "accounts.rotation.view"); !ok {
			return
		}
		var in rotationplans.RetryInput
		if decodeRequestJSONLimit(w, r, &in, 128<<10) != nil {
			rotationPlanError(w, rotationplans.ErrInvalid)
			return
		}
		release := lockAccess()
		defer release()
		u, p, ok := requestUser(w, r, "accounts.rotation.view")
		if !ok {
			return
		}
		out, e := service.Retry(r.Context(), actor(u), r.PathValue("runID"), in, p.Allows("accounts.rotation.manage_all"), accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "credential_rotation"})
		if e != nil {
			rotationPlanError(w, e)
			return
		}
		writeJSON(w, 202, out)
	}))
	mux.Handle("POST /api/v1/accounts/rotation-runs/{runID}/cancel", protect(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := requestUser(w, r, "accounts.rotation.manage")
		if !ok {
			return
		}
		if e := service.Cancel(r.PathValue("runID"), actor(u), p.Allows("accounts.rotation.manage_all")); e != nil {
			rotationPlanError(w, e)
			return
		}
		w.WriteHeader(204)
	}))
	mux.Handle("POST /api/v1/accounts/rotation-runs/{runID}/recover", protect(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := requestUser(w, r, "accounts.rotation.execute")
		if !ok {
			return
		}
		run, e := service.Run(r.PathValue("runID"))
		if e != nil {
			rotationPlanError(w, e)
			return
		}
		for _, target := range run.Items {
			if target.CollectorID != "" && !p.Allows("accounts.rotation.privileged") {
				rotationPlanError(w, rotationplans.ErrDenied)
				return
			}
		}
		e = service.Recover(r.PathValue("runID"), actor(u), p.Allows("accounts.rotation.manage_all"), accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "credential_rotation"})
		if e != nil {
			rotationPlanError(w, e)
			return
		}
		w.WriteHeader(204)
	}))
	mux.Handle("GET /api/v1/accounts/rotation-runs/{runID}/export", protect(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := requestUser(w, r, "accounts.rotation.view"); !ok {
			return
		}
		run, e := service.Run(r.PathValue("runID"))
		if e != nil {
			rotationPlanError(w, e)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="credential-rotation.csv"`)
		_, _ = w.Write([]byte("\xef\xbb\xbf"))
		writer := csv.NewWriter(w)
		_ = writer.Write([]string{"run_id", "account_id", "asset_id", "asset_name", "username", "credential_type", "state", "error_code", "linked_to", "before_revision", "after_revision", "finished_at", "parent_run_id", "source_item_id", "retry_run_id", "operation", "check_duration_ms"})
		for _, v := range run.Items {
			at := ""
			if !v.FinishedAt.IsZero() {
				at = v.FinishedAt.Format(time.RFC3339)
			}
			operation := "rotation"
			if run.Operation == "check" {
				operation = "check"
			}
			row := []string{run.ID, v.AccountID, v.AssetID, v.AssetName, v.Username, v.CredentialType, v.State, v.ErrorCode, v.LinkedTo, strconv.FormatUint(v.BeforeRevision, 10), strconv.FormatUint(v.AfterRevision, 10), at, run.ParentRunID, v.SourceItemID, v.RetryRunID, operation, strconv.FormatInt(v.CheckDurationMS, 10)}
			for i, value := range row {
				trim := strings.TrimLeft(value, " \t\r\n")
				if trim != "" && strings.ContainsRune("=+-@", rune(trim[0])) {
					row[i] = "'" + value
				}
			}
			_ = writer.Write(row)
		}
		writer.Flush()
	}))
	mux.Handle("GET /api/v1/accounts/rotation-audit", protect(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := requestUser(w, r, "accounts.rotation.view"); !ok {
			return
		}
		offset, limit, e := paging(r)
		if e != nil {
			rotationPlanError(w, e)
			return
		}
		rows, total, e := service.Audit(offset, limit)
		if e != nil {
			rotationPlanError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": total})
	}))
}
