package api

import (
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/accountdiscovery"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
	"net/http"
	"strconv"
	"sync"
)

func canResumeDiscoveryPlan(d Dependencies, r *http.Request, p operations.Plan) bool {
	if !hasPermission(r, "accounts.schedule") || !hasPermission(r, "accounts.discover") || p.Discovery == nil || len(p.AssetIDs) != 1 {
		return false
	}
	owner, ok := jobOwner(d, p.OwnerID)
	if !ok {
		return false
	}
	permissions := effectivePermissions(owner, d.RBAC, d.Groups)
	if !permissions.Allows("accounts.schedule") || !permissions.Allows("accounts.discover") {
		return false
	}
	origin := p.AccessOrigin
	origin.Method = "scheduled_exec"
	a, e := authorizeTerminalAsset(d, owner, p.AssetIDs[0], assets.ProtocolSSH, origin, false)
	return e == nil && a.Username == p.Discovery.Account && assets.ResourceID(a) == p.Discovery.ParentAssetID && discoveryIdentity(a) == p.Discovery.Target && discoveryPoliciesAllowed(d, owner, a, origin)
}

func cancelDiscoveryApprovals(d Dependencies, p operations.Plan) error {
	if d.AccessReviews == nil {
		return nil
	}
	runs, _ := d.Operations.Runs(p.OwnerID, 0, 1000)
	for _, run := range runs {
		if run.PlanID != p.ID || !run.Cancelled {
			continue
		}
		for _, item := range run.Items {
			if item.ReviewID != "" {
				if e := d.AccessReviews.CancelOwned(item.ReviewID, run.OwnerID); e != nil {
					return e
				}
			}
		}
	}
	return nil
}

func registerAccountDiscoveryPlans(mux *http.ServeMux, d Dependencies, mu *sync.RWMutex) {
	if d.Operations == nil || d.AccountDiscovery == nil {
		return
	}
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	owned := func(r *http.Request, p operations.Plan) bool {
		u, _ := PrincipalFromContext(r.Context())
		return u.ID == p.OwnerID || hasPermission(r, "plans.manage_all")
	}
	mux.Handle("GET /api/v1/assets/{assetID}/account-discovery/plans", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		u, _ := PrincipalFromContext(r.Context())
		owner := u.ID
		if hasPermission(r, "plans.view_all") || hasPermission(r, "plans.manage_all") {
			owner = ""
		}
		type view struct {
			operations.Plan
			LastRun *operations.Run `json:"last_run,omitempty"`
		}
		rows := []view{}
		parent := ""
		if a, e := d.Assets.Get(r.PathValue("assetID")); e == nil {
			parent = assets.ResourceID(a)
		}
		for _, p := range d.Operations.Plans(owner) {
			if p.Discovery != nil && len(p.AssetIDs) == 1 && (p.AssetIDs[0] == r.PathValue("assetID") || parent != "" && p.Discovery.ParentAssetID == parent) {
				v := view{Plan: p}
				if p.LastRunID != "" {
					last, e := d.Operations.Run(p.LastRunID)
					if e != nil {
						if receipt, ok := d.AccountDiscovery.LatestCollection(p.LastRunID); ok {
							e = json.Unmarshal(receipt.Run, &last)
						}
					}
					if e == nil {
						v.LastRun = &last
					}
				}
				rows = append(rows, v)
			}
		}
		writeJSON(w, 200, rows)
	}))
	mux.Handle("POST /api/v1/assets/{assetID}/account-discovery/plans", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !hasPermission(r, "accounts.schedule") || !hasPermission(r, "accounts.discover") {
			writeJobError(w, operations.ErrDenied)
			return
		}
		var in struct {
			Name      string `json:"name"`
			Interval  int    `json:"interval_seconds"`
			RequestID string `json:"request_id"`
		}
		if decodeRequestJSON(w, r, &in) != nil || in.RequestID == "" {
			writeJobError(w, operations.ErrInvalid)
			return
		}
		if in.Name == "" {
			in.Name = "Linux account discovery"
		}
		if in.Interval == 0 {
			in.Interval = 3600
		}
		mu.Lock()
		defer mu.Unlock()
		u, _ := PrincipalFromContext(r.Context())
		origin := accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "scheduled_exec"}
		a, e := authorizeTerminalAsset(d, u, r.PathValue("assetID"), assets.ProtocolSSH, origin, false)
		if e != nil || !discoveryPoliciesAllowed(d, u, a, origin) {
			writeJobError(w, operations.ErrDenied)
			return
		}
		op := accountdiscovery.Operation{Binding: databaseRouteBinding(d, a), Target: discoveryIdentity(a)}
		p, e := d.Operations.CreateDiscoveryCollector(u.ID, u.Username, operations.PlanInput{Name: in.Name, AssetIDs: []string{a.ID}, Kind: "interval", IntervalSeconds: in.Interval, RequestID: in.RequestID, Origin: origin}, op, assets.ResourceID(a), a.Username, a.Name)
		if e != nil {
			writeJobError(w, e)
			return
		}
		writeJSON(w, 201, p)
	}))
	mux.Handle("PUT /api/v1/assets/{assetID}/account-discovery/plans/{planID}", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		var in struct {
			Enabled  *bool `json:"enabled"`
			Interval int   `json:"interval_seconds"`
			Revision int   `json:"revision"`
		}
		if decodeRequestJSON(w, r, &in) != nil || in.Enabled == nil {
			writeJobError(w, operations.ErrInvalid)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		p, e := d.Operations.Plan(r.PathValue("planID"))
		if e != nil || p.Discovery == nil || len(p.AssetIDs) != 1 || p.AssetIDs[0] != r.PathValue("assetID") || !owned(r, p) {
			writeJobError(w, operations.ErrNotFound)
			return
		}
		if *in.Enabled && !canResumeDiscoveryPlan(d, r, p) {
			writeJobError(w, operations.ErrDenied)
			return
		}
		if in.Interval == 0 {
			in.Interval = p.IntervalSeconds
		}
		p, e = d.Operations.UpdateDiscoveryCollector(p.ID, in.Revision, *in.Enabled, in.Interval)
		if e != nil {
			writeJobError(w, e)
			return
		}
		if !p.Enabled {
			if e := cancelDiscoveryApprovals(d, p); e != nil {
				writeJSON(w, 503, map[string]string{"detail": "access review cancellation unavailable"})
				return
			}
		}
		writeJSON(w, 200, p)
	}))
	mux.Handle("GET /api/v1/assets/{assetID}/account-discovery/collections", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		mu.RLock()
		defer mu.RUnlock()
		src, ok := discoverySource(d, r)
		if !ok {
			writeJobError(w, operations.ErrNotFound)
			return
		}
		before, e := strconv.ParseUint(defaultQuery(r, "before", "0"), 10, 64)
		limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "50"))
		if e != nil || e2 != nil || limit < 1 || limit > 100 {
			writeJobError(w, operations.ErrInvalid)
			return
		}
		page, e := d.AccountDiscovery.Collections(src.AssetID, before, limit)
		if e != nil {
			writeDiscoveryError(w, e)
			return
		}
		writeJSON(w, 200, page)
	}))
}
