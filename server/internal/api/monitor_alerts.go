package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/monitoralerts"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
)

func monitorAlertError(w http.ResponseWriter, e error) {
	code, status := "unavailable", 503
	switch {
	case errors.Is(e, monitoralerts.ErrInvalid):
		code, status = "invalid", 400
	case errors.Is(e, monitoralerts.ErrDenied):
		code, status = "denied", 403
	case errors.Is(e, monitoralerts.ErrNotFound):
		code, status = "not_found", 404
	case errors.Is(e, monitoralerts.ErrConflict):
		code, status = "conflict", 409
	case errors.Is(e, monitoralerts.ErrCapacity):
		code, status = "capacity", 429
	}
	writeJSON(w, status, map[string]string{"error_code": code})
}
func monitorActor(ctx context.Context, d Dependencies, id, permission string, all bool) (coreauth.User, rbac.Snapshot, error) {
	u, p, ok := notificationActor(ctx, d, id)
	if !ok || !p.Allows(permission) || all && !(p.Allows("assets.view_all") || p.Allows("assets.manage")) {
		return u, p, monitoralerts.ErrDenied
	}
	return u, p, nil
}
func monitorVisible(d Dependencies, u coreauth.User, p rbac.Snapshot, id string) bool {
	if p.Allows("assets.view_all") || p.Allows("assets.manage") {
		return true
	}
	a, e := d.Assets.AccountAsset(id, id)
	if e != nil {
		return false
	}
	var groups, nodes []string
	if d.Groups != nil {
		groups = d.Groups.GroupIDsForUser(u.ID)
	}
	if d.Nodes != nil {
		nodes = d.Nodes.AncestorIDs(a.NodeID)
	}
	accounts, e := d.Assets.ManagedAccounts(id)
	if e != nil {
		return false
	}
	for _, account := range accounts {
		if !account.Active {
			continue
		}
		if d.Grants != nil && d.Grants.AllowsForScopes(u.ID, groups, id, nodes, account.Username, "view", time.Now().UTC()) {
			return true
		}
	}
	return false
}
func registerMonitorAlertRoutes(mux *http.ServeMux, d Dependencies, mu *sync.RWMutex) {
	if d.MonitorAlerts == nil || d.Assets == nil || d.Auth == nil {
		return
	}
	service := d.MonitorAlerts
	acquire := func(ctx context.Context) (func(), error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
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
		}, nil
	}
	service.SetRunner(monitoralerts.Runner{Acquire: acquire, Sources: func(ctx context.Context) ([]monitoralerts.Source, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		ancestry := func(id string) []string {
			if d.Nodes == nil {
				return nil
			}
			return d.Nodes.AncestorIDs(id)
		}
		return d.Assets.MonitorSources(ancestry), nil
	}, Authorized: func(ctx context.Context, a monitoralerts.Actor) bool {
		_, _, e := monitorActor(ctx, d, a.ID, "monitoring.manage", true)
		return e == nil
	}})
	protect := func(permission string, all bool, next func(http.ResponseWriter, *http.Request, coreauth.User, rbac.Snapshot)) http.Handler {
		return protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, _ := PrincipalFromContext(r.Context())
			release, e := acquire(r.Context())
			if e != nil {
				monitorAlertError(w, e)
				return
			}
			defer release()
			u, p, e := monitorActor(r.Context(), d, principal.ID, permission, all)
			if e != nil {
				monitorAlertError(w, e)
				return
			}
			setNoStore(w)
			next(w, r, u, p)
		}), d.AdminToken, d.Auth)
	}
	validScope := func(scope monitoralerts.Scope) bool {
		for _, id := range scope.AssetIDs {
			a, e := d.Assets.AccountAsset(id, id)
			if e != nil || !coreassets.IsSSH(a) || a.ParentAssetID != "" || a.AccountDisabled {
				return false
			}
		}
		for _, id := range scope.NodeIDs {
			if d.Nodes == nil {
				return false
			}
			if _, e := d.Nodes.Get(id); e != nil {
				return false
			}
		}
		return true
	}
	mux.Handle("GET /api/v1/monitoring/rules", protect("monitoring.manage", true, func(w http.ResponseWriter, r *http.Request, u coreauth.User, p rbac.Snapshot) {
		writeJSON(w, 200, service.Rules())
	}))
	save := func(w http.ResponseWriter, r *http.Request, u coreauth.User, _ rbac.Snapshot) {
		var in monitoralerts.Input
		if decodeRequestJSON(w, r, &in) != nil || !validScope(in.Scope) {
			monitorAlertError(w, monitoralerts.ErrInvalid)
			return
		}
		out, e := service.SaveRule(r.PathValue("ruleID"), in, monitoralerts.Actor{ID: u.ID, Name: u.Username})
		if e != nil {
			monitorAlertError(w, e)
			return
		}
		status := 200
		if r.Method == "POST" {
			status = 201
		}
		writeJSON(w, status, out)
	}
	mux.Handle("POST /api/v1/monitoring/rules", protect("monitoring.manage", true, save))
	mux.Handle("PUT /api/v1/monitoring/rules/{ruleID}", protect("monitoring.manage", true, save))
	mux.Handle("DELETE /api/v1/monitoring/rules/{ruleID}", protect("monitoring.manage", true, func(w http.ResponseWriter, r *http.Request, u coreauth.User, _ rbac.Snapshot) {
		revision, e := strconv.Atoi(r.URL.Query().Get("revision"))
		if e != nil {
			monitorAlertError(w, monitoralerts.ErrInvalid)
			return
		}
		if e = service.DeleteRule(r.PathValue("ruleID"), revision, monitoralerts.Actor{ID: u.ID, Name: u.Username}); e != nil {
			monitorAlertError(w, e)
			return
		}
		w.WriteHeader(204)
	}))
	mux.Handle("POST /api/v1/monitoring/rules/{ruleID}/mute", protect("monitoring.manage", true, func(w http.ResponseWriter, r *http.Request, u coreauth.User, _ rbac.Snapshot) {
		var in struct {
			Revision int       `json:"revision"`
			Until    time.Time `json:"until"`
			Reason   string    `json:"reason"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			monitorAlertError(w, monitoralerts.ErrInvalid)
			return
		}
		out, e := service.MuteRule(r.PathValue("ruleID"), in.Revision, in.Until, in.Reason, monitoralerts.Actor{ID: u.ID, Name: u.Username})
		if e != nil {
			monitorAlertError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	paging := func(r *http.Request) (int, int, error) {
		offset, limit := 0, 25
		var e error
		if v := r.URL.Query().Get("offset"); v != "" {
			offset, e = strconv.Atoi(v)
		}
		if e == nil {
			if v := r.URL.Query().Get("limit"); v != "" {
				limit, e = strconv.Atoi(v)
			}
		}
		if e != nil || offset < 0 || limit < 1 || limit > 200 {
			return 0, 0, monitoralerts.ErrInvalid
		}
		return offset, limit, nil
	}
	mux.Handle("GET /api/v1/monitoring/alerts", protect("monitoring.view", false, func(w http.ResponseWriter, r *http.Request, u coreauth.User, p rbac.Snapshot) {
		offset, limit, e := paging(r)
		q := strings.ToLower(r.URL.Query().Get("q"))
		if e != nil || len(q) > 200 {
			monitorAlertError(w, monitoralerts.ErrInvalid)
			return
		}
		visible := map[string]bool{}
		checked := map[string]bool{}
		out, e := service.Alerts(offset, limit, r.URL.Query().Get("state"), func(a monitoralerts.Alert) bool {
			if q != "" && !strings.Contains(strings.ToLower(a.AssetName+" "+a.RuleName+" "+a.ID), q) {
				return false
			}
			if !checked[a.AssetID] {
				visible[a.AssetID] = monitorVisible(d, u, p, a.AssetID)
				checked[a.AssetID] = true
			}
			return visible[a.AssetID]
		})
		if e != nil {
			monitorAlertError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	get := func(w http.ResponseWriter, r *http.Request, u coreauth.User, p rbac.Snapshot, ack bool) {
		a, e := service.Alert(r.PathValue("alertID"))
		if e != nil {
			monitorAlertError(w, e)
			return
		}
		if !monitorVisible(d, u, p, a.AssetID) {
			monitorAlertError(w, monitoralerts.ErrNotFound)
			return
		}
		if ack {
			var in struct {
				Revision int    `json:"revision"`
				Comment  string `json:"comment"`
			}
			if decodeRequestJSON(w, r, &in) != nil {
				monitorAlertError(w, monitoralerts.ErrInvalid)
				return
			}
			a, e = service.Acknowledge(a.ID, in.Revision, in.Comment, monitoralerts.Actor{ID: u.ID, Name: u.Username})
			if e != nil {
				monitorAlertError(w, e)
				return
			}
		}
		writeJSON(w, 200, a)
	}
	mux.Handle("GET /api/v1/monitoring/alerts/{alertID}", protect("monitoring.view", false, func(w http.ResponseWriter, r *http.Request, u coreauth.User, p rbac.Snapshot) { get(w, r, u, p, false) }))
	mux.Handle("POST /api/v1/monitoring/alerts/{alertID}/acknowledge", protect("monitoring.ack", false, func(w http.ResponseWriter, r *http.Request, u coreauth.User, p rbac.Snapshot) {
		if !p.Allows("monitoring.view") {
			monitorAlertError(w, monitoralerts.ErrDenied)
			return
		}
		get(w, r, u, p, true)
	}))
	mux.Handle("GET /api/v1/monitoring/health", protect("monitoring.manage", true, func(w http.ResponseWriter, r *http.Request, u coreauth.User, p rbac.Snapshot) {
		writeJSON(w, 200, service.Health())
	}))
	mux.Handle("GET /api/v1/monitoring/audit", protect("monitoring.manage", true, func(w http.ResponseWriter, r *http.Request, u coreauth.User, p rbac.Snapshot) {
		offset, limit, e := paging(r)
		if e != nil {
			monitorAlertError(w, e)
			return
		}
		out, e := service.Audit(offset, limit)
		if e != nil {
			monitorAlertError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
}
func monitorNotificationAllowed(ctx context.Context, d Dependencies, id string, a monitoralerts.Alert, action string) bool {
	u, p, e := monitorActor(ctx, d, id, "monitoring.view", false)
	if e != nil || !monitorVisible(d, u, p, a.AssetID) {
		return false
	}
	if action == "monitoring_resolved" {
		return a.State == "resolved"
	}
	if action != "monitoring_firing" || a.State != "firing" || !a.AcknowledgedAt.IsZero() {
		return false
	}
	rule, ok := d.MonitorAlerts.Rule(a.RuleID)
	if !ok || !rule.Enabled || rule.Definition != a.RuleRevision || rule.MutedUntil.After(time.Now().UTC()) {
		return false
	}
	_, _, e = monitorActor(ctx, d, rule.Owner.ID, "monitoring.manage", true)
	return e == nil
}
