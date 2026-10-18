package api

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/desktop"
)

func registerDesktopMonitorRoutes(mux *http.ServeMux, d Dependencies) {
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	mux.Handle("POST /api/v1/desktop-sessions/{sessionID}/monitor", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		u, _ := PrincipalFromContext(r.Context())
		source := accesspolicies.SourceIP(r.Context())
		if _, e := netip.ParseAddr(source); e != nil {
			writeJSON(w, 404, map[string]string{"detail": "live desktop monitoring is unavailable"})
			return
		}
		all := hasPermission(r, "audit.desktops.monitor_all")
		guard := func(ctx context.Context, record desktop.Record) error {
			if accesspolicies.SourceIP(ctx) != source {
				return accesspolicies.ErrDenied
			}
			current, ok := jobOwnerSnapshot(d, u)
			if !ok || all && !effectivePermissions(current, d.RBAC, d.Groups).Allows("audit.desktops.monitor_all") {
				return accesspolicies.ErrDenied
			}
			if d.Assets == nil {
				return accesspolicies.ErrDenied
			}
			id := record.AssetID
			for hops := 0; ; hops++ {
				if hops > 3 {
					return accesspolicies.ErrDenied
				}
				asset, e := d.Assets.Get(id)
				if e != nil {
					return accesspolicies.ErrDenied
				}
				decision, e := checkAccessPolicies(d, current, asset, accesspolicies.Origin{SourceIP: source, Method: "rdp"}, false)
				if e != nil || !decision.Allowed {
					return accesspolicies.ErrDenied
				}
				if asset.GatewayID == "" {
					break
				}
				id = asset.GatewayID
			}
			return nil
		}
		created, e := d.Desktops.CreateMonitor(r.Context(), desktop.MonitorRequest{SessionID: r.PathValue("sessionID"), ViewerID: u.ID, Viewer: u.Username, AllowAll: all, Guard: guard})
		if e != nil {
			status := 404
			if errors.Is(e, desktop.ErrMonitorCapacity) {
				status = 429
			}
			writeJSON(w, status, map[string]string{"detail": "live desktop monitoring is unavailable"})
			return
		}
		if d.OrganizationID != "" {
			created.URL += "?org=" + d.OrganizationID
		}
		writeJSON(w, 201, created)
	}))
	mux.HandleFunc("GET /ws/desktop/{sessionID}/monitor", d.Desktops.ServeMonitor)
	mux.Handle("GET /api/v1/desktop-sessions/{sessionID}/monitor-events", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		offset, limit := 0, 50
		var e error
		if value := r.URL.Query().Get("offset"); value != "" {
			offset, e = strconv.Atoi(value)
		}
		if e == nil {
			if value := r.URL.Query().Get("limit"); value != "" {
				limit, e = strconv.Atoi(value)
			}
		}
		if e != nil || offset < 0 || offset > 1000000 || limit < 1 || limit > 100 {
			writeJSON(w, 400, map[string]string{"detail": "invalid desktop monitor pagination"})
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		rows, total, e := d.Desktops.ListMonitorEvents(r.PathValue("sessionID"), u.ID, hasPermission(r, "audit.sessions.view_all"), offset, limit)
		if e != nil {
			status := 404
			if errors.Is(e, desktop.ErrMonitorAudit) {
				status = 503
			}
			writeJSON(w, status, map[string]string{"detail": "desktop monitor audit is unavailable"})
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": total, "offset": offset, "limit": limit})
	}))
}
