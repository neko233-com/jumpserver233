package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
)

func registerSessionMonitorRoutes(mux *http.ServeMux, broker *gateway.Broker, adminToken string, identities *coreauth.Service) {
	mux.Handle("POST /api/v1/sessions/{sessionID}/monitor", protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		u, _ := PrincipalFromContext(r.Context())
		d := policyDependencies(r)
		source := accesspolicies.SourceIP(r.Context())
		all := hasPermission(r, "audit.sessions.monitor_all")
		guard := func(ctx context.Context) error {
			if accesspolicies.SourceIP(ctx) != source {
				return accesspolicies.ErrDenied
			}
			current := u
			if identities != nil && u.ID != "admin-token" && u.ID != "loopback-admin" {
				var ok bool
				current, ok = identities.ActiveUserByID(u.ID)
				if !ok {
					return accesspolicies.ErrDenied
				}
			}
			if all && !effectivePermissions(current, d.RBAC, d.Groups).Allows("audit.sessions.monitor_all") {
				return accesspolicies.ErrDenied
			}
			decision, err := checkAccessPolicies(d, current, assets.Asset{}, accesspolicies.Origin{SourceIP: source}, false)
			if err != nil || !decision.Allowed {
				return accesspolicies.ErrDenied
			}
			return nil
		}
		created, err := broker.CreateMonitor(r.Context(), gateway.MonitorRequest{SessionID: r.PathValue("sessionID"), ViewerID: u.ID, Viewer: u.Username, AllowAll: all, AccessPolicy: guard})
		if err != nil {
			status := http.StatusNotFound
			if errors.Is(err, gateway.ErrMonitorCapacity) {
				status = http.StatusTooManyRequests
			}
			writeJSON(w, status, map[string]string{"detail": "live session monitoring is unavailable"})
			return
		}
		if d.OrganizationID != "" {
			created.WebSocketURL += "?org=" + d.OrganizationID
		}
		writeJSON(w, http.StatusCreated, created)
	}), adminToken, identities))
	mux.HandleFunc("GET /ws/api/v1/sessions/{sessionID}/monitor", broker.ServeMonitor)
}
