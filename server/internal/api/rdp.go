package api

import (
	"context"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/databasequery"
	"github.com/neko233-com/jumpserver233/server/internal/desktop"
	"net/http"
	"strconv"
	"sync"
)

func registerRDPRoutes(mux *http.ServeMux, d Dependencies, mu *sync.RWMutex) {
	registerDesktopMonitorRoutes(mux, d)
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	fail := func(w http.ResponseWriter, e error) {
		code := 502
		if errors.Is(e, assets.ErrNotFound) || errors.Is(e, desktop.ErrNotFound) {
			code = 404
		}
		if errors.Is(e, accesspolicies.ErrDenied) {
			code = 403
		}
		if errors.Is(e, assets.ErrUnsupportedProtocol) {
			code = 400
		}
		writeJSON(w, code, map[string]string{"detail": "RDP session unavailable"})
	}
	mux.Handle("POST /api/v1/assets/{assetID}/rdp/sessions", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		u, _ := PrincipalFromContext(r.Context())
		origin := accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "rdp"}
		mu.RLock()
		a, e := authorizeTerminalAsset(d, u, r.PathValue("assetID"), assets.ProtocolRDP, origin, true)
		binding := databasequery.Binding(struct {
			Route    string
			Settings any
		}{databaseRouteBinding(d, a), a.RDP})
		mu.RUnlock()
		if e != nil {
			fail(w, e)
			return
		}
		if a.LoginReviewRequired && !effectivePermissions(u, d.RBAC, d.Groups).Allows("login_review.bypass") {
			if d.AccessReviews == nil {
				writeJSON(w, 503, map[string]string{"detail": "login review unavailable"})
				return
			}
			approved, e := d.AccessReviews.ConsumeApprovedAction(u.ID, a.ID, a.Username, accessreviews.ActionRDP)
			if e != nil {
				fail(w, e)
				return
			}
			if !approved {
				review, e := d.AccessReviews.RequestAction(u.ID, u.Username, a.ID, a.Name, a.Username, accessreviews.ActionRDP)
				if e != nil {
					fail(w, e)
					return
				}
				writeJSON(w, 202, map[string]any{"review_id": review.ID, "state": review.State, "expires_at": review.ExpiresAt})
				return
			}
		}
		guard := func(ctx context.Context, method string) error {
			user, ok := jobOwnerSnapshot(d, u)
			if !ok {
				return accesspolicies.ErrDenied
			}
			o := origin
			o.Method = method
			if source := accesspolicies.SourceIP(ctx); source != "" {
				o.SourceIP = source
			}
			mu.RLock()
			defer mu.RUnlock()
			current, e := authorizeTerminalAsset(d, user, a.ID, assets.ProtocolRDP, o, false)
			if e != nil || databasequery.Binding(struct {
				Route    string
				Settings any
			}{databaseRouteBinding(d, current), current.RDP}) != binding {
				return accesspolicies.ErrDenied
			}
			if current.RDP.ReadOnly && (method == "rdp_input" || method == "rdp_clipboard_write") || !current.RDP.Clipboard && (method == "rdp_clipboard_read" || method == "rdp_clipboard_write") {
				return accesspolicies.ErrDenied
			}
			return nil
		}
		var resolvedGateways []string
		created, e := d.Desktops.Create(r.Context(), desktop.Request{Record: desktop.Record{AssetID: a.ID, AssetName: a.Name, Username: a.Username, OperatorID: u.ID, Operator: u.Username, ReadOnly: a.RDP.ReadOnly, Clipboard: a.RDP.Clipboard}, Guard: guard, ResolvedGateways: func() []string { return resolvedGateways }, Open: func(ctx context.Context) (desktop.Display, error) {
			if e := guard(ctx, "rdp"); e != nil {
				return nil, e
			}
			openedAsset, c, e := d.Assets.OpenRDP(ctx, a.ID)
			if e != nil {
				return nil, e
			}
			if e = guard(ctx, "rdp"); e != nil {
				c.Close()
				return nil, e
			}
			resolvedGateways = openedAsset.GatewayIDs
			return c, nil
		}})
		if e != nil {
			fail(w, e)
			return
		}
		if d.OrganizationID != "" {
			created.URL += "?org=" + d.OrganizationID
		}
		writeJSON(w, 201, created)
	}))
	mux.Handle("GET /ws/desktop/{sessionID}", http.HandlerFunc(d.Desktops.ServeWS))
	mux.Handle("GET /api/v1/desktop-sessions", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		u, _ := PrincipalFromContext(r.Context())
		rows, e := d.Desktops.List(u.ID, hasPermission(r, "audit.sessions.view_all") || hasPermission(r, "audit.desktops.monitor_all"))
		if e != nil {
			fail(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows})
	}))
	mux.Handle("GET /api/v1/desktop-sessions/{sessionID}", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		u, _ := PrincipalFromContext(r.Context())
		record, e := d.Desktops.Get(r.PathValue("sessionID"), u.ID, hasPermission(r, "audit.replays.view_all"))
		if e != nil {
			fail(w, e)
			return
		}
		writeJSON(w, 200, record)
	}))
	mux.Handle("GET /api/v1/desktop-sessions/{sessionID}/frames/{frame}", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		u, _ := PrincipalFromContext(r.Context())
		index, e := strconv.Atoi(r.PathValue("frame"))
		if e != nil {
			fail(w, desktop.ErrNotFound)
			return
		}
		data, e := d.Desktops.Frame(r.PathValue("sessionID"), u.ID, hasPermission(r, "audit.replays.view_all"), index)
		if e != nil {
			fail(w, e)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Write(data)
	}))
	mux.Handle("DELETE /api/v1/desktop-sessions/{sessionID}", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		u, _ := PrincipalFromContext(r.Context())
		if e := d.Desktops.Stop(r.PathValue("sessionID"), u.ID, hasPermission(r, "audit.sessions.terminate_all")); e != nil {
			fail(w, e)
			return
		}
		w.WriteHeader(204)
	}))
}
