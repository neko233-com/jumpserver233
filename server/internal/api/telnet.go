package api

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/telnetclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	"github.com/neko233-com/jumpserver233/server/internal/core/databasequery"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
)

func telnetBinding(d Dependencies, a assets.Asset) string {
	return databasequery.Binding(struct {
		Route    string
		Settings *telnetclient.Settings
	}{databaseRouteBinding(d, a), a.Telnet})
}

func registerTelnetRoutes(mux *http.ServeMux, d Dependencies, accessMu *sync.RWMutex) {
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	writeError := func(w http.ResponseWriter, e error) {
		switch {
		case errors.Is(e, assets.ErrNotFound):
			writeJSON(w, 404, map[string]string{"detail": "asset not found"})
		case errors.Is(e, assets.ErrUnsupportedProtocol), errors.Is(e, telnetclient.ErrInvalid):
			writeJSON(w, 400, map[string]string{"detail": "invalid Telnet target"})
		case errors.Is(e, accesspolicies.ErrDenied):
			writeJSON(w, 403, map[string]string{"detail": "Telnet access is not granted"})
		default:
			writeJSON(w, 502, map[string]string{"detail": "could not establish Telnet session"})
		}
	}
	mux.Handle("POST /api/v1/assets/{assetID}/telnet/sessions", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		var input struct {
			Cols int `json:"cols"`
			Rows int `json:"rows"`
		}
		if decodeRequestJSON(w, r, &input) != nil || input.Cols < 2 || input.Cols > 500 || input.Rows < 2 || input.Rows > 500 {
			writeError(w, telnetclient.ErrInvalid)
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		origin := accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "telnet"}
		accessMu.RLock()
		a, e := authorizeTerminalAsset(d, u, r.PathValue("assetID"), assets.ProtocolTelnet, origin, true)
		binding := telnetBinding(d, a)
		accessMu.RUnlock()
		if e != nil {
			writeError(w, e)
			return
		}
		if d.Sessions == nil {
			writeJSON(w, 503, map[string]string{"detail": "terminal service unavailable"})
			return
		}
		if a.LoginReviewRequired && !effectivePermissions(u, d.RBAC, d.Groups).Allows("login_review.bypass") {
			if d.AccessReviews == nil {
				writeJSON(w, 503, map[string]string{"detail": "login review unavailable"})
				return
			}
			approved, e := d.AccessReviews.ConsumeApprovedAction(u.ID, a.ID, a.Username, accessreviews.ActionTelnet)
			if e != nil {
				writeError(w, e)
				return
			}
			if !approved {
				review, e := d.AccessReviews.RequestAction(u.ID, u.Username, a.ID, a.Name, a.Username, accessreviews.ActionTelnet)
				if e != nil {
					writeError(w, e)
					return
				}
				writeJSON(w, 202, map[string]any{"review_id": review.ID, "state": review.State, "expires_at": review.ExpiresAt})
				return
			}
		}
		guard := func(ctx context.Context) error {
			currentOrigin := origin
			currentOrigin.SourceIP = accesspolicies.SourceIP(ctx)
			currentUser, ok := jobOwnerSnapshot(d, u)
			if !ok {
				return accesspolicies.ErrDenied
			}
			accessMu.RLock()
			defer accessMu.RUnlock()
			current, e := authorizeTerminalAsset(d, currentUser, a.ID, assets.ProtocolTelnet, currentOrigin, false)
			if e != nil || telnetBinding(d, current) != binding {
				return accesspolicies.ErrDenied
			}
			return nil
		}
		request := gateway.CreateRequest{AssetID: a.ID, Protocol: assets.ProtocolTelnet, Cols: input.Cols, Rows: input.Rows, OperatorID: u.ID, Operator: u.Username, AccessPolicy: guard}
		if d.CommandFilters != nil {
			request.CommandPolicy = func(command string, supported bool, at time.Time) gateway.CommandPolicyDecision {
				current, _ := d.Assets.Get(a.ID)
				var groups, nodes []string
				if d.Groups != nil {
					groups = d.Groups.GroupIDsForUser(u.ID)
				}
				if d.Nodes != nil {
					nodes = d.Nodes.AncestorIDs(current.NodeID)
				}
				decision := d.CommandFilters.Decide(commandfilters.Scope{UserID: u.ID, GroupIDs: groups, AssetID: assets.ResourceID(a), NodeIDs: nodes, Account: a.Username}, command, supported, at)
				return gateway.CommandPolicyDecision{Allowed: decision.Allowed, RequireReview: decision.Action == commandfilters.ActionReview, RuleName: decision.RuleName}
			}
		}
		request.Open = func(ctx context.Context, id string, cols, rows int) (gateway.AssetInfo, gateway.Terminal, error) {
			if e := guard(ctx); e != nil {
				return gateway.AssetInfo{}, nil, e
			}
			asset, shell, e := d.Assets.OpenTelnetShell(ctx, id, cols, rows)
			if e != nil {
				return gateway.AssetInfo{}, nil, e
			}
			if e = guard(ctx); e != nil {
				shell.Close()
				return gateway.AssetInfo{}, nil, e
			}
			return gateway.AssetInfo{ID: asset.ID, Name: asset.Name, Host: asset.Host, Port: asset.Port, Username: asset.Username, GatewayIDs: asset.GatewayIDs, Protocol: assets.ProtocolTelnet}, shell, nil
		}
		session, e := d.Sessions.Create(r.Context(), request)
		if e != nil {
			writeError(w, e)
			return
		}
		if d.OrganizationID != "" {
			session.WebSocketURL += "?org=" + d.OrganizationID
		}
		writeJSON(w, 201, session)
	}))
}
