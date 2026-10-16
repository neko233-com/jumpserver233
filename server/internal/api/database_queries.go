package api

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	"github.com/neko233-com/jumpserver233/server/internal/core/databasequery"
)

func databaseBinding(a assets.Asset) string {
	return databasequery.Binding(struct {
		Protocol           string
		Host               string
		Port               int
		Username           string
		Revision           uint64
		Gateway            string
		Settings           *sqlclient.Settings
		HostKeyFingerprint string `json:",omitempty"`
	}{assets.Protocol(a), a.Host, a.Port, a.Username, a.CredentialRevision, a.GatewayID, assets.DatabaseSettings(a), a.HostKeyFingerprint})
}
func databaseRouteBinding(d Dependencies, a assets.Asset) string {
	bindings := []string{databaseBinding(a)}
	seen := map[string]bool{a.ID: true}
	for a.GatewayID != "" {
		if len(bindings) > 3 || seen[a.GatewayID] {
			return ""
		}
		seen[a.GatewayID] = true
		next, e := d.Assets.Get(a.GatewayID)
		if e != nil || !assets.IsSSH(next) {
			return ""
		}
		bindings = append(bindings, databaseBinding(next))
		a = next
	}
	return databasequery.Binding(bindings)
}
func authorizeDatabase(d Dependencies, u coreauth.User, id, sql string, origin accesspolicies.Origin, audit bool) (assets.Asset, commandfilters.Decision, error) {
	a, e := d.Assets.Get(id)
	if e != nil {
		return a, commandfilters.Decision{}, assets.ErrNotFound
	}
	if !assets.IsDatabase(a) {
		return a, commandfilters.Decision{}, assets.ErrUnsupportedProtocol
	}
	var groups, nodes []string
	if d.Groups != nil {
		groups = d.Groups.GroupIDsForUser(u.ID)
	}
	if d.Nodes != nil {
		nodes = d.Nodes.AncestorIDs(a.NodeID)
	}
	if !effectivePermissions(u, d.RBAC, d.Groups).Allows("assets.connect_all") && (d.Grants == nil || !d.Grants.AllowsForScopes(u.ID, groups, a.ID, nodes, a.Username, "connect", time.Now().UTC())) {
		return a, commandfilters.Decision{}, databasequery.ErrDenied
	}
	decision, e := checkAccessPolicies(d, u, a, origin, audit)
	if e != nil || !decision.Allowed {
		return a, commandfilters.Decision{}, databasequery.ErrDenied
	}
	for gatewayID, hops := a.GatewayID, 0; gatewayID != ""; hops++ {
		if hops >= 3 {
			return a, commandfilters.Decision{}, databasequery.ErrDenied
		}
		gateway, e := d.Assets.Get(gatewayID)
		if e != nil || !assets.IsSSH(gateway) {
			return a, commandfilters.Decision{}, databasequery.ErrDenied
		}
		policy, e := checkAccessPolicies(d, u, gateway, origin, audit)
		if e != nil || !policy.Allowed {
			return a, commandfilters.Decision{}, databasequery.ErrDenied
		}
		gatewayID = gateway.GatewayID
	}
	filter := commandfilters.Decision{Allowed: true, Action: commandfilters.ActionAllow}
	if sql != "" && d.CommandFilters != nil {
		filter = d.CommandFilters.Decide(commandfilters.Scope{UserID: u.ID, GroupIDs: groups, AssetID: a.ID, NodeIDs: nodes, Account: a.Username}, sql, true, time.Now().UTC())
		if filter.Action == commandfilters.ActionDeny {
			return a, filter, databasequery.ErrDenied
		}
	}
	return a, filter, nil
}
func registerDatabaseQueryRoutes(mux *http.ServeMux, d Dependencies, accessMu *sync.RWMutex) {
	s := d.DatabaseQueries
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	s.SetGuard(func(j databasequery.Job) error {
		u, ok := jobOwner(d, j.OperatorID)
		if !ok {
			return databasequery.ErrDenied
		}
		accessMu.RLock()
		defer accessMu.RUnlock()
		a, filter, e := authorizeDatabase(d, u, j.AssetID, j.ExecutionSQL, j.Origin, false)
		if e != nil || a.Username != j.Account || databaseRouteBinding(d, a) != j.Binding {
			return databasequery.ErrDenied
		}
		if filter.Action == commandfilters.ActionReview && (j.ReviewedBy == "" || j.RuleName != filter.RuleName) {
			return databasequery.ErrDenied
		}
		return nil
	})
	mux.Handle("POST /api/v1/assets/{assetID}/database-sessions", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		u, _ := PrincipalFromContext(r.Context())
		origin := accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "database"}
		accessMu.RLock()
		defer accessMu.RUnlock()
		a, _, e := authorizeDatabase(d, u, r.PathValue("assetID"), "", origin, true)
		if e != nil {
			writeDatabaseError(w, e)
			return
		}
		if !hasPermission(r, "login_review.bypass") && a.LoginReviewRequired {
			if d.AccessReviews == nil {
				writeJSON(w, 503, map[string]string{"detail": "database_review_unavailable"})
				return
			}
			approved, e := d.AccessReviews.ConsumeApprovedAction(u.ID, a.ID, a.Username, accessreviews.ActionDatabase)
			if e != nil {
				writeDatabaseError(w, e)
				return
			}
			if !approved {
				review, e := d.AccessReviews.RequestAction(u.ID, u.Username, a.ID, a.Name, a.Username, accessreviews.ActionDatabase)
				if e != nil {
					writeDatabaseError(w, e)
					return
				}
				writeJSON(w, 202, map[string]any{"review_id": review.ID, "state": review.State, "expires_at": review.ExpiresAt})
				return
			}
		}
		e = d.Assets.PingDatabase(r.Context(), a.ID)
		if e != nil {
			writeDatabaseError(w, e)
			return
		}
		settings := assets.DatabaseSettings(a)
		session, e := s.CreateSession(databasequery.Session{Protocol: assets.Protocol(a), UserID: u.ID, Operator: u.Username, AssetID: a.ID, AssetName: a.Name, Account: a.Username, Database: settings.Database, ReadOnly: settings.ReadOnly, Binding: databaseRouteBinding(d, a)})
		if e != nil {
			writeDatabaseError(w, e)
			return
		}
		writeJSON(w, 201, session)
	}))
	mux.Handle("DELETE /api/v1/database-sessions", protect(func(w http.ResponseWriter, r *http.Request) {
		u, _ := PrincipalFromContext(r.Context())
		if e := s.DeleteSession(r.Header.Get("X-JMS-DB-SESSION"), u.ID); e != nil {
			writeDatabaseError(w, e)
			return
		}
		w.WriteHeader(204)
	}))
	mux.Handle("POST /api/v1/assets/{assetID}/database-queries", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		u, _ := PrincipalFromContext(r.Context())
		var in databasequery.Input
		if decodeRequestJSON(w, r, &in) != nil {
			writeDatabaseError(w, databasequery.ErrInvalid)
			return
		}
		if in.RowLimit == 0 {
			in.RowLimit = 500
		}
		if in.TimeoutSeconds == 0 {
			in.TimeoutSeconds = 30
		}

		session, e := s.Session(r.Header.Get("X-JMS-DB-SESSION"), u.ID, r.PathValue("assetID"))
		if e != nil {
			writeDatabaseError(w, e)
			return
		}
		in.Dialect = session.Protocol
		if sqlclient.ValidateInput(in.Input) != nil {
			writeDatabaseError(w, databasequery.ErrInvalid)
			return
		}
		origin := accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "database"}
		accessMu.RLock()
		defer accessMu.RUnlock()
		a, filter, e := authorizeDatabase(d, u, session.AssetID, in.SQL, origin, true)
		if e != nil {
			writeDatabaseError(w, e)
			return
		}
		if databaseRouteBinding(d, a) != session.Binding {
			writeDatabaseError(w, databasequery.ErrDenied)
			return
		}
		j, e := s.Submit(session, in, origin, filter.Action == commandfilters.ActionReview, filter.RuleName)
		if e != nil {
			writeDatabaseError(w, e)
			return
		}
		writeJSON(w, 201, j)
	}))
	mux.Handle("GET /api/v1/database-queries", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		u, _ := PrincipalFromContext(r.Context())
		all := hasPermission(r, "database.audit.view_all")
		rows := s.List(u.ID, r.URL.Query().Get("asset_id"), all)
		if r.URL.Query().Get("pending_reviews") == "true" {
			if !hasPermission(r, "reviews.command.manage") {
				writeDatabaseError(w, databasequery.ErrDenied)
				return
			}
			rows = s.List(u.ID, "", true)
			filtered := rows[:0]
			for _, j := range rows {
				if j.State == "awaiting_review" {
					filtered = append(filtered, j)
				}
			}
			rows = filtered
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": len(rows)})
	}))
	mux.Handle("GET /api/v1/database-queries/{queryID}", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		u, _ := PrincipalFromContext(r.Context())
		auditAll := hasPermission(r, "database.audit.view_all")
		reviewer := hasPermission(r, "reviews.command.manage")
		response, e := s.Get(r.PathValue("queryID"), u.ID, auditAll || reviewer)
		if e != nil {
			writeDatabaseError(w, e)
			return
		}
		if response.OperatorID != u.ID && !auditAll && response.State != "awaiting_review" {
			writeDatabaseError(w, databasequery.ErrNotFound)
			return
		}
		if response.OperatorID == u.ID {
			accessMu.RLock()
			a, _, authErr := authorizeDatabase(d, u, response.AssetID, "", accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "database"}, false)
			accessMu.RUnlock()
			if authErr != nil || databaseRouteBinding(d, a) != response.Binding {
				response.Result = nil
				response.ResultAvailable = false
				if !auditAll {
					writeDatabaseError(w, databasequery.ErrDenied)
					return
				}
			}
		}
		writeJSON(w, 200, response)
	}))
	mux.Handle("POST /api/v1/database-queries/{queryID}/cancel", protect(func(w http.ResponseWriter, r *http.Request) {
		u, _ := PrincipalFromContext(r.Context())
		if e := s.Cancel(r.PathValue("queryID"), u.ID, hasPermission(r, "database.cancel_all")); e != nil {
			writeDatabaseError(w, e)
			return
		}
		w.WriteHeader(204)
	}))
	mux.Handle("POST /api/v1/database-queries/{queryID}/review", protect(func(w http.ResponseWriter, r *http.Request) {
		if !hasPermission(r, "reviews.command.manage") {
			writeDatabaseError(w, databasequery.ErrDenied)
			return
		}
		var input struct {
			Approve bool `json:"approve"`
		}
		if decodeRequestJSON(w, r, &input) != nil {
			writeDatabaseError(w, databasequery.ErrInvalid)
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		if e := s.Resolve(r.PathValue("queryID"), u.Username, input.Approve); e != nil {
			writeDatabaseError(w, e)
			return
		}
		w.WriteHeader(204)
	}))
}
func writeDatabaseError(w http.ResponseWriter, e error) {
	setNoStore(w)
	switch {
	case errors.Is(e, databasequery.ErrNotFound), errors.Is(e, assets.ErrNotFound):
		writeJSON(w, 404, map[string]string{"detail": "database_resource_not_found"})
	case errors.Is(e, databasequery.ErrDenied), errors.Is(e, sqlclient.ErrDenied):
		writeJSON(w, 403, map[string]string{"detail": "database_access_denied"})
	case errors.Is(e, databasequery.ErrConflict):
		writeJSON(w, 409, map[string]string{"detail": "database_query_conflict"})
	case errors.Is(e, databasequery.ErrBusy):
		writeJSON(w, 429, map[string]string{"detail": "database_query_busy"})
	case errors.Is(e, databasequery.ErrInvalid), errors.Is(e, sqlclient.ErrInvalid), errors.Is(e, assets.ErrUnsupportedProtocol):
		writeJSON(w, 400, map[string]string{"detail": "database_input_invalid"})
	case errors.Is(e, sqlclient.ErrUnavailable):
		writeJSON(w, 502, map[string]string{"detail": "database_connection_failed"})
	default:
		writeJSON(w, 503, map[string]string{"detail": "database_operation_unavailable"})
	}
}
