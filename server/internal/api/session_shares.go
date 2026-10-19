package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	"github.com/neko233-com/jumpserver233/server/internal/core/sessionshares"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
)

func shareActor(r *http.Request) sessionshares.Actor {
	u, _ := PrincipalFromContext(r.Context())
	return sessionshares.Actor{ID: u.ID, Name: u.Username}
}
func shareError(w http.ResponseWriter, e error) {
	status := 500
	switch {
	case errors.Is(e, sessionshares.ErrDenied), errors.Is(e, gateway.ErrSessionNotFound):
		status = 404
	case errors.Is(e, sessionshares.ErrInvalid), errors.Is(e, gateway.ErrInvalidSessionRequest):
		status = 400
	case errors.Is(e, sessionshares.ErrCapacity):
		status = 429
	case errors.Is(e, sessionshares.ErrAudit):
		status = 503
	case errors.Is(e, gateway.ErrCommandReviewInProgress):
		status = 409
	}
	writeJSON(w, status, map[string]string{"detail": "session sharing is unavailable"})
}
func registerSessionShareRoutes(mux *http.ServeMux, b *gateway.Broker, adminToken string, identities *coreauth.Service) {
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, adminToken, identities) }
	mux.Handle("POST /api/v1/sessions/{sessionID}/shares", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !hasPermission(r, "sessions.share") || identities == nil {
			writeJSON(w, 403, map[string]string{"detail": "session sharing is not allowed"})
			return
		}
		var in struct {
			Mode    string   `json:"mode"`
			Minutes int      `json:"minutes"`
			Users   []string `json:"users"`
		}
		if decodeRequestJSON(w, r, &in) != nil || len(in.Users) < 1 || len(in.Users) > 20 {
			shareError(w, sessionshares.ErrInvalid)
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		d := policyDependencies(r)
		info, infoErr := b.ShareAsset(r.PathValue("sessionID"), u.ID)
		if infoErr != nil {
			shareError(w, infoErr)
			return
		}
		source := accesspolicies.SourceIP(r.Context())
		ids := []string{}
		usersByName := map[string]coreauth.User{}
		for _, candidate := range identities.ListUsers() {
			usersByName[candidate.Username] = candidate
		}
		for _, name := range in.Users {
			found := false
			if candidate, exists := usersByName[strings.TrimSpace(name)]; exists {
				if candidate.Username == strings.TrimSpace(name) && organizationSubjectAllowed(r, candidate.ID) {
					if _, ok := identities.ActiveUserByID(candidate.ID); ok {
						ids = append(ids, candidate.ID)
						found = true
					}
				}
			}
			if !found {
				shareError(w, sessionshares.ErrInvalid)
				return
			}
		}
		check := func() error {
			current := u
			if u.ID != "admin-token" && u.ID != "loopback-admin" {
				var ok bool
				current, ok = identities.ActiveUserSnapshot(u)
				if !ok {
					return sessionshares.ErrDenied
				}
			}
			if !effectivePermissions(current, d.RBAC, d.Groups).Allows("sessions.share") {
				return sessionshares.ErrDenied
			}
			if d.OrganizationAllowed != nil && !d.OrganizationAllowed(current) {
				return sessionshares.ErrDenied
			}
			if d.Assets == nil {
				return sessionshares.ErrDenied
			}
			protocol := info.Protocol
			if protocol == "" {
				protocol = "ssh"
			}
			_, e := authorizeTerminalAsset(d, current, info.ID, protocol, accesspolicies.Origin{SourceIP: source, Method: protocol}, false)
			return e
		}
		created, e := b.CreateShare(r.Context(), r.PathValue("sessionID"), shareActor(r), sessionshares.Input{Mode: in.Mode, Minutes: in.Minutes, AllowedUsers: ids}, check)
		if e != nil {
			shareError(w, e)
			return
		}
		writeJSON(w, 201, created)
	}))
	mux.Handle("GET /api/v1/sessions/{sessionID}/shares", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		state, e := b.ShareState(r.PathValue("sessionID"), shareActor(r).ID)
		if e != nil {
			shareError(w, e)
			return
		}
		state.Usernames = map[string]string{}
		if identities != nil {
			for _, invitation := range state.Shares {
				for _, id := range invitation.AllowedUsers {
					if user, ok := identities.UserByID(id); ok {
						state.Usernames[id] = user.Username
					}
				}
			}
		}
		writeJSON(w, 200, state)
	}))
	mux.Handle("DELETE /api/v1/session-shares/{shareID}", protect(func(w http.ResponseWriter, r *http.Request) {
		if e := b.RevokeShare(r.PathValue("shareID"), shareActor(r)); e != nil {
			shareError(w, e)
			return
		}
		w.WriteHeader(204)
	}))
	mux.Handle("DELETE /api/v1/session-share-members/{memberID}", protect(func(w http.ResponseWriter, r *http.Request) {
		if e := b.KickShareMember(r.PathValue("memberID"), shareActor(r)); e != nil {
			shareError(w, e)
			return
		}
		w.WriteHeader(204)
	}))
	mux.Handle("POST /api/v1/sessions/{sessionID}/share-control", protect(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			MemberID string `json:"member_id"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			shareError(w, sessionshares.ErrInvalid)
			return
		}
		if e := b.ChangeShareControl(r.Context(), r.PathValue("sessionID"), shareActor(r), in.MemberID); e != nil {
			shareError(w, e)
			return
		}
		w.WriteHeader(204)
	}))
	mux.Handle("POST /api/v1/session-shares/{shareID}/join", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		var in struct {
			Code string `json:"code"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			shareError(w, sessionshares.ErrInvalid)
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		d := policyDependencies(r)
		source := accesspolicies.SourceIP(r.Context())
		current := func() (coreauth.User, bool) {
			if u.ID == "admin-token" || u.ID == "loopback-admin" {
				return u, true
			}
			if identities == nil {
				return u, false
			}
			return identities.ActiveUserSnapshot(u)
		}
		guard := func(ctx context.Context, info gateway.AssetInfo) error {
			if accesspolicies.SourceIP(ctx) != source {
				return sessionshares.ErrDenied
			}
			principal, ok := current()
			if !ok {
				return sessionshares.ErrDenied
			}
			if d.Assets == nil {
				return sessionshares.ErrDenied
			}
			id := info.ID
			for hops := 0; ; hops++ {
				if hops > 3 {
					return sessionshares.ErrDenied
				}
				asset, e := d.Assets.Get(id)
				if e != nil {
					return sessionshares.ErrDenied
				}
				method := info.Protocol
				if method == "" {
					method = "ssh"
				}
				decision, e := checkAccessPolicies(d, principal, asset, accesspolicies.Origin{SourceIP: source, Method: method}, false)
				if e != nil || !decision.Allowed {
					return sessionshares.ErrDenied
				}
				if asset.GatewayID == "" {
					break
				}
				id = asset.GatewayID
			}
			return nil
		}
		policy := func(info gateway.AssetInfo) gateway.CommandPolicy {
			return func(command string, supported bool, at time.Time) gateway.CommandPolicyDecision {
				principal, ok := current()
				if !ok || d.Assets == nil {
					return gateway.CommandPolicyDecision{}
				}
				asset, e := d.Assets.Get(info.ID)
				if e != nil {
					return gateway.CommandPolicyDecision{}
				}
				if d.CommandFilters == nil {
					return gateway.CommandPolicyDecision{Allowed: true}
				}
				groups, nodes := []string{}, []string{}
				if d.Groups != nil {
					groups = d.Groups.GroupIDsForUser(principal.ID)
				}
				if d.Nodes != nil {
					nodes = d.Nodes.AncestorIDs(asset.NodeID)
				}
				v := d.CommandFilters.Decide(commandfilters.Scope{UserID: principal.ID, GroupIDs: groups, AssetID: assets.ResourceID(asset), NodeIDs: nodes, Account: asset.Username}, command, supported, at)
				return gateway.CommandPolicyDecision{Allowed: v.Allowed, RequireReview: v.Action == commandfilters.ActionReview, RuleName: v.RuleName, PolicyKey: v.PolicyKey, DirectoryRequired: v.DirectoryRequired}
			}
		}
		created, e := b.JoinShare(r.Context(), r.PathValue("shareID"), in.Code, shareActor(r), guard, policy)
		if e != nil {
			shareError(w, e)
			return
		}
		if d.OrganizationID != "" {
			created.WebSocketURL += "?org=" + d.OrganizationID
		}
		writeJSON(w, 201, created)
	}))
	mux.Handle("GET /api/v1/sessions/{sessionID}/share-events", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		offset, limit := 0, 50
		var e error
		if v := r.URL.Query().Get("offset"); v != "" {
			offset, e = strconv.Atoi(v)
		}
		if e == nil {
			if v := r.URL.Query().Get("limit"); v != "" {
				limit, e = strconv.Atoi(v)
			}
		}
		if e != nil || offset < 0 || offset > 1000000 || limit < 1 || limit > 100 {
			shareError(w, sessionshares.ErrInvalid)
			return
		}
		rows, total, e := b.ListShareEvents(r.PathValue("sessionID"), shareActor(r).ID, hasPermission(r, "audit.sessions.view_all"), offset, limit)
		if e != nil {
			shareError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": total, "offset": offset, "limit": limit})
	}))
	mux.HandleFunc("GET /ws/api/v1/sessions/{sessionID}/share", b.ServeShare)
}
