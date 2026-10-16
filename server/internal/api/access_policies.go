package api

import (
	"context"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
)

type accessPolicyKey struct{}

func withAccessPolicies(next http.Handler, d Dependencies) http.Handler {
	var trusted []netip.Prefix
	for _, v := range d.TrustedProxies {
		if p, e := netip.ParsePrefix(v); e == nil {
			trusted = append(trusted, p)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		source := requestSourceIP(r, trusted)
		ctx := context.WithValue(r.Context(), accessPolicyKey{}, d)
		next.ServeHTTP(w, r.WithContext(accesspolicies.WithSourceIP(ctx, source)))
	})
}

// Only an explicitly trusted immediate peer can supply X-Forwarded-For. Walk
// right to left and stop at the first untrusted hop. Other forwarding headers
// never change the source used for access control.
func requestSourceIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		return "unknown"
	}
	peer, e := netip.ParseAddr(host)
	if e != nil || peer.Zone() != "" {
		return "unknown"
	}
	peer = peer.Unmap()
	isTrusted := func(ip netip.Addr) bool {
		for _, p := range trusted {
			if p.Contains(ip) {
				return true
			}
		}
		return false
	}
	if !isTrusted(peer) {
		return peer.String()
	}
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return "unknown"
	}
	raw := strings.Join(values, ",")
	if len(raw) > 2048 {
		return "unknown"
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 32 {
		return "unknown"
	}
	chain := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		ip, e := netip.ParseAddr(strings.TrimSpace(part))
		if e != nil || ip.Zone() != "" {
			return "unknown"
		}
		chain = append(chain, ip.Unmap())
	}
	for i := len(chain) - 1; i >= 0; i-- {
		if !isTrusted(peer) {
			break
		}
		peer = chain[i]
	}
	return peer.String()
}
func policyDependencies(r *http.Request) Dependencies {
	d, _ := r.Context().Value(accessPolicyKey{}).(Dependencies)
	return d
}
func policyScope(d Dependencies, user coreauth.User, asset coreassets.Asset, kind string, origin accesspolicies.Origin) accesspolicies.Scope {
	scope := accesspolicies.Scope{Kind: kind, UserID: user.ID, Origin: origin}
	if d.Groups != nil {
		scope.GroupIDs = d.Groups.GroupIDsForUser(user.ID)
	}
	if kind == accesspolicies.Asset {
		scope.AssetID = asset.ID
		scope.Account = asset.Username
		if d.Nodes != nil {
			scope.NodeIDs = d.Nodes.AncestorIDs(asset.NodeID)
		}
	}
	if kind == accesspolicies.Method {
		scope.AssetID = asset.ID
		scope.Account = asset.Username
	}
	return scope
}
func checkAccessPolicies(d Dependencies, user coreauth.User, asset coreassets.Asset, origin accesspolicies.Origin, record bool) (accesspolicies.Decision, error) {
	if d.OrganizationAllowed != nil && !d.OrganizationAllowed(user) {
		return accesspolicies.Decision{Allowed: false, Reason: "organization_membership"}, nil
	}
	if d.GlobalPolicies != nil && d.GlobalPolicies != d.AccessPolicies {
		global := d
		global.AccessPolicies = d.GlobalPolicies
		global.GlobalPolicies = nil
		global.OrganizationAllowed = nil
		global.Groups = d.GlobalGroups
		decision, e := checkAccessPolicies(global, user, coreassets.Asset{}, accesspolicies.Origin{SourceIP: origin.SourceIP}, record)
		if e != nil || !decision.Allowed {
			return decision, e
		}
	}
	kinds := []string{accesspolicies.Login}
	if origin.Method != "" {
		kinds = append(kinds, accesspolicies.Method, accesspolicies.Asset)
	}
	for _, kind := range kinds {
		scope := policyScope(d, user, asset, kind, origin)
		var decision accesspolicies.Decision
		var err error
		if record {
			decision, err = d.AccessPolicies.Check(scope, time.Now())
		} else {
			decision = d.AccessPolicies.Decide(scope, time.Now())
		}
		if err != nil || !decision.Allowed {
			return decision, err
		}
		if len(kinds) == 1 {
			return decision, nil
		}
	}
	return accesspolicies.Decision{Allowed: true}, nil
}
func writePolicyDenied(w http.ResponseWriter, err error) {
	setNoStore(w)
	if err != nil {
		writeJSON(w, 503, map[string]string{"detail": "access policy audit is unavailable", "code": "access_policy_unavailable"})
		return
	}
	writeJSON(w, 403, map[string]string{"detail": "access policy denied", "code": "access_policy_denied"})
}
func enforceLoginPolicy(w http.ResponseWriter, r *http.Request, user coreauth.User) bool {
	decision, err := checkAccessPolicies(policyDependencies(r), user, coreassets.Asset{}, accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context())}, true)
	if err != nil || !decision.Allowed {
		writePolicyDenied(w, err)
		return false
	}
	return true
}
func enforceAssetPolicy(w http.ResponseWriter, r *http.Request, user coreauth.User, asset coreassets.Asset, method string) bool {
	d := policyDependencies(r)
	decision, err := checkAccessPolicies(d, user, asset, accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: method}, true)
	if err != nil || !decision.Allowed {
		writePolicyDenied(w, err)
		return false
	}
	return true
}
func registerAccessPolicyRoutes(mux *http.ServeMux, d Dependencies) {
	platformAllowed := func(r *http.Request) bool {
		if !d.Tenant {
			return true
		}
		u, _ := PrincipalFromContext(r.Context())
		return effectivePermissions(u, d.GlobalRBAC, d.GlobalGroups).Allows("access_policies.manage")
	}

	protect := func(h http.HandlerFunc) http.Handler { return protectAdminAPI(h, d.AdminToken, d.Auth) }
	mux.Handle("GET /api/v1/access-policies", protect(func(w http.ResponseWriter, r *http.Request) {
		items := d.AccessPolicies.List()
		if d.PlatformOnlyPolicies {
			items = slices.DeleteFunc(items, func(rule accesspolicies.Rule) bool { return rule.Kind != accesspolicies.Login })
		} else if d.Tenant && !platformAllowed(r) {
			items = slices.DeleteFunc(items, func(rule accesspolicies.Rule) bool { return rule.Kind == accesspolicies.Login })
		}
		writeJSON(w, 200, items)
	}))
	mux.Handle("GET /api/v1/access-policies/audit", protect(func(w http.ResponseWriter, r *http.Request) {
		limit, offset := 25, 0
		var err error
		if v := r.URL.Query().Get("limit"); v != "" {
			limit, err = strconv.Atoi(v)
		}
		if v := r.URL.Query().Get("offset"); v != "" && err == nil {
			offset, err = strconv.Atoi(v)
		}
		if err != nil || limit < 1 || limit > 200 || offset < 0 {
			writePolicyError(w, accesspolicies.ErrInvalid)
			return
		}
		scope := "all"
		if d.PlatformOnlyPolicies {
			scope = "platform"
		} else if d.Tenant && !platformAllowed(r) {
			scope = "organization"
		}
		items, total := d.AccessPolicies.AuditPageScope(scope, offset, limit)
		writeJSON(w, 200, map[string]any{"results": items, "total": total, "limit": limit, "offset": offset})
	}))
	mux.Handle("GET /api/v1/access-policies/context", protect(func(w http.ResponseWriter, r *http.Request) {
		u, _ := PrincipalFromContext(r.Context())
		writeJSON(w, 200, map[string]any{"source_ip": accesspolicies.SourceIP(r.Context()), "user_id": u.ID, "at": time.Now().UTC()})
	}))
	validate := func(in accesspolicies.Input, r *http.Request) bool {
		if d.PlatformOnlyPolicies && in.Kind != accesspolicies.Login {
			return false
		}
		if d.Tenant && in.Kind == accesspolicies.Login && (d.OrganizationID != organizations.DefaultID || !platformAllowed(r)) {
			return false
		}
		if d.Tenant && in.Kind != accesspolicies.Login && in.UserID != "" && !organizationSubjectAllowed(r, in.UserID) {
			return false
		}
		for _, id := range in.ApproverIDs {
			if _, ok := d.Auth.UserByID(id); !ok {
				return false
			}
		}
		for _, id := range in.ApproverGroupIDs {
			if d.Groups == nil {
				return false
			}
			if _, e := d.Groups.Get(id); e != nil {
				return false
			}
		}
		if in.UserID != "" {
			if _, ok := d.Auth.UserByID(in.UserID); !ok {
				return false
			}
		}
		if in.GroupID != "" {
			if d.Groups == nil {
				return false
			}
			if _, e := d.Groups.Get(in.GroupID); e != nil {
				return false
			}
		}
		if in.AssetID != "" {
			if d.Assets == nil {
				return false
			}
			if _, e := d.Assets.Get(in.AssetID); e != nil {
				return false
			}
		}
		if in.NodeID != "" {
			if d.Nodes == nil {
				return false
			}
			if _, e := d.Nodes.Get(in.NodeID); e != nil {
				return false
			}
		}
		return true
	}
	save := func(w http.ResponseWriter, r *http.Request) {
		var in accesspolicies.Input
		if decodeRequestJSON(w, r, &in) != nil || !validate(in, r) {
			writePolicyError(w, accesspolicies.ErrInvalid)
			return
		}
		if old, e := d.AccessPolicies.Get(r.PathValue("ruleID")); e == nil && old.Kind == accesspolicies.Login && !platformAllowed(r) {
			writeJSON(w, 403, map[string]string{"code": "organization_denied"})
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		guard := policyScope(d, u, coreassets.Asset{}, accesspolicies.Login, accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context())})
		rule, e := d.AccessPolicies.Save(r.PathValue("ruleID"), in, u.ID, &guard)
		if e != nil {
			writePolicyError(w, e)
			return
		}
		status := 200
		if r.Method == http.MethodPost {
			status = 201
		}
		writeJSON(w, status, rule)
	}
	mux.Handle("POST /api/v1/access-policies", protect(save))
	mux.Handle("PUT /api/v1/access-policies/{ruleID}", protect(save))
	mux.Handle("DELETE /api/v1/access-policies/{ruleID}", protect(func(w http.ResponseWriter, r *http.Request) {
		revision, e := strconv.Atoi(r.URL.Query().Get("revision"))
		if e != nil || revision < 1 {
			writePolicyError(w, accesspolicies.ErrInvalid)
			return
		}
		if old, e := d.AccessPolicies.Get(r.PathValue("ruleID")); e == nil && old.Kind == accesspolicies.Login && !platformAllowed(r) {
			writeJSON(w, 403, map[string]string{"code": "organization_denied"})
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		guard := policyScope(d, u, coreassets.Asset{}, accesspolicies.Login, accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context())})
		if e = d.AccessPolicies.Delete(r.PathValue("ruleID"), revision, u.ID, &guard); e != nil {
			writePolicyError(w, e)
			return
		}
		w.WriteHeader(204)
	}))
}
func writePolicyError(w http.ResponseWriter, err error) {
	status := 500
	code := "access_policy_unavailable"
	switch {
	case errors.Is(err, accesspolicies.ErrInvalid):
		status = 400
		code = "invalid"
	case errors.Is(err, accesspolicies.ErrNotFound):
		status = 404
		code = "not_found"
	case errors.Is(err, accesspolicies.ErrConflict):
		status = 409
		code = "conflict"
	case errors.Is(err, accesspolicies.ErrLockout):
		status = 409
		code = "lockout"
	case errors.Is(err, accesspolicies.ErrCapacity):
		status = 409
		code = "capacity"
	}
	writeJSON(w, status, map[string]string{"detail": "access policy operation failed", "code": code})
}
