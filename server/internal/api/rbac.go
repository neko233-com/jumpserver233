package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	coregroups "github.com/neko233-com/jumpserver233/server/internal/core/groups"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
)

type rbacPolicyKey struct{}
type rbacPolicy struct {
	store  *rbac.Store
	groups *coregroups.Store
}

func withRBAC(next http.Handler, store *rbac.Store, groups *coregroups.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), rbacPolicyKey{}, rbacPolicy{store, groups})))
	})
}
func effectivePermissions(user coreauth.User, store *rbac.Store, groups *coregroups.Store) rbac.Snapshot {
	var ids []string
	if groups != nil {
		ids = groups.GroupIDsForUser(user.ID)
	}
	return store.Effective(user.ID, user.Role, ids)
}
func permissionsForRequest(r *http.Request, user coreauth.User) rbac.Snapshot {
	p, _ := r.Context().Value(rbacPolicyKey{}).(rbacPolicy)
	return effectivePermissions(user, p.store, p.groups)
}
func hasPermission(r *http.Request, permission string) bool {
	user, _ := PrincipalFromContext(r.Context())
	return permissionsForRequest(r, user).Allows(permission)
}
func adminAPIAllowed(r *http.Request, user coreauth.User) bool {
	if user.Role == coreauth.RoleAdmin {
		return true
	}
	snapshot := permissionsForRequest(r, user)
	allowed := func(permissions ...string) bool {
		for _, p := range permissions {
			if snapshot.Allows(p) {
				return true
			}
		}
		return false
	}
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/api/v1/settings/branding"):
		return allowed("branding.manage")
	case strings.HasPrefix(path, "/api/v1/accounts/rotation-"):
		if strings.HasSuffix(path, "/checks") && r.Method == "POST" {
			return allowed("accounts.rotation.check")
		}
		if strings.HasSuffix(path, "/retry") && r.Method == "POST" {
			return allowed("accounts.rotation.execute", "accounts.rotation.check")
		}
		if (strings.HasSuffix(path, "/runs") || strings.HasSuffix(path, "/recover")) && r.Method == "POST" {
			return allowed("accounts.rotation.execute")
		}
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" {
			return allowed("accounts.rotation.manage")
		}
		return allowed("accounts.rotation.view")
	case strings.HasPrefix(path, "/api/v1/accounts/risks"):
		if r.Method == "PUT" || strings.HasSuffix(path, "/review") {
			return allowed("accounts.risks.manage")
		}
		if r.Method == "POST" || r.Method == "DELETE" {
			return allowed("accounts.risks.scan")
		}
		if strings.HasSuffix(path, "/export") {
			return allowed("accounts.risks.export")
		}
		return allowed("accounts.risks.view")
	case strings.HasPrefix(path, "/api/v1/accounts/imports"):
		return allowed("accounts.import")
	case strings.HasPrefix(path, "/api/v1/login-reviews"):
		return allowed("reviews.platform_login.manage")
	case strings.HasPrefix(path, "/api/v1/access-policies"):
		return allowed("access_policies.manage")
	case strings.HasPrefix(path, "/api/v1/rbac/"):
		return allowed("roles.manage")
	case path == "/api/v1/users":
		if r.Method == "GET" {
			return allowed("users.manage", "roles.manage", "groups.manage", "grants.manage", "command_filters.manage", "access_policies.manage")
		}
		return allowed("users.manage")
	case strings.HasPrefix(path, "/api/v1/users/"):
		return allowed("users.manage")
	case strings.HasPrefix(path, "/api/v1/user-groups"):
		if r.Method == "GET" {
			return allowed("groups.manage", "roles.manage", "grants.manage", "command_filters.manage", "access_policies.manage")
		}
		return allowed("groups.manage")
	case strings.HasPrefix(path, "/api/v1/settings/security/"):
		return allowed("security.manage")
	case strings.HasPrefix(path, "/api/v1/identity-sources"):
		return allowed("security.manage")
	case strings.HasPrefix(path, "/api/v1/assets/nodes"):
		return allowed("nodes.manage")
	case strings.HasPrefix(path, "/api/v1/assets/") && strings.Contains(path, "/credential-backups"):
		return allowed("assets.backups")
	case strings.HasPrefix(path, "/api/v1/assets/") && (strings.HasSuffix(path, "/password-rotation") || strings.Contains(path, "/ssh-key-rotation")):
		return allowed("assets.rotate")
	case strings.HasPrefix(path, "/api/v1/assets/") && strings.HasSuffix(path, "/probe"):
		return allowed("assets.probe")
	case path == "/api/v1/assets" || strings.HasPrefix(path, "/api/v1/assets/"):
		return allowed("assets.manage")
	case strings.HasPrefix(path, "/api/v1/grants"):
		return allowed("grants.manage")
	case strings.HasPrefix(path, "/api/v1/command-filters"):
		return allowed("command_filters.manage")
	case strings.HasPrefix(path, "/api/v1/command-reviews"):
		return allowed("reviews.command.manage")
	case strings.HasPrefix(path, "/api/v1/access-reviews"):
		return allowed("reviews.login.manage")
	case strings.HasPrefix(path, "/api/v1/ops/jobs/") && strings.HasSuffix(path, "/review"):
		return allowed("jobs.review")
	default:
		return false
	}
}
func registerRBACRoutes(mux *http.ServeMux, d Dependencies) {
	authenticated := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	protect := func(h http.HandlerFunc) http.Handler { return protectAdminAPI(h, d.AdminToken, d.Auth) }
	mux.Handle("GET /api/v1/rbac/me", authenticated(func(w http.ResponseWriter, r *http.Request) {
		u, _ := PrincipalFromContext(r.Context())
		snapshot := permissionsForRequest(r, u)
		writeJSON(w, 200, map[string]any{"user_id": u.ID, "role_ids": snapshot.RoleIDs, "permissions": rbac.Union(snapshot, effectivePermissions(u, d.GlobalRBAC, d.GlobalGroups)).Permissions, "organization_permissions": snapshot.Permissions, "organization_id": d.OrganizationID, "system_permissions": effectivePermissions(u, d.GlobalRBAC, d.GlobalGroups).Permissions})
	}))
	mux.Handle("GET /api/v1/rbac/permissions", protect(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, d.RBAC.Catalog()) }))
	mux.Handle("GET /api/v1/rbac/roles", protect(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, d.RBAC.Roles()) }))
	saveRole := func(w http.ResponseWriter, r *http.Request) {
		var in rbac.RoleInput
		if decodeRequestJSON(w, r, &in) != nil {
			writeRBACError(w, rbac.ErrInvalid)
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		role, err := d.RBAC.SaveRole(r.PathValue("roleID"), in, u.ID, u.Username)
		if err != nil {
			writeRBACError(w, err)
			return
		}
		status := 200
		if r.Method == "POST" {
			status = 201
		}
		writeJSON(w, status, role)
	}
	mux.Handle("POST /api/v1/rbac/roles", protect(saveRole))
	mux.Handle("PUT /api/v1/rbac/roles/{roleID}", protect(saveRole))
	mux.Handle("DELETE /api/v1/rbac/roles/{roleID}", protect(func(w http.ResponseWriter, r *http.Request) {
		revision, err := strconv.Atoi(r.URL.Query().Get("revision"))
		if err != nil || revision < 1 {
			writeRBACError(w, rbac.ErrInvalid)
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		if err := d.RBAC.DeleteRole(r.PathValue("roleID"), revision, u.ID, u.Username); err != nil {
			writeRBACError(w, err)
			return
		}
		w.WriteHeader(204)
	}))
	mux.Handle("GET /api/v1/rbac/bindings", protect(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, d.RBAC.Bindings()) }))
	mux.Handle("PUT /api/v1/rbac/bindings", protect(func(w http.ResponseWriter, r *http.Request) {
		var in rbac.BindingInput
		if decodeRequestJSON(w, r, &in) != nil {
			writeRBACError(w, rbac.ErrInvalid)
			return
		}
		exists := false
		if in.SubjectType == "user" {
			_, exists = d.Auth.UserByID(in.SubjectID)
			if exists && !organizationSubjectAllowed(r, in.SubjectID) {
				exists = false
			}
		} else if in.SubjectType == "group" && d.Groups != nil {
			for _, group := range d.Groups.List() {
				if group.ID == in.SubjectID {
					exists = true
					break
				}
			}
		}
		if !exists {
			writeRBACError(w, rbac.ErrInvalid)
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		b, err := d.RBAC.SaveBinding(in, u.ID, u.Username)
		if err != nil {
			writeRBACError(w, err)
			return
		}
		writeJSON(w, 200, b)
	}))
	mux.Handle("GET /api/v1/rbac/audit", protect(func(w http.ResponseWriter, r *http.Request) {
		offset, limit := 0, 50
		var err error
		if v := r.URL.Query().Get("offset"); v != "" {
			offset, err = strconv.Atoi(v)
		}
		if err == nil {
			if v := r.URL.Query().Get("limit"); v != "" {
				limit, err = strconv.Atoi(v)
			}
		}
		if err != nil || offset < 0 || limit < 1 || limit > 100 {
			writeRBACError(w, rbac.ErrInvalid)
			return
		}
		items, total := d.RBAC.Audit(offset, limit)
		writeJSON(w, 200, map[string]any{"results": items, "total": total})
	}))
}
func writeRBACError(w http.ResponseWriter, err error) {
	status := 500
	detail := "RBAC state or audit is unavailable"
	switch {
	case errors.Is(err, rbac.ErrInvalid):
		status = 400
		detail = "invalid role, permission or subject"
	case errors.Is(err, rbac.ErrNotFound):
		status = 404
		detail = "role not found"
	case errors.Is(err, rbac.ErrConflict):
		status = 409
		detail = "revision conflicts or role remains bound"
	case errors.Is(err, rbac.ErrProtected):
		status = 403
		detail = "built-in role is immutable"
	case errors.Is(err, rbac.ErrCapacity):
		status = 503
		detail = "RBAC history or record capacity reached"
	}
	writeJSON(w, status, map[string]string{"detail": detail})
}
