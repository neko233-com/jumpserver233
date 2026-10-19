package api

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
)

func systemAdministrator(d Dependencies, u coreauth.User) bool {
	return u.Role == coreauth.RoleAdmin || slices.Contains(effectivePermissions(u, d.GlobalRBAC, d.GlobalGroups).RoleIDs, "system-administrator")
}
func organizationSubjectAllowed(r *http.Request, id string) bool {
	d := policyDependencies(r)
	if !d.Tenant || d.OrganizationAllowed == nil {
		return true
	}
	u, ok := d.Auth.UserByID(id)
	return ok && d.OrganizationAllowed(u)
}
func organizationHeader(r *http.Request) (string, error) {
	values := r.Header.Values("X-JMS-ORG")
	if len(values) > 1 {
		return "", organizations.ErrInvalid
	}
	id := ""
	if len(values) == 1 {
		id = values[0]
	}
	if strings.HasPrefix(r.URL.Path, "/ws/") {
		values := r.URL.Query()["org"]
		if len(values) > 1 {
			return "", organizations.ErrInvalid
		}
		if len(values) == 1 {
			if id != "" && id != values[0] {
				return "", organizations.ErrInvalid
			}
			id = values[0]
		}
	} else if r.URL.Query().Has("org") {
		return "", organizations.ErrInvalid
	}
	if id == "" {
		return organizations.DefaultID, nil
	}
	if !organizations.ValidID(id) {
		return "", organizations.ErrInvalid
	}
	return id, nil
}

// Resource handlers are selected before route matching. No resource lookup can
// fall back to another organization. WebSocket tickets select a broker and its
// saved policy checks the current owner membership before terminal attachment.
func NewOrganizationRouter(version string, d Dependencies, resources func(string) (http.Handler, error)) http.Handler {
	global := NewRouter(version, d)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, e := organizationHeader(r)
		if e != nil {
			writeOrganizationError(w, e)
			return
		}
		path := r.URL.Path
		if strings.HasPrefix(path, "/api/v1/branding") || strings.HasPrefix(path, "/api/v1/settings/branding") {
			global.ServeHTTP(w, r)
			return
		}
		if path == "/api/v1/system/users" || strings.HasPrefix(path, "/api/v1/system/user-groups") {
			next := r.Clone(r.Context())
			url := *r.URL
			next.URL = &url
			next.URL.Path = strings.Replace(path, "/api/v1/system/", "/api/v1/", 1)
			global.ServeHTTP(w, next)
			return
		}
		if strings.HasPrefix(path, "/api/v1/system/rbac") {
			next := r.Clone(r.Context())
			url := *r.URL
			next.URL = &url
			next.URL.Path = strings.Replace(path, "/api/v1/system/rbac", "/api/v1/rbac", 1)
			global.ServeHTTP(w, next)
			return
		}
		if strings.HasPrefix(path, "/api/v1/platform-access-policies") {
			next := r.Clone(r.Context())
			url := *r.URL
			next.URL = &url
			next.URL.Path = strings.Replace(path, "/api/v1/platform-access-policies", "/api/v1/access-policies", 1)
			global.ServeHTTP(w, next)
			return
		}
		isGlobal := strings.HasPrefix(path, "/api/v1/audits/logins") || strings.HasPrefix(path, "/api/v1/platform-notifications") || r.Method == "OPTIONS" || path == "/api/health" || strings.HasPrefix(path, "/api/v1/authentication/") || strings.HasPrefix(path, "/api/v1/settings/security/") || strings.HasPrefix(path, "/api/v1/login-reviews") || strings.HasPrefix(path, "/api/v1/organizations") || strings.HasPrefix(path, "/api/v1/users/") || path == "/api/v1/users" && r.Method != "GET" || strings.HasPrefix(path, "/api/v1/rbac/") && path != "/api/v1/rbac/me"
		if isGlobal {
			global.ServeHTTP(w, r)
			return
		}
		if !d.Organizations.Enabled(id) {
			writeOrganizationError(w, organizations.ErrNotFound)
			return
		}
		if !strings.HasPrefix(path, "/ws/") {
			u, status := resolvePrincipal(r, d.AdminToken, d.Auth)
			if status != 200 {
				writeJSON(w, status, map[string]string{"detail": "authentication required"})
				return
			}
			if !systemAdministrator(d, u) && d.Organizations.Role(id, u.ID) == "none" {
				writeJSON(w, 403, map[string]string{"detail": "organization membership required", "code": "organization_denied"})
				return
			}
		}
		handler, e := resources(id)
		if e != nil {
			writeOrganizationError(w, e)
			return
		}
		w.Header().Set("X-JMS-ORG", id)
		if strings.HasPrefix(path, "/api/v1/organization-rbac") {
			next := r.Clone(r.Context())
			url := *r.URL
			next.URL = &url
			next.URL.Path = strings.Replace(path, "/api/v1/organization-rbac", "/api/v1/rbac", 1)
			handler.ServeHTTP(w, next)
			return
		}
		handler.ServeHTTP(w, r)
	})
}
func registerOrganizationRoutes(mux *http.ServeMux, d Dependencies) {
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	canManage := func(r *http.Request, u coreauth.User) bool {
		return permissionsForRequest(r, u).Allows("organizations.manage")
	}
	canMembers := func(r *http.Request, u coreauth.User, id string) bool {
		if canManage(r, u) {
			return true
		}
		if d.OrganizationSnapshot == nil {
			return false
		}
		snapshot, e := d.OrganizationSnapshot(id, u)
		return e == nil && snapshot.Allows("organizations.members.manage")
	}
	changed := func(id string) {
		if d.OrganizationChanged != nil {
			d.OrganizationChanged(id)
		}
	}
	mux.Handle("GET /api/v1/organizations", protect(func(w http.ResponseWriter, r *http.Request) {
		u, _ := PrincipalFromContext(r.Context())
		manage := canManage(r, u)
		type view struct {
			organizations.Organization
			MemberRole       string `json:"member_role"`
			CanManageMembers bool   `json:"can_manage_members"`
		}
		out := []view{}
		for _, o := range d.Organizations.List(manage && r.URL.Query().Get("include_archived") == "true") {
			role := d.Organizations.Role(o.ID, u.ID)
			if manage || systemAdministrator(d, u) || o.Enabled && role != "none" {
				if systemAdministrator(d, u) {
					role = "admin"
				}
				out = append(out, view{Organization: o, MemberRole: role, CanManageMembers: canMembers(r, u, o.ID)})
			}
		}
		id, e := organizationHeader(r)
		if e != nil {
			writeOrganizationError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": out, "current_id": id, "can_manage": manage})
	}))
	save := func(w http.ResponseWriter, r *http.Request) {
		u, _ := PrincipalFromContext(r.Context())
		if !canManage(r, u) {
			writeJSON(w, 403, map[string]string{"code": "organization_denied"})
			return
		}
		var in organizations.Input
		if decodeRequestJSON(w, r, &in) != nil {
			writeOrganizationError(w, organizations.ErrInvalid)
			return
		}
		o, e := d.Organizations.Save(r.PathValue("organizationID"), in, u.ID)
		if e != nil {
			writeOrganizationError(w, e)
			return
		}
		changed(o.ID)
		status := 200
		if r.Method == "POST" {
			status = 201
		}
		writeJSON(w, status, o)
	}
	mux.Handle("POST /api/v1/organizations", protect(save))
	mux.Handle("PUT /api/v1/organizations/{organizationID}", protect(save))
	archive := func(restore bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			u, _ := PrincipalFromContext(r.Context())
			if !canManage(r, u) {
				writeJSON(w, 403, map[string]string{"code": "organization_denied"})
				return
			}
			revision, e := strconv.Atoi(r.URL.Query().Get("revision"))
			if e != nil {
				writeOrganizationError(w, organizations.ErrInvalid)
				return
			}
			id := r.PathValue("organizationID")
			if e = d.Organizations.Archive(id, revision, restore, u.ID); e != nil {
				writeOrganizationError(w, e)
				return
			}
			changed(id)
			w.WriteHeader(204)
		}
	}
	mux.Handle("DELETE /api/v1/organizations/{organizationID}", protect(archive(false)))
	mux.Handle("POST /api/v1/organizations/{organizationID}/restore", protect(archive(true)))
	mux.Handle("GET /api/v1/organizations/{organizationID}/members", protect(func(w http.ResponseWriter, r *http.Request) {
		u, _ := PrincipalFromContext(r.Context())
		id := r.PathValue("organizationID")
		if !canMembers(r, u, id) {
			writeJSON(w, 403, map[string]string{"code": "organization_denied"})
			return
		}
		type view struct {
			organizations.Member
			Username string `json:"username"`
			Implicit bool   `json:"implicit"`
		}
		out := []view{}
		for _, candidate := range d.Auth.ListUsers() {
			m, explicit := d.Organizations.Member(id, candidate.ID)
			if !explicit {
				if id != organizations.DefaultID {
					continue
				}
				m = organizations.Member{MemberInput: organizations.MemberInput{UserID: candidate.ID, Role: "member"}}
			}
			out = append(out, view{Member: m, Username: candidate.Username, Implicit: !explicit})
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("PUT /api/v1/organizations/{organizationID}/members", protect(func(w http.ResponseWriter, r *http.Request) {
		u, _ := PrincipalFromContext(r.Context())
		id := r.PathValue("organizationID")
		if !canMembers(r, u, id) {
			writeJSON(w, 403, map[string]string{"code": "organization_denied"})
			return
		}
		var in struct {
			organizations.MemberInput
			Username string `json:"username"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			writeOrganizationError(w, organizations.ErrInvalid)
			return
		}
		if in.UserID == "" && in.Username != "" {
			for _, candidate := range d.Auth.ListUsers() {
				if candidate.Username == strings.ToLower(strings.TrimSpace(in.Username)) {
					in.UserID = candidate.ID
					break
				}
			}
		}
		if _, ok := d.Auth.UserByID(in.UserID); !ok {
			writeOrganizationError(w, organizations.ErrInvalid)
			return
		}
		m, e := d.Organizations.SaveMember(id, in.MemberInput, u.ID)
		if e != nil {
			writeOrganizationError(w, e)
			return
		}
		writeJSON(w, 200, m)
	}))
	mux.Handle("GET /api/v1/organizations/{organizationID}/audit", protect(func(w http.ResponseWriter, r *http.Request) {
		u, _ := PrincipalFromContext(r.Context())
		id := r.PathValue("organizationID")
		if !canMembers(r, u, id) {
			writeJSON(w, 403, map[string]string{"code": "organization_denied"})
			return
		}
		offset, e1 := strconv.Atoi(defaultQuery(r, "offset", "0"))
		limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "50"))
		if e1 != nil || e2 != nil || offset < 0 || limit < 1 || limit > 200 {
			writeOrganizationError(w, organizations.ErrInvalid)
			return
		}
		items, total := d.Organizations.Audit(id, offset, limit)
		writeJSON(w, 200, map[string]any{"results": items, "total": total})
	}))
}
func defaultQuery(r *http.Request, key, value string) string {
	if supplied := r.URL.Query().Get(key); supplied != "" {
		return supplied
	}
	return value
}
func registerOrganizationUserRoutes(mux *http.ServeMux, d Dependencies) {
	mux.Handle("GET /api/v1/users", protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _ := PrincipalFromContext(r.Context())
		snapshot := rbac.Union(permissionsForRequest(r, u), effectivePermissions(u, d.GlobalRBAC, d.GlobalGroups))
		if !snapshot.Allows("users.manage") && !snapshot.Allows("groups.manage") && !snapshot.Allows("grants.manage") && !snapshot.Allows("roles.manage") && !snapshot.Allows("organizations.members.manage") && !snapshot.Allows("access_policies.manage") {
			writeJSON(w, 403, map[string]string{"code": "organization_denied"})
			return
		}
		out := []coreauth.User{}
		for _, candidate := range d.Auth.ListUsers() {
			if d.OrganizationAllowed == nil || d.OrganizationAllowed(candidate) {
				out = append(out, candidate)
			}
		}
		writeJSON(w, 200, out)
	}), d.AdminToken, d.Auth))
}
func writeOrganizationError(w http.ResponseWriter, e error) {
	status, code := 503, "organization_unavailable"
	switch {
	case errors.Is(e, organizations.ErrInvalid):
		status, code = 400, "organization_invalid"
	case errors.Is(e, organizations.ErrNotFound):
		status, code = 404, "organization_not_found"
	case errors.Is(e, organizations.ErrConflict):
		status, code = 409, "organization_conflict"
	case errors.Is(e, organizations.ErrProtected):
		status, code = 403, "organization_protected"
	case errors.Is(e, organizations.ErrCapacity):
		status, code = 429, "organization_capacity"
	}
	setNoStore(w)
	writeJSON(w, status, map[string]string{"detail": "organization operation could not be completed", "code": code})
}

// Default-organization groups may already be bound to system roles. A local
// organization administrator cannot edit those memberships to gain system power.
func globalGroupMutationAllowed(w http.ResponseWriter, r *http.Request, id string) bool {
	d := policyDependencies(r)
	if !d.Tenant || d.OrganizationID != organizations.DefaultID || d.GlobalRBAC == nil {
		return true
	}
	for _, b := range d.GlobalRBAC.Bindings() {
		if b.SubjectType == "group" && b.SubjectID == id && len(b.RoleIDs) > 0 {
			u, _ := PrincipalFromContext(r.Context())
			system := effectivePermissions(u, d.GlobalRBAC, d.GlobalGroups)
			if !system.Allows("roles.manage") && !system.Allows("groups.manage") {
				writeJSON(w, 403, map[string]string{"code": "organization_system_group"})
				return false
			}
		}
	}
	return true
}
