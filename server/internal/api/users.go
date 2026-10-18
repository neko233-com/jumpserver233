package api

import (
	"errors"
	"net/http"
	"strconv"

	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
)

func lockUserLifecycle(d Dependencies) func() {
	global := d.GlobalAccessMu
	if global != nil && global != d.AccessMu {
		global.Lock()
	}
	d.AccessMu.Lock()
	return func() {
		d.AccessMu.Unlock()
		if global != nil && global != d.AccessMu {
			global.Unlock()
		}
	}
}
func userError(w http.ResponseWriter, e error) {
	setNoStore(w)
	status, code := 503, "user_unavailable"
	switch {
	case errors.Is(e, coreauth.ErrUserNotFound):
		status, code = 404, "user_not_found"
	case errors.Is(e, coreauth.ErrUserRevision):
		status, code = 409, "user_revision"
	case errors.Is(e, coreauth.ErrUserSelf):
		status, code = 409, "user_self"
	case errors.Is(e, coreauth.ErrLastAdministrator):
		status, code = 409, "user_last_admin"
	case errors.Is(e, coreauth.ErrUserAdmin):
		status, code = 403, "user_admin"
	case errors.Is(e, coreauth.ErrInvalidCredentials):
		status, code = 401, "user_session"
	case errors.Is(e, coreauth.ErrUserState), errors.Is(e, coreauth.ErrInvalidRole), errors.Is(e, coreauth.ErrExternalIdentity):
		status, code = 400, "user_invalid"
	}
	writeJSON(w, status, map[string]string{"error_code": code})
}
func registerUserLifecycle(mux *http.ServeMux, d Dependencies) {
	protect := func(h http.HandlerFunc) http.Handler { return protectAdminAPI(h, d.AdminToken, d.Auth) }
	page := func(r *http.Request) (int, int, error) {
		offset, e := strconv.Atoi(defaultQuery(r, "offset", "0"))
		limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "25"))
		if e != nil || e2 != nil {
			return 0, 0, coreauth.ErrUserState
		}
		return offset, limit, nil
	}
	mux.Handle("GET /api/v1/users/management", protect(func(w http.ResponseWriter, r *http.Request) {
		offset, limit, e := page(r)
		if e != nil {
			userError(w, e)
			return
		}
		rows, total, e := d.Auth.ManagedUsers(defaultQuery(r, "scope", "current"), r.URL.Query().Get("q"), offset, limit)
		if e != nil {
			userError(w, e)
			return
		}
		setNoStore(w)
		writeJSON(w, 200, map[string]any{"results": rows, "total": total})
	}))
	mux.Handle("GET /api/v1/users/audit", protect(func(w http.ResponseWriter, r *http.Request) {
		offset, limit, e := page(r)
		if e != nil {
			userError(w, e)
			return
		}
		rows, total, e := d.Auth.UserAudit(r.URL.Query().Get("user_id"), offset, limit)
		if e != nil {
			userError(w, e)
			return
		}
		setNoStore(w)
		writeJSON(w, 200, map[string]any{"results": rows, "total": total})
	}))
	mux.Handle("GET /api/v1/users/{userID}", protect(func(w http.ResponseWriter, r *http.Request) {
		row, e := d.Auth.ManagedUser(r.PathValue("userID"))
		if e != nil {
			userError(w, e)
			return
		}
		setNoStore(w)
		writeJSON(w, 200, row)
	}))
	change := func(w http.ResponseWriter, r *http.Request, in []coreauth.UserChange) {
		release := lockUserLifecycle(d)
		defer release()
		actor, _ := PrincipalFromContext(r.Context())
		if !hasPermission(r, "users.manage") {
			userError(w, coreauth.ErrUserAdmin)
			return
		}
		canManage := hasPermission(r, "roles.manage")
		rows, e := d.Auth.ChangeUsers(in, coreauth.UserActor{ID: actor.ID, Name: actor.Username, AuthGeneration: actor.AuthGeneration, ManageAdministrators: canManage})
		if e != nil {
			userError(w, e)
			return
		}
		setNoStore(w)
		writeJSON(w, 200, map[string]any{"results": rows})
	}
	mux.Handle("PUT /api/v1/users/{userID}", protect(func(w http.ResponseWriter, r *http.Request) {
		var in coreauth.UserUpdate
		if decodeRequestJSON(w, r, &in) != nil {
			userError(w, coreauth.ErrUserState)
			return
		}
		change(w, r, []coreauth.UserChange{{ID: r.PathValue("userID"), Action: "update", UserUpdate: in}})
	}))
	mux.Handle("DELETE /api/v1/users/{userID}", protect(func(w http.ResponseWriter, r *http.Request) {
		revision, e := strconv.Atoi(r.URL.Query().Get("revision"))
		if e != nil {
			userError(w, coreauth.ErrUserState)
			return
		}
		change(w, r, []coreauth.UserChange{{ID: r.PathValue("userID"), Action: "archive", UserUpdate: coreauth.UserUpdate{Revision: revision}}})
	}))
	for _, action := range []string{"restore", "revoke"} {
		mux.Handle("POST /api/v1/users/{userID}/"+action, protect(func(w http.ResponseWriter, r *http.Request) {
			var in struct {
				Revision int `json:"revision"`
			}
			if decodeRequestJSON(w, r, &in) != nil {
				userError(w, coreauth.ErrUserState)
				return
			}
			change(w, r, []coreauth.UserChange{{ID: r.PathValue("userID"), Action: action, UserUpdate: coreauth.UserUpdate{Revision: in.Revision}}})
		}))
	}
	mux.Handle("POST /api/v1/users/actions", protect(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Changes []coreauth.UserChange `json:"changes"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			userError(w, coreauth.ErrUserState)
			return
		}
		change(w, r, in.Changes)
	}))
}
