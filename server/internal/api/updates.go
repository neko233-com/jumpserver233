package api

import (
	"errors"
	"net/http"

	"github.com/neko233-com/jumpserver233/server/internal/core/updates"
)

func updateError(w http.ResponseWriter, e error) {
	status, code := 503, updates.ErrorCode(e)
	switch {
	case errors.Is(e, updates.ErrInvalid):
		status, code = 400, "invalid"
	case errors.Is(e, updates.ErrConflict):
		status, code = 409, "conflict"
	case errors.Is(e, updates.ErrBusy):
		status, code = 409, "busy"
	case errors.Is(e, updates.ErrLimited):
		status = 429
		w.Header().Set("Retry-After", "60")
	case errors.Is(e, updates.ErrFeed), errors.Is(e, updates.ErrNetwork):
		status = 502
	}
	writeJSON(w, status, map[string]string{"error_code": code})
}
func registerUpdateRoutes(mux *http.ServeMux, d Dependencies) {
	if d.Tenant || d.Updates == nil || d.Auth == nil {
		return
	}
	protect := func(fn http.HandlerFunc) http.Handler { return protectAdminAPI(fn, d.AdminToken, d.Auth) }
	const path = "/api/v1/settings/security/updates"
	mux.Handle("GET "+path, protect(func(w http.ResponseWriter, r *http.Request) { setNoStore(w); writeJSON(w, 200, d.Updates.Snapshot()) }))
	mux.Handle("GET "+path+"/audit", protect(func(w http.ResponseWriter, r *http.Request) { setNoStore(w); writeJSON(w, 200, d.Updates.Audit()) }))
	mux.Handle("PUT "+path, protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		var in updates.Settings
		if decodeRequestJSON(w, r, &in) != nil {
			updateError(w, updates.ErrInvalid)
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		if _, e := d.Updates.Save(in, u.ID, u.Username); e != nil {
			updateError(w, e)
			return
		}
		writeJSON(w, 200, d.Updates.Snapshot())
	}))
	mux.Handle("POST "+path+"/check", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		var in struct {
			Revision  int    `json:"revision"`
			RequestID string `json:"request_id"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			updateError(w, updates.ErrInvalid)
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		if _, e := d.Updates.Check(r.Context(), in.Revision, in.RequestID, u.ID, u.Username); e != nil {
			updateError(w, e)
			return
		}
		writeJSON(w, 200, d.Updates.Snapshot())
	}))
}
