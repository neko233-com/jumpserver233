package api

import (
	"errors"
	"net/http"

	"github.com/neko233-com/jumpserver233/server/internal/core/sessionpolicy"
)

func registerSessionPolicyRoutes(mux *http.ServeMux, d Dependencies) {
	protect := func(h http.HandlerFunc) http.Handler { return protectAdminAPI(h, d.AdminToken, d.Auth) }
	mux.Handle("GET /api/v1/settings/security/sessions", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		writeJSON(w, 200, d.SessionPolicy.Snapshot())
	}))
	mux.Handle("GET /api/v1/settings/security/sessions/audit", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		writeJSON(w, 200, d.SessionPolicy.Audit())
	}))
	mux.Handle("PUT /api/v1/settings/security/sessions", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		var in sessionpolicy.Settings
		if decodeRequestJSON(w, r, &in) != nil {
			writeJSON(w, 400, map[string]string{"detail": "invalid session security settings"})
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		out, err := d.SessionPolicy.Save(in, u.ID, u.Username)
		if err != nil {
			status := 500
			if errors.Is(err, sessionpolicy.ErrInvalid) {
				status = 400
			}
			if errors.Is(err, sessionpolicy.ErrConflict) {
				status = 409
			}
			writeJSON(w, status, map[string]string{"detail": "session security update failed"})
			return
		}
		writeJSON(w, 200, out)
	}))
}
