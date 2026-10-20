package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/neko233-com/jumpserver233/server/internal/core/announcements"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
)

func announcementError(w http.ResponseWriter, e error) {
	status, code := 503, "announcements_unavailable"
	switch {
	case errors.Is(e, announcements.ErrInvalid):
		status, code = 400, "announcements_invalid"
	case errors.Is(e, announcements.ErrNotFound):
		status, code = 404, "announcements_not_found"
	case errors.Is(e, announcements.ErrConflict):
		status, code = 409, "announcements_conflict"
	case errors.Is(e, announcements.ErrCapacity):
		status, code = 507, "announcements_capacity"
	}
	setNoStore(w)
	writeJSON(w, status, map[string]string{"error_code": code})
}
func registerAnnouncementRoutes(mux *http.ServeMux, d Dependencies) {
	if d.Announcements == nil {
		return
	}
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	manager := func(w http.ResponseWriter, r *http.Request) (coreauth.User, bool) {
		u, _ := PrincipalFromContext(r.Context())
		if !globalLoginPermissions(d, u).Allows("announcements.manage") {
			writeJSON(w, 403, map[string]string{"error_code": "permission_denied"})
			return u, false
		}
		return u, true
	}
	page := func(w http.ResponseWriter, r *http.Request) (int, int, bool) {
		offset, e := strconv.Atoi(defaultQuery(r, "offset", "0"))
		limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "20"))
		if e != nil || e2 != nil || offset < 0 || limit < 1 || limit > 100 {
			announcementError(w, announcements.ErrInvalid)
			return 0, 0, false
		}
		return offset, limit, true
	}
	mux.Handle("GET /api/v1/announcements", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		u, _ := PrincipalFromContext(r.Context())
		manage := r.URL.Query().Get("manage") == "true"
		if manage {
			if _, ok := manager(w, r); !ok {
				return
			}
		}
		offset, limit, ok := page(w, r)
		if !ok {
			return
		}
		rows, total, unread, e := d.Announcements.Page(u.ID, manage, offset, limit)
		if e != nil {
			announcementError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": total, "unread": unread})
	}))
	mux.Handle("GET /api/v1/announcements/permissions", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		u, _ := PrincipalFromContext(r.Context())
		writeJSON(w, 200, map[string]bool{"manage": globalLoginPermissions(d, u).Allows("announcements.manage")})
	}))
	mux.Handle("GET /api/v1/announcements/audit", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if _, ok := manager(w, r); !ok {
			return
		}
		offset, limit, ok := page(w, r)
		if !ok {
			return
		}
		rows, total, e := d.Announcements.Audit(offset, limit)
		if e != nil {
			announcementError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": total})
	}))
	save := func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		u, ok := manager(w, r)
		if !ok {
			return
		}
		var in announcements.Input
		if decodeRequestJSON(w, r, &in) != nil {
			announcementError(w, announcements.ErrInvalid)
			return
		}
		n, e := d.Announcements.Save(r.PathValue("noticeID"), u.ID, in)
		if e != nil {
			announcementError(w, e)
			return
		}
		status := 200
		if r.Method == "POST" {
			status = 201
		}
		writeJSON(w, status, n)
	}
	mux.Handle("POST /api/v1/announcements", protect(save))
	mux.Handle("PUT /api/v1/announcements/{noticeID}", protect(save))
	mux.Handle("DELETE /api/v1/announcements/{noticeID}", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		u, ok := manager(w, r)
		if !ok {
			return
		}
		var in struct {
			Revision  int    `json:"revision"`
			RequestID string `json:"request_id"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			announcementError(w, announcements.ErrInvalid)
			return
		}
		if e := d.Announcements.Delete(r.PathValue("noticeID"), u.ID, in.Revision, in.RequestID); e != nil {
			announcementError(w, e)
			return
		}
		w.WriteHeader(204)
	}))
	mux.Handle("POST /api/v1/announcements/{noticeID}/read", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		u, _ := PrincipalFromContext(r.Context())
		var in struct {
			Revision int `json:"revision"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			announcementError(w, announcements.ErrInvalid)
			return
		}
		reading, e := d.Announcements.Acknowledge(r.PathValue("noticeID"), u.ID, in.Revision)
		if e != nil {
			announcementError(w, e)
			return
		}
		writeJSON(w, 200, reading)
	}))
}
