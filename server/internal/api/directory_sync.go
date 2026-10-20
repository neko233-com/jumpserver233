package api

import (
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/connector/ldapclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/directorysync"
	"net/http"
	"strconv"
)

func directorySyncError(w http.ResponseWriter, e error) {
	status, code := 503, "directory_sync_unavailable"
	switch {
	case errors.Is(e, directorysync.ErrInvalid), errors.Is(e, ldapclient.ErrConfig):
		status, code = 400, "directory_sync_invalid"
	case errors.Is(e, directorysync.ErrConflict):
		status, code = 409, "directory_sync_conflict"
	case errors.Is(e, directorysync.ErrPending):
		status, code = 409, "directory_sync_pending"
	case errors.Is(e, directorysync.ErrCapacity):
		status, code = 507, "directory_sync_capacity"
	case errors.Is(e, ldapclient.ErrIncomplete):
		status, code = 422, "directory_sync_incomplete"
	}
	writeJSON(w, status, map[string]string{"error_code": code})
}
func syncPage[T any](w http.ResponseWriter, r *http.Request, rows []T) {
	offset, e := strconv.Atoi(r.URL.Query().Get("offset"))
	if e != nil {
		offset = 0
	}
	limit, e := strconv.Atoi(r.URL.Query().Get("limit"))
	if e != nil || limit < 1 {
		limit = 100
	}
	offset = min(max(0, offset), len(rows))
	end := min(len(rows), offset+min(limit, 200))
	items := rows[offset:end]
	if items == nil {
		items = []T{}
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": len(rows)})
}
func registerDirectorySyncRoutes(mux *http.ServeMux, d Dependencies) {
	base := "/api/v1/identity-sources/{sourceID}/sync"
	protect := func(h http.HandlerFunc, write bool) http.Handler {
		return protectAdminAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			source, _, ok := d.IdentitySources.Get(r.PathValue("sourceID"))
			if !ok || source.Kind != "ldap" {
				http.NotFound(w, r)
				return
			}
			if write && (!hasPermission(r, "groups.manage") || !hasPermission(r, "roles.manage") || !hasPermission(r, "organizations.manage")) {
				writeJSON(w, 403, map[string]string{"error_code": "permission_denied"})
				return
			}
			h(w, r)
		}), d.AdminToken, d.Auth)
	}
	mux.Handle("GET "+base, protect(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, d.DirectorySync.Config(r.PathValue("sourceID")))
	}, false))
	mux.Handle("PUT "+base, protect(func(w http.ResponseWriter, r *http.Request) {
		var in directorysync.ConfigInput
		if decodeRequestJSON(w, r, &in) != nil {
			directorySyncError(w, directorysync.ErrInvalid)
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		out, e := d.DirectorySync.SaveConfig(r.PathValue("sourceID"), u.ID, in)
		if e != nil {
			directorySyncError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}, true))
	mux.Handle("GET "+base+"/entries", protect(func(w http.ResponseWriter, r *http.Request) {
		syncPage(w, r, d.DirectorySync.Entries(r.PathValue("sourceID")))
	}, false))
	mux.Handle("GET "+base+"/runs", protect(func(w http.ResponseWriter, r *http.Request) {
		syncPage(w, r, d.DirectorySync.Runs(r.PathValue("sourceID")))
	}, false))
	mux.Handle("GET "+base+"/audit", protect(func(w http.ResponseWriter, r *http.Request) {
		syncPage(w, r, d.DirectorySync.Audit(r.PathValue("sourceID")))
	}, false))
	for _, action := range []string{"preview", "apply", "abort"} {
		mux.Handle("POST "+base+"/"+action, protect(func(w http.ResponseWriter, r *http.Request) {
			var in directorysync.Operation
			if decodeRequestJSON(w, r, &in) != nil {
				directorySyncError(w, directorysync.ErrInvalid)
				return
			}
			u, _ := PrincipalFromContext(r.Context())
			source := r.PathValue("sourceID")
			var out any
			var e error
			switch action {
			case "preview":
				out, e = d.DirectorySync.Preview(r.Context(), source, u.ID, in)
			case "apply":
				out, e = d.DirectorySync.Apply(r.Context(), source, u.ID, in)
			case "abort":
				out, e = d.DirectorySync.Abort(r.Context(), source, u.ID, in)
			}
			if e != nil {
				directorySyncError(w, e)
				return
			}
			writeJSON(w, 200, out)
		}, true))
	}
}
