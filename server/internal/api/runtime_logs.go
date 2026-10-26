package api

import (
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/runtimelog"
	"net/http"
)

const runtimeLogsPath = "/api/v1/settings/security/runtime-logs"

func registerRuntimeLogRoutes(mux *http.ServeMux, d Dependencies) {
	if d.Tenant || d.Auth == nil {
		return
	}
	protect := func(h http.HandlerFunc) http.Handler { return protectAdminAPI(h, d.AdminToken, d.Auth) }
	mux.Handle("GET "+runtimeLogsPath, protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if d.RuntimeLogs == nil {
			writeJSON(w, 200, map[string]bool{"enabled": false})
			return
		}
		writeJSON(w, 200, map[string]any{"enabled": true, "status": d.RuntimeLogs.Snapshot()})
	}))
	mux.Handle("POST "+runtimeLogsPath+"/rotate", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if d.RuntimeLogs == nil {
			writeJSON(w, 409, map[string]string{"error_code": "unsupported"})
			return
		}
		var in runtimelog.Input
		if decodeRequestJSON(w, r, &in) != nil {
			writeJSON(w, 400, map[string]string{"error_code": "invalid"})
			return
		}
		out, err := d.RuntimeLogs.Rotate(in)
		if err != nil {
			status, code := 503, "log_io_failed"
			if errors.Is(err, runtimelog.ErrConflict) {
				status, code = 409, "conflict"
			}
			if errors.Is(err, runtimelog.ErrInvalid) {
				status, code = 400, "invalid"
			}
			writeJSON(w, status, map[string]string{"error_code": code})
			return
		}
		writeJSON(w, 200, map[string]any{"enabled": true, "status": out})
	}))
}
