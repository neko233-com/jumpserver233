package api

import (
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/servicemaintenance"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
	"net/http"
	"strings"
)

const maintenancePath = "/api/v1/settings/security/maintenance"

func registerMaintenanceRoutes(mux *http.ServeMux, d Dependencies) {
	if d.Tenant || d.Maintenance == nil || d.Auth == nil {
		return
	}
	protect := func(h http.HandlerFunc) http.Handler { return protectAdminAPI(h, d.AdminToken, d.Auth) }
	mux.Handle("GET "+maintenancePath, protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		writeJSON(w, 200, d.Maintenance.Snapshot())
	}))
	mux.Handle("POST "+maintenancePath+"/stop", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		var in servicemaintenance.Input
		if decodeRequestJSON(w, r, &in) != nil {
			writeJSON(w, 400, map[string]string{"error_code": "invalid"})
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		out, stop, e := d.Maintenance.Stop(in, u.ID, u.Username)
		if e != nil {
			code, status := "unavailable", 503
			if errors.Is(e, servicemaintenance.ErrInvalid) {
				code, status = "invalid", 400
			}
			if errors.Is(e, servicemaintenance.ErrConflict) {
				code, status = "conflict", 409
			}
			if errors.Is(e, servicemaintenance.ErrUnsupported) {
				code, status = "unsupported", 409
			}
			writeJSON(w, status, map[string]string{"error_code": code})
			return
		}
		writeJSON(w, 200, out)
		_ = http.NewResponseController(w).Flush()
		stop()
	}))
	mux.Handle("PUT "+maintenancePath, protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		var input struct {
			Instance  string `json:"instance"`
			Revision  int    `json:"revision"`
			RequestID string `json:"request_id"`
			Draining  *bool  `json:"draining"`
		}
		if decodeRequestJSON(w, r, &input) != nil || input.Draining == nil {
			writeJSON(w, 400, map[string]string{"error_code": "invalid"})
			return
		}
		in := servicemaintenance.Input{Instance: input.Instance, Revision: input.Revision, RequestID: input.RequestID, Draining: *input.Draining}
		u, _ := PrincipalFromContext(r.Context())
		out, e := d.Maintenance.Change(in, u.ID, u.Username)
		if e != nil {
			status, code := 503, "unavailable"
			switch {
			case errors.Is(e, servicemaintenance.ErrInvalid):
				status, code = 400, "invalid"
			case errors.Is(e, servicemaintenance.ErrConflict):
				status, code = 409, "conflict"
			case errors.Is(e, servicemaintenance.ErrUnsupported):
				status, code = 409, "unsupported"
			}
			writeJSON(w, status, map[string]string{"error_code": code})
			return
		}
		writeJSON(w, 200, out)
	}))
}

func maintenanceExempt(r *http.Request) bool {
	p := r.URL.Path
	if p == maintenancePath || p == maintenancePath+"/stop" || p == "/api/v1/settings/security/updates/installation/cancel" && r.Method == http.MethodPost || strings.HasPrefix(p, "/api/v1/authentication/") || strings.HasPrefix(p, "/api/v1/login-reviews") {
		return true
	}
	// Cancellation and session interruption remain available during draining.
	if r.Method == http.MethodPost && strings.HasSuffix(p, "/cancel") {
		for _, prefix := range []string{"/api/v1/ops/runs/", "/api/v1/database-queries/", "/api/v1/accounts/rotation-runs/", "/api/v1/asset-discovery/runs/"} {
			if strings.HasPrefix(p, prefix) {
				return true
			}
		}
		if strings.HasPrefix(p, "/api/v1/assets/") && strings.HasSuffix(p, "/ssh-key-rotation/cancel") {
			return true
		}
	}
	return r.Method == http.MethodDelete && (strings.HasPrefix(p, "/api/v1/sessions/") || strings.HasPrefix(p, "/api/v1/ops/jobs/") || p == "/api/v1/database-sessions" || strings.HasPrefix(p, "/api/v1/desktop-sessions/") || strings.HasSuffix(p, "/files/session"))
}

func withMaintenance(next http.Handler, c *servicemaintenance.Controller) http.Handler {
	if c == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if workgate.FromContext(r.Context()) == c.Gate() {
			next.ServeHTTP(w, r)
			return
		}
		ctx := workgate.WithGate(r.Context(), c.Gate())
		r = r.WithContext(ctx)
		operational := strings.HasPrefix(r.URL.Path, "/ws/") || strings.HasPrefix(r.URL.Path, "/api/") && r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS"
		if !operational || maintenanceExempt(r) {
			next.ServeHTTP(w, r)
			return
		}
		ctx, release, e := c.Gate().Enter(ctx, "http_requests")
		if e != nil {
			setNoStore(w)
			w.Header().Set("Retry-After", "1")
			writeJSON(w, 503, map[string]string{"error_code": "service_draining"})
			return
		}
		defer release()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
