package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/branding"
)

func brandingError(w http.ResponseWriter, err error) {
	status, code := 503, "branding_unavailable"
	switch {
	case errors.Is(err, branding.ErrInvalid):
		status, code = 400, "branding_invalid"
	case errors.Is(err, branding.ErrImage):
		status, code = 400, "branding_image_invalid"
	case errors.Is(err, branding.ErrContrast):
		status, code = 400, "branding_contrast"
	case errors.Is(err, branding.ErrConflict):
		status, code = 409, "branding_conflict"
	}
	setNoStore(w)
	writeJSON(w, status, map[string]string{"error_code": code})
}
func brandingPrincipal(w http.ResponseWriter, r *http.Request, d Dependencies) (coreauth.User, bool) {
	u, status := resolvePrincipal(r, d.AdminToken, d.Auth)
	if status != 200 {
		writeJSON(w, 401, map[string]string{"error_code": "authentication_required"})
		return u, false
	}
	if !permissionsForRequest(r, u).Allows("branding.manage") {
		writeJSON(w, 403, map[string]string{"error_code": "permission_denied"})
		return u, false
	}
	return u, enforceLoginPolicy(w, r, u)
}
func cacheMatch(r *http.Request, etag string) bool {
	for _, candidate := range strings.Split(r.Header.Get("If-None-Match"), ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || strings.TrimPrefix(candidate, "W/") == etag {
			return true
		}
	}
	return false
}
func registerBrandingRoutes(mux *http.ServeMux, d Dependencies) {
	mux.HandleFunc("GET /api/v1/branding", func(w http.ResponseWriter, r *http.Request) {
		out := branding.Defaults().Public()
		if d.Branding != nil {
			if e := d.Branding.Refresh(); e != nil {
				brandingError(w, e)
				return
			}
			out = d.Branding.Snapshot()
		}
		body, _ := json.Marshal(out)
		digest := sha256.Sum256(body)
		etag := "\"" + hex.EncodeToString(digest[:]) + "\""
		w.Header().Set("Cache-Control", "public, no-cache")
		w.Header().Set("ETag", etag)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if cacheMatch(r, etag) {
			w.WriteHeader(304)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	mux.HandleFunc("GET /api/v1/branding/images/{digest}", func(w http.ResponseWriter, r *http.Request) {
		if d.Branding == nil {
			http.NotFound(w, r)
			return
		}
		digest := r.PathValue("digest")
		if e := d.Branding.Refresh(); e != nil {
			brandingError(w, e)
			return
		}
		data, ok := d.Branding.Image(digest)
		if !ok {
			setNoStore(w)
			http.NotFound(w, r)
			return
		}
		etag := "\"" + digest + "\""
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
		if cacheMatch(r, etag) {
			w.WriteHeader(304)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		_, _ = w.Write(data)
	})
	if d.Tenant || d.Auth == nil {
		return
	}
	protect := func(h http.HandlerFunc) http.Handler { return protectAdminAPI(h, d.AdminToken, d.Auth) }
	read := func(h http.HandlerFunc) http.Handler {
		return protect(func(w http.ResponseWriter, r *http.Request) {
			setNoStore(w)
			d.AccessMu.RLock()
			defer d.AccessMu.RUnlock()
			if _, ok := brandingPrincipal(w, r, d); !ok {
				return
			}
			if d.Branding == nil {
				brandingError(w, errors.New("unavailable"))
				return
			}
			if e := d.Branding.Refresh(); e != nil {
				brandingError(w, e)
				return
			}
			h(w, r)
		})
	}
	mux.Handle("GET /api/v1/settings/branding", read(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"settings": d.Branding.Snapshot(), "themes": branding.Themes()})
	}))
	mux.Handle("GET /api/v1/settings/branding/audit", read(func(w http.ResponseWriter, r *http.Request) {
		offset, e1 := strconv.Atoi(defaultQuery(r, "offset", "0"))
		limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "25"))
		if e1 != nil || e2 != nil {
			brandingError(w, branding.ErrInvalid)
			return
		}
		rows, total, e := d.Branding.Audit(offset, limit)
		if e != nil {
			brandingError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": total})
	}))
	mux.Handle("POST /api/v1/settings/branding/prepare-image", read(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Kind string `json:"kind"`
			Data []byte `json:"data"`
		}
		if decodeRequestJSONLimit(w, r, &in, (3<<20)+8192) != nil || in.Kind != "logo" && in.Kind != "icon" && in.Kind != "mark" && in.Kind != "login_image" || len(in.Data) == 0 {
			brandingError(w, branding.ErrImage)
			return
		}
		var data []byte
		var e error
		if in.Kind == "login_image" {
			data, e = branding.PrepareLoginImage(in.Data)
		} else {
			data, e = branding.PrepareImage(in.Data, in.Kind == "icon" || in.Kind == "mark")
		}
		if e != nil {
			brandingError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"data": data})
	}))
	mux.Handle("PUT /api/v1/settings/branding", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		var in branding.Input
		if decodeRequestJSONLimit(w, r, &in, (6<<20)+8192) != nil {
			brandingError(w, branding.ErrInvalid)
			return
		}
		release := lockUserLifecycle(d)
		defer release()
		u, ok := brandingPrincipal(w, r, d)
		if !ok {
			return
		}
		if d.Branding == nil {
			brandingError(w, errors.New("unavailable"))
			return
		}
		out, e := d.Branding.Save(in, u.ID, u.Username)
		if e != nil {
			brandingError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
}
