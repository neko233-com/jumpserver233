package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/neko233-com/jumpserver233/server/internal/core/identityscope"
	"github.com/neko233-com/jumpserver233/server/internal/core/identitysources"
)

func identitySourceError(w http.ResponseWriter, e error) {
	status, code := 503, "identity_sources_unavailable"
	switch {
	case errors.Is(e, identitysources.ErrInvalid):
		status, code = 400, "identity_sources_invalid"
	case errors.Is(e, identitysources.ErrConflict):
		status, code = 409, "identity_sources_conflict"
	case errors.Is(e, identitysources.ErrNotFound):
		status, code = 404, "identity_sources_not_found"
	case errors.Is(e, identitysources.ErrCapacity):
		status, code = 507, "identity_sources_capacity"
	}
	setNoStore(w)
	writeJSON(w, status, map[string]string{"error_code": code})
}
func registerIdentitySourceRoutes(mux *http.ServeMux, d Dependencies) {
	const base = "/api/v1/identity-sources"
	protect := func(h http.HandlerFunc) http.Handler { return protectAdminAPI(h, d.AdminToken, d.Auth) }
	mux.Handle("GET "+base, protect(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, d.IdentitySources.List()) }))
	mux.Handle("GET "+base+"/audit", protect(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, d.IdentitySources.Audit()) }))
	save := func(w http.ResponseWriter, r *http.Request) {
		var in identitysources.Input
		if decodeRequestJSON(w, r, &in) != nil {
			identitySourceError(w, identitysources.ErrInvalid)
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		value, e := d.IdentitySources.Save(r.PathValue("sourceID"), u.ID, in)
		if e != nil {
			identitySourceError(w, e)
			return
		}
		code := 200
		if r.Method == "POST" {
			code = 201
		}
		writeJSON(w, code, value)
	}
	mux.Handle("POST "+base, protect(save))
	mux.Handle("PUT "+base+"/{sourceID}", protect(save))
	mux.Handle("GET "+base+"/{sourceID}", protect(func(w http.ResponseWriter, r *http.Request) {
		v, _, ok := d.IdentitySources.Get(r.PathValue("sourceID"))
		if !ok {
			identitySourceError(w, identitysources.ErrNotFound)
			return
		}
		writeJSON(w, 200, v)
	}))
	if d.DirectorySync != nil {
		registerDirectorySyncRoutes(mux, d)
	}
	mux.HandleFunc("GET /api/v1/authentication/sources", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		type choice struct {
			ID       string `json:"id"`
			Kind     string `json:"kind"`
			Name     string `json:"name"`
			StartURL string `json:"start_url"`
		}
		out := []choice{}
		if !d.Auth.BootstrapRequired() {
			for _, source := range d.IdentitySources.List() {
				_, runtime, ok := d.IdentitySources.Get(source.ID)
				if ok && runtime.Ready() {
					start := ""
					if source.Kind != "ldap" {
						start = identityscope.Prefix(source.ID) + "/api/v1/authentication/" + source.Kind + "/start"
					}
					out = append(out, choice{source.ID, source.Kind, source.Name, start})
				}
			}
		}
		writeJSON(w, 200, out)
	})
	// Cache one mux (and its attempt limiter) per immutable source runtime.
	var mu sync.Mutex
	children := map[string]*http.ServeMux{}
	mux.Handle(base+"/{sourceID}/{rest...}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		id, path := identityScopedPath(r.URL.Path)
		source, runtime, ok := d.IdentitySources.Get(id)
		if !ok || r.URL.RawPath != "" {
			http.NotFound(w, r)
			return
		}
		public := strings.HasPrefix(path, "/api/v1/authentication/")
		if public {
			providerBase := "/api/v1/authentication/" + source.Kind + "/"
			if !strings.HasPrefix(path, providerBase) {
				http.NotFound(w, r)
				return
			}
			if path == providerBase+"status" && r.Method == "GET" {
				if !allowOrigin(w, r) {
					return
				}
				writeJSON(w, 200, map[string]bool{"enabled": runtime.Ready() && !d.Auth.BootstrapRequired()})
				return
			}
			metadata := source.Kind == "saml" && path == providerBase+"metadata" && r.Method == "GET" && !source.Archived
			if !runtime.Ready() && !metadata {
				http.NotFound(w, r)
				return
			}
		} else if !strings.HasPrefix(path, "/api/v1/settings/security/"+source.Kind) {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		child := children[id]
		if child == nil {
			child = http.NewServeMux()
			scoped := d
			scoped.LDAP = runtime.LDAP
			scoped.OIDC = runtime.OIDC
			scoped.CAS = runtime.CAS
			scoped.SAML = runtime.SAML
			switch source.Kind {
			case "ldap":
				registerLDAPRoutes(child, scoped)
			case "oidc":
				registerOIDCRoutes(child, scoped)
			case "cas":
				registerCASRoutes(child, scoped)
			case "saml":
				registerSAMLRoutes(child, scoped)
			}
			children[id] = child
		}
		mu.Unlock()
		next := withExternalSource(r, id, runtime)
		next = next.WithContext(context.WithValue(next.Context(), identityOriginalURIKey{}, r.URL.RequestURI()))
		u := *r.URL
		u.Path = path
		u.RawPath = ""
		next.URL = &u
		child.ServeHTTP(w, next)
	}))
}
