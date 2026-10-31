package api

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/passwordvault"
)

// The vault accepts direct TLS or a loopback-only connection, such as an SSH
// tunnel. Forwarded headers alone do not establish transport confidentiality.
func vaultSecureTransport(r *http.Request, d Dependencies) bool {
	if r.TLS != nil {
		return true
	}
	if additionalHTTPSRequest(r) {
		return true
	}
	public, err := url.Parse(d.PublicURL)
	peerHost, _, peerErr := net.SplitHostPort(r.RemoteAddr)
	peer, ipErr := netip.ParseAddr(peerHost)
	if err == nil && public.Scheme == "https" && strings.EqualFold(public.Host, r.Host) && peerErr == nil && ipErr == nil && len(r.Header.Values("X-Forwarded-Proto")) == 1 && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		for _, raw := range d.TrustedProxies {
			if prefix, e := netip.ParsePrefix(raw); e == nil && prefix.Contains(peer.Unmap()) {
				return true
			}
		}
	}
	return vaultLocalDirect(r)
}
func vaultLocalDirect(r *http.Request) bool {
	host, _, e := net.SplitHostPort(r.Host)
	if e != nil {
		host = r.Host
	}
	host = strings.Trim(host, "[]")
	return isLoopbackRemote(r.RemoteAddr) && (host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()) && r.Header.Get("Forwarded") == "" && r.Header.Get("X-Forwarded-For") == "" && r.Header.Get("X-Forwarded-Proto") == ""
}
func vaultError(w http.ResponseWriter, e error) {
	status, code := http.StatusInternalServerError, "vault_unavailable"
	switch {
	case errors.Is(e, passwordvault.ErrInvalid):
		status, code = 400, "vault_invalid"
	case errors.Is(e, passwordvault.ErrNotFound):
		status, code = 404, "vault_not_found"
	case errors.Is(e, passwordvault.ErrDenied):
		status, code = 403, "vault_denied"
	case errors.Is(e, passwordvault.ErrConflict):
		status, code = 409, "vault_conflict"
	}
	writeJSON(w, status, map[string]string{"error_code": code})
}
func registerPasswordVaultRoutes(mux *http.ServeMux, d Dependencies, mu *sync.RWMutex) {
	if d.PasswordVault == nil || d.Auth == nil {
		return
	}
	type handler func(http.ResponseWriter, *http.Request, coreauth.User)
	protect := func(browserOnly bool, f handler) http.Handler {
		return protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !vaultSecureTransport(r, d) {
				writeJSON(w, 403, map[string]string{"error_code": "vault_secure_transport_required"})
				return
			}
			if browserOnly && (r.Header.Get("Authorization") != "" || !browserLoginRequest(r)) {
				vaultError(w, passwordvault.ErrDenied)
				return
			}
			var release func()
			var e error
			if d.Maintenance != nil {
				release, e = d.Maintenance.Gate().Acquire("password-vault")
				if e != nil {
					writeJSON(w, 503, map[string]string{"error_code": "service_draining"})
					return
				}
				defer release()
			}
			if d.GlobalAccessMu != nil && d.GlobalAccessMu != mu {
				d.GlobalAccessMu.RLock()
				defer d.GlobalAccessMu.RUnlock()
			}
			mu.RLock()
			defer mu.RUnlock()
			u, _ := PrincipalFromContext(r.Context())
			current, status := resolvePrincipal(r, d.AdminToken, d.Auth)
			if status != http.StatusOK || current.ID != u.ID || current.AuthGeneration != u.AuthGeneration {
				vaultError(w, passwordvault.ErrDenied)
				return
			}
			fresh, _, ok := notificationActor(r.Context(), d, u.ID)
			if !ok || fresh.AuthGeneration != current.AuthGeneration {
				vaultError(w, passwordvault.ErrDenied)
				return
			}
			f(w, r, fresh)
		}), d.AdminToken, d.Auth)
	}
	mux.Handle("GET /api/v1/password-vault/items", protect(true, func(w http.ResponseWriter, r *http.Request, u coreauth.User) {
		writeJSON(w, 200, map[string]any{"results": d.PasswordVault.List(u.ID)})
	}))
	mux.Handle("POST /api/v1/password-vault/items", protect(false, func(w http.ResponseWriter, r *http.Request, u coreauth.User) {
		var in struct {
			Kind      string `json:"kind"`
			Title     string `json:"title"`
			Site      string `json:"site"`
			Username  string `json:"username"`
			Shared    bool   `json:"shared"`
			Password  string `json:"password"`
			RequestID string `json:"request_id"`
			OwnerID   string `json:"owner_id,omitempty"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			vaultError(w, passwordvault.ErrInvalid)
			return
		}
		owner := u.ID
		if in.OwnerID != "" {
			if u.ID != "admin-token" || !vaultLocalDirect(r) {
				vaultError(w, passwordvault.ErrDenied)
				return
			}
			candidate, ok := d.Auth.ActiveUserByID(in.OwnerID)
			if !ok || d.OrganizationAllowed != nil && !d.OrganizationAllowed(candidate) {
				vaultError(w, passwordvault.ErrDenied)
				return
			}
			owner = candidate.ID
		}
		item, e := d.PasswordVault.CreateFor(u.ID, owner, in.RequestID, passwordvault.Item{Kind: in.Kind, Title: in.Title, Site: in.Site, Username: in.Username, Shared: in.Shared}, in.Password)
		if e != nil {
			vaultError(w, e)
			return
		}
		writeJSON(w, 201, item)
	}))
	mux.Handle("PUT /api/v1/password-vault/items/{id}", protect(true, func(w http.ResponseWriter, r *http.Request, u coreauth.User) {
		var in struct {
			Kind     string `json:"kind"`
			Title    string `json:"title"`
			Site     string `json:"site"`
			Username string `json:"username"`
			Shared   bool   `json:"shared"`
			Password string `json:"password"`
			Revision int    `json:"revision"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			vaultError(w, passwordvault.ErrInvalid)
			return
		}
		item, e := d.PasswordVault.Put(u.ID, passwordvault.Item{ID: r.PathValue("id"), Kind: in.Kind, Title: in.Title, Site: in.Site, Username: in.Username, Shared: in.Shared, Revision: in.Revision}, in.Password)
		if e != nil {
			vaultError(w, e)
			return
		}
		writeJSON(w, 200, item)
	}))
	mux.Handle("POST /api/v1/password-vault/items/{id}/reveal", protect(true, func(w http.ResponseWriter, r *http.Request, u coreauth.User) {
		item, secret, e := d.PasswordVault.Reveal(u.ID, r.PathValue("id"))
		if e != nil {
			vaultError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"item": item, "password": secret})
	}))
	mux.Handle("DELETE /api/v1/password-vault/items/{id}", protect(true, func(w http.ResponseWriter, r *http.Request, u coreauth.User) {
		var in struct {
			Revision int `json:"revision"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			vaultError(w, passwordvault.ErrInvalid)
			return
		}
		if e := d.PasswordVault.Delete(u.ID, r.PathValue("id"), in.Revision); e != nil {
			vaultError(w, e)
			return
		}
		w.WriteHeader(204)
	}))
	mux.Handle("GET /api/v1/password-vault/grants", protect(true, func(w http.ResponseWriter, r *http.Request, u coreauth.User) {
		writeJSON(w, 200, map[string]any{"results": d.PasswordVault.GrantsFor(u.ID)})
	}))
	mux.Handle("POST /api/v1/password-vault/items/{id}/grant", protect(true, func(w http.ResponseWriter, r *http.Request, u coreauth.User) {
		var in struct {
			RequestID string `json:"request_id"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			vaultError(w, passwordvault.ErrInvalid)
			return
		}
		id, token, e := d.PasswordVault.Grant(u.ID, r.PathValue("id"), in.RequestID, 10*time.Minute)
		if e != nil {
			vaultError(w, e)
			return
		}
		writeJSON(w, 201, map[string]string{"grant_id": id, "token": token})
	}))
	mux.Handle("DELETE /api/v1/password-vault/grants/{id}", protect(true, func(w http.ResponseWriter, r *http.Request, u coreauth.User) {
		if e := d.PasswordVault.Revoke(u.ID, r.PathValue("id")); e != nil {
			vaultError(w, e)
			return
		}
		w.WriteHeader(204)
	}))
	mux.Handle("POST /api/v1/password-vault/grants/{id}/consume", protect(false, func(w http.ResponseWriter, r *http.Request, u coreauth.User) {
		var in struct {
			Token string `json:"token"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			vaultError(w, passwordvault.ErrInvalid)
			return
		}
		item, secret, e := d.PasswordVault.Consume(u.ID, r.PathValue("id"), in.Token)
		if e != nil {
			vaultError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"item": item, "password": secret})
	}))
	mux.Handle("GET /api/v1/password-vault/audit", protect(true, func(w http.ResponseWriter, r *http.Request, u coreauth.User) {
		writeJSON(w, 200, map[string]any{"results": d.PasswordVault.AuditFor(u.ID)})
	}))
}
