package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/ldapclient"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/ldaplogin"
	"github.com/neko233-com/jumpserver233/server/internal/core/logintickets"
)

const ldapPendingCookie = "jms_ldap_pending"
const ldapCookiePath = "/api/v1/authentication/ldap"

func ldapCookie(r *http.Request) string {
	c, e := r.Cookie(ldapPendingCookie)
	if e != nil || len(c.Value) > 400 {
		return ""
	}
	return externalReadFlowCookie(r, ldapPendingCookie, c.Value)
}
func setLDAPCookie(w http.ResponseWriter, r *http.Request, value string) {
	age := 300
	if value == "" {
		age = -1
	}
	http.SetCookie(w, &http.Cookie{Name: ldapPendingCookie, Value: externalSetFlowCookie(r, ldapPendingCookie, value), Path: externalCookiePath(r, ldapCookiePath), HttpOnly: true, Secure: secureSessionCookie(r), SameSite: http.SameSiteLaxMode, MaxAge: age})
}
func registerLDAPRoutes(mux *http.ServeMux, d Dependencies) {
	protect := func(h http.HandlerFunc) http.Handler { return protectAdminAPI(h, d.AdminToken, d.Auth) }
	attempts := newLoginFailures()
	reserve := func(w http.ResponseWriter, key string) bool {
		if retry, ok := attempts.reserve(key, time.Now()); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			writeJSON(w, 429, map[string]string{"detail": "directory sign-in attempt limit reached"})
			return false
		}
		return true
	}
	mux.Handle("GET /api/v1/settings/security/ldap", protect(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, d.LDAP.Snapshot()) }))
	mux.Handle("PUT /api/v1/settings/security/ldap", protect(func(w http.ResponseWriter, r *http.Request) {
		var in ldaplogin.Input
		if decodeRequestJSON(w, r, &in) != nil {
			writeLDAPError(w, ldaplogin.ErrInvalid)
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		result, e := d.LDAP.Save(in, u.ID, u.Username)
		if e != nil {
			writeLDAPError(w, e)
			return
		}
		writeJSON(w, 200, result)
	}))
	mux.Handle("GET /api/v1/settings/security/ldap/audit", protect(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, d.LDAP.Audit()) }))
	mux.Handle("POST /api/v1/settings/security/ldap/check", protect(func(w http.ResponseWriter, r *http.Request) {
		if e := d.LDAP.Check(r.Context()); e != nil {
			writeLDAPError(w, e)
			return
		}
		writeJSON(w, 200, map[string]bool{"bind_available": true})
	}))
	mux.Handle("POST /api/v1/settings/security/ldap/users", protect(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			DirectoryUsername string `json:"directory_username"`
			Username          string `json:"username"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			writeLDAPError(w, ldaplogin.ErrInvalid)
			return
		}
		id, e := d.LDAP.Lookup(r.Context(), in.DirectoryUsername)
		if e != nil {
			writeLDAPError(w, e)
			return
		}
		user, e := ensureExternalForRequest(r, d.Auth, "ldap", id.Issuer, id.Subject, in.Username, true)
		if e != nil {
			writeLDAPError(w, e)
			return
		}
		writeJSON(w, 201, user)
	}))
	mux.HandleFunc("GET /api/v1/authentication/ldap/status", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		writeJSON(w, 200, map[string]bool{"enabled": d.LDAP.Snapshot().Enabled && !d.Auth.BootstrapRequired()})
	})
	complete := func(w http.ResponseWriter, r *http.Request, ticket, otp, setupToken string) {
		completeExternalBrowserLogin(w, r, d.Auth, d.LDAP, "ldap", ticket, otp, setupToken, attempts, false, func() { setLDAPCookie(w, r, "") }, writeLDAPError)
	}
	mux.HandleFunc("POST /api/v1/authentication/ldap/login", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		host := "host:" + remoteHost(r.RemoteAddr)
		if !reserve(w, host) {
			return
		}
		var in struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			writeLDAPError(w, ldaplogin.ErrInvalid)
			return
		}
		sum := sha256.Sum256([]byte(strings.ToLower(in.Username)))
		attemptedLoginName(r, in.Username)
		key := "name:" + hex.EncodeToString(sum[:])
		if !reserve(w, key) {
			return
		}
		d.LDAP.Tickets.Consume(ldapCookie(r))
		setLDAPCookie(w, r, "")
		id, e := d.LDAP.Authenticate(r.Context(), in.Username, in.Password)
		in.Password = ""
		if e != nil {
			if errors.Is(e, ldapclient.ErrCredentials) {
				attempts.failed(host, time.Now())
				attempts.failed(key, time.Now())
			}
			writeLDAPError(w, e)
			return
		}
		user, e := ensureExternalForRequest(r, d.Auth, "ldap", id.Issuer, id.Subject, "", id.Provision)
		if e != nil {
			writeLDAPError(w, e)
			return
		}
		ticket, e := d.LDAP.NewPending(user.ID, id.Revision, user.AuthGeneration)
		if e != nil {
			writeLDAPError(w, e)
			return
		}
		attempts.succeeded(host)
		attempts.succeeded(key)
		setLDAPCookie(w, r, ticket)
		complete(w, r, ticket, "", "")
	})
	mux.HandleFunc("POST /api/v1/authentication/ldap/complete", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		if !reserve(w, "host:"+remoteHost(r.RemoteAddr)) {
			return
		}
		var in struct {
			OTP        string `json:"otp"`
			SetupToken string `json:"setup_token"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			writeLDAPError(w, ldaplogin.ErrInvalid)
			return
		}
		complete(w, r, ldapCookie(r), in.OTP, in.SetupToken)
	})
	mux.HandleFunc("DELETE /api/v1/authentication/ldap/pending", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		d.LDAP.Tickets.Consume(ldapCookie(r))
		setLDAPCookie(w, r, "")
		w.WriteHeader(204)
	})
}
func writeLDAPError(w http.ResponseWriter, e error) {
	status := 503
	detail := "directory authentication or configuration unavailable"
	switch {
	case errors.Is(e, ldaplogin.ErrConflict):
		status = 409
	case errors.Is(e, ldaplogin.ErrInvalid), errors.Is(e, ldapclient.ErrConfig):
		status = 400
	case errors.Is(e, ldapclient.ErrCredentials), errors.Is(e, coreauth.ErrInvalidCredentials), errors.Is(e, coreauth.ErrInvalidOTP), errors.Is(e, coreauth.ErrUserNotFound), errors.Is(e, logintickets.ErrTicket), errors.Is(e, coreauth.ErrMFASetupChallenge), errors.Is(e, ldaplogin.ErrDisabled):
		status = 401
		detail = "directory identity or second factor rejected"
	case errors.Is(e, coreauth.ErrUserExists), errors.Is(e, coreauth.ErrInvalidUsername):
		status = 409
	}
	writeJSON(w, status, map[string]string{"detail": detail})
}
