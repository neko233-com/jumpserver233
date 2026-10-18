package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/casclient"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/caslogin"
	"github.com/neko233-com/jumpserver233/server/internal/core/logintickets"
)

const casFlowCookie = "jms_cas_flow"
const casPendingCookie = "jms_cas_pending"
const casCookiePath = "/api/v1/authentication/cas"

func casCookie(r *http.Request, name string) string {
	c, e := r.Cookie(name)
	if e != nil || len(c.Value) > 128 {
		return ""
	}
	return c.Value
}
func setCASCookie(w http.ResponseWriter, r *http.Request, d Dependencies, name, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: casCookiePath, HttpOnly: true, Secure: secureSessionCookie(r) || d.CAS.SecureCookies(), SameSite: http.SameSiteLaxMode, MaxAge: age})
}
func registerCASRoutes(mux *http.ServeMux, d Dependencies) {
	protect := func(h http.HandlerFunc) http.Handler { return protectAdminAPI(h, d.AdminToken, d.Auth) }
	attempts := newLoginFailures()
	reserve := func(w http.ResponseWriter, key string) bool {
		if retry, ok := attempts.reserve(key, time.Now()); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			writeJSON(w, 429, map[string]string{"detail": "CAS login attempt limit reached"})
			return false
		}
		return true
	}
	mux.Handle("GET /api/v1/settings/security/cas", protect(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, d.CAS.Snapshot()) }))
	mux.Handle("PUT /api/v1/settings/security/cas", protect(func(w http.ResponseWriter, r *http.Request) {
		var in caslogin.Config
		if decodeRequestJSON(w, r, &in) != nil {
			writeCASError(w, caslogin.ErrInvalid)
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		result, e := d.CAS.Save(in, u.ID, u.Username)
		if e != nil {
			writeCASError(w, e)
			return
		}
		writeJSON(w, 200, result)
	}))
	mux.Handle("GET /api/v1/settings/security/cas/audit", protect(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, d.CAS.Audit()) }))
	mux.Handle("POST /api/v1/settings/security/cas/check", protect(func(w http.ResponseWriter, r *http.Request) {
		if e := d.CAS.Check(r.Context()); e != nil {
			writeCASError(w, e)
			return
		}
		writeJSON(w, 200, map[string]bool{"login_endpoint_available": true})
	}))
	mux.Handle("POST /api/v1/settings/security/cas/users", protect(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Subject  string `json:"subject"`
			Username string `json:"username"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			writeCASError(w, caslogin.ErrInvalid)
			return
		}
		c := d.CAS.Snapshot()
		if c.BaseURL == "" {
			writeCASError(w, caslogin.ErrInvalid)
			return
		}
		u, e := d.Auth.EnsureExternalUser("cas", c.BaseURL, in.Subject, in.Username, true)
		if e != nil {
			writeCASError(w, e)
			return
		}
		writeJSON(w, 201, u)
	}))
	mux.HandleFunc("GET /api/v1/authentication/cas/status", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		writeJSON(w, 200, map[string]bool{"enabled": d.CAS.Snapshot().Enabled && !d.Auth.BootstrapRequired()})
	})
	mux.HandleFunc("GET /api/v1/authentication/cas/start", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		if d.Auth.BootstrapRequired() {
			writeCASError(w, caslogin.ErrDisabled)
			return
		}
		if !reserve(w, "host:"+remoteHost(r.RemoteAddr)) {
			return
		}
		d.CAS.Tickets.Consume(casCookie(r, casPendingCookie))
		setCASCookie(w, r, d, casPendingCookie, "", -1)
		start, e := d.CAS.Begin()
		if e != nil {
			http.Redirect(w, r, d.CAS.ReturnURL("/login?cas_error=1"), 303)
			return
		}
		setCASCookie(w, r, d, casFlowCookie, start.Proof, 600)
		markLoginAudit(r, "started", "")
		http.Redirect(w, r, start.URL, 303)
	})
	mux.HandleFunc("GET /api/v1/authentication/cas/callback", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		w.Header().Set("Referrer-Policy", "no-referrer")
		proof := casCookie(r, casFlowCookie)
		setCASCookie(w, r, d, casFlowCookie, "", -1)
		fail := func() {
			markLoginAudit(r, "failed", "flow_rejected")
			http.Redirect(w, r, d.CAS.ReturnURL("/login?cas_error=1"), 303)
		}
		q := r.URL.Query()
		if len(q["state"]) != 1 || len(q["ticket"]) != 1 {
			fail()
			return
		}
		id, e := d.CAS.Finish(r.Context(), q.Get("state"), proof, q.Get("ticket"))
		if e != nil {
			fail()
			return
		}
		user, e := d.Auth.EnsureExternalUser("cas", id.Issuer, id.Subject, "", id.Provision)
		if e != nil {
			fail()
			return
		}
		ticket, e := d.CAS.NewPending(user.ID, id.Revision, user.AuthGeneration)
		if e != nil {
			fail()
			return
		}
		loginAuditSubject(r, user)
		markLoginAudit(r, "external_verified", "external_identity_verified")
		setCASCookie(w, r, d, casPendingCookie, ticket, 300)
		http.Redirect(w, r, d.CAS.ReturnURL("/login?cas=continue"), 303)
	})
	mux.HandleFunc("GET /api/v1/authentication/cas/pending", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		p, e := d.CAS.Pending(casCookie(r, casPendingCookie), false)
		if e != nil {
			writeCASError(w, e)
			return
		}
		u, ok := d.Auth.UserByID(p.UserID)
		if !ok || u.Source != "cas" {
			writeCASError(w, caslogin.ErrFlow)
			return
		}
		writeJSON(w, 200, map[string]bool{"active": true, "mfa_required": u.MFAEnabled})
	})
	mux.HandleFunc("POST /api/v1/authentication/cas/complete", func(w http.ResponseWriter, r *http.Request) {
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
			writeCASError(w, caslogin.ErrFlow)
			return
		}
		completeExternalBrowserLogin(w, r, d.Auth, d.CAS, "cas", casCookie(r, casPendingCookie), in.OTP, in.SetupToken, attempts, d.CAS.SecureCookies(), func() { setCASCookie(w, r, d, casPendingCookie, "", -1) }, writeCASError)
	})
	mux.HandleFunc("DELETE /api/v1/authentication/cas/pending", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		d.CAS.Tickets.Consume(casCookie(r, casPendingCookie))
		setCASCookie(w, r, d, casPendingCookie, "", -1)
		w.WriteHeader(204)
	})
}
func writeCASError(w http.ResponseWriter, e error) {
	status := 503
	detail := "CAS configuration or provider unavailable"
	switch {
	case errors.Is(e, caslogin.ErrInvalid), errors.Is(e, casclient.ErrConfig):
		status = 400
	case errors.Is(e, caslogin.ErrConflict):
		status = 409
	case errors.Is(e, caslogin.ErrDisabled), errors.Is(e, caslogin.ErrFlow), errors.Is(e, logintickets.ErrTicket), errors.Is(e, coreauth.ErrUserNotFound), errors.Is(e, coreauth.ErrInvalidOTP), errors.Is(e, coreauth.ErrInvalidCredentials), errors.Is(e, coreauth.ErrMFASetupChallenge):
		status = 401
		detail = "CAS login or second factor rejected"
	case errors.Is(e, coreauth.ErrUserExists), errors.Is(e, coreauth.ErrInvalidUsername):
		status = 409
	}
	writeJSON(w, status, map[string]string{"detail": detail})
}
