package api

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strconv"
	"time"

	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/oidclogin"
)

const oidcCookiePath = "/api/v1/authentication/oidc"
const oidcFlowCookie = "jms_oidc_flow"
const oidcPendingCookie = "jms_oidc_pending"

func oidcCookieValue(r *http.Request, name string) string {
	if cookie, err := r.Cookie(name); err == nil && len(cookie.Value) <= 128 {
		return cookie.Value
	}
	return ""
}
func setOIDCCookie(w http.ResponseWriter, r *http.Request, d Dependencies, name, value string, expires time.Time) {
	maxAge := int(time.Until(expires).Seconds())
	if value == "" {
		maxAge = -1
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: oidcCookiePath, HttpOnly: true, Secure: secureSessionCookie(r) || d.OIDC.SecureCookies(), SameSite: http.SameSiteLaxMode, MaxAge: maxAge, Expires: expires})
}
func registerOIDCRoutes(mux *http.ServeMux, d Dependencies) {
	protect := func(h http.HandlerFunc) http.Handler { return protectAdminAPI(h, d.AdminToken, d.Auth) }
	attempts := newLoginFailures()
	mux.Handle("GET /api/v1/settings/security/oidc", protect(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, d.OIDC.Snapshot()) }))
	mux.Handle("PUT /api/v1/settings/security/oidc", protect(func(w http.ResponseWriter, r *http.Request) {
		var in oidclogin.Input
		if decodeRequestJSON(w, r, &in) != nil {
			writeOIDCError(w, oidclogin.ErrInvalid)
			return
		}
		user, _ := PrincipalFromContext(r.Context())
		snapshot, err := d.OIDC.Save(in, user.ID, user.Username)
		if err != nil {
			writeOIDCError(w, err)
			return
		}
		writeJSON(w, 200, snapshot)
	}))
	mux.Handle("POST /api/v1/settings/security/oidc/check", protect(func(w http.ResponseWriter, r *http.Request) {
		if err := d.OIDC.Check(r.Context()); err != nil {
			writeOIDCError(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"discovery_available": true})
	}))
	mux.Handle("GET /api/v1/settings/security/oidc/audit", protect(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, d.OIDC.Audit()) }))
	mux.Handle("POST /api/v1/settings/security/oidc/users", protect(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Subject  string `json:"subject"`
			Username string `json:"username"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			writeOIDCError(w, oidclogin.ErrInvalid)
			return
		}
		config := d.OIDC.Snapshot()
		user, err := d.Auth.EnsureOIDCUser(config.Issuer, in.Subject, in.Username, true)
		if err != nil {
			writeOIDCError(w, err)
			return
		}
		writeJSON(w, 201, user)
	}))
	mux.HandleFunc("GET /api/v1/authentication/oidc/status", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		writeJSON(w, 200, map[string]bool{"enabled": d.OIDC.Snapshot().Enabled && !d.Auth.BootstrapRequired()})
	})
	mux.HandleFunc("GET /api/v1/authentication/oidc/start", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		if d.Auth.BootstrapRequired() {
			writeOIDCError(w, oidclogin.ErrDisabled)
			return
		}
		if retry, ok := attempts.reserve(remoteHost(r.RemoteAddr), time.Now()); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			writeJSON(w, 429, map[string]string{"detail": "login attempt limit reached"})
			return
		}
		d.OIDC.ConsumePending(oidcCookieValue(r, oidcPendingCookie))
		setOIDCCookie(w, r, d, oidcPendingCookie, "", time.Unix(1, 0))
		start, err := d.OIDC.Begin(r.Context())
		if err != nil {
			http.Redirect(w, r, d.OIDC.ReturnURL("/login?sso_error=1"), http.StatusSeeOther)
			return
		}
		setOIDCCookie(w, r, d, oidcFlowCookie, start.Proof, start.Expires)
		markLoginAudit(r, "started", "")
		http.Redirect(w, r, start.URL, http.StatusSeeOther)
	})
	mux.HandleFunc("GET /api/v1/authentication/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		w.Header().Set("Referrer-Policy", "no-referrer")
		proof := oidcCookieValue(r, oidcFlowCookie)
		setOIDCCookie(w, r, d, oidcFlowCookie, "", time.Unix(1, 0))
		fail := func() {
			markLoginAudit(r, "failed", "flow_rejected")
			http.Redirect(w, r, d.OIDC.ReturnURL("/login?sso_error=1"), http.StatusSeeOther)
		}
		if r.URL.Query().Get("error") != "" {
			fail()
			return
		}
		identity, err := d.OIDC.Finish(r.Context(), r.URL.Query().Get("state"), proof, r.URL.Query().Get("code"))
		if err != nil {
			fail()
			return
		}
		user, err := d.Auth.EnsureOIDCUser(identity.Issuer, identity.Subject, "", identity.Provision)
		if err != nil {
			fail()
			return
		}
		ticket, err := d.OIDC.NewPending(user.ID, identity.Revision, user.AuthGeneration)
		if err != nil {
			fail()
			return
		}
		loginAuditSubject(r, user)
		markLoginAudit(r, "external_verified", "external_identity_verified")
		setOIDCCookie(w, r, d, oidcPendingCookie, ticket, time.Now().Add(5*time.Minute))
		http.Redirect(w, r, d.OIDC.ReturnURL("/login?sso=continue"), http.StatusSeeOther)
	})
	mux.HandleFunc("GET /api/v1/authentication/oidc/pending", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		p, err := d.OIDC.Pending(oidcCookieValue(r, oidcPendingCookie), false)
		if err != nil {
			writeOIDCError(w, err)
			return
		}
		user, ok := d.Auth.ActiveUserByID(p.UserID)
		if !ok || user.AuthGeneration != p.AuthGeneration || user.Source != "oidc" {
			writeOIDCError(w, oidclogin.ErrFlow)
			return
		}
		writeJSON(w, 200, map[string]bool{"active": true, "mfa_required": user.MFAEnabled})
	})
	mux.HandleFunc("POST /api/v1/authentication/oidc/complete", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		ticket := oidcCookieValue(r, oidcPendingCookie)
		p, err := d.OIDC.Pending(ticket, true)
		if err != nil {
			writeOIDCError(w, err)
			return
		}
		u, active := d.Auth.ActiveUserByID(p.UserID)
		if !active || u.AuthGeneration != p.AuthGeneration {
			writeOIDCError(w, oidclogin.ErrFlow)
			return
		}
		attemptKey := "oidc-user:" + p.UserID
		if u, ok := d.Auth.UserByID(p.UserID); ok {
			loginAuditSubject(r, u)
		}
		if retry, ok := attempts.reserve(attemptKey, time.Now()); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			writeJSON(w, 429, map[string]string{"detail": "SSO second-factor attempt limit reached"})
			return
		}
		var input struct {
			OTP        string `json:"otp"`
			SetupToken string `json:"setup_token"`
		}
		if decodeRequestJSON(w, r, &input) != nil {
			writeOIDCError(w, oidclogin.ErrFlow)
			return
		}
		var session coreauth.LoginSession
		if input.SetupToken != "" {
			if p.SetupToken == "" || subtle.ConstantTimeCompare([]byte(input.SetupToken), []byte(p.SetupToken)) != 1 {
				attempts.failed(attemptKey, time.Now())
				writeOIDCError(w, oidclogin.ErrFlow)
				return
			}
			session, err = d.Auth.ConfirmMFASetupChallenge(input.SetupToken, input.OTP, p.UserID)
		} else {
			var setup *coreauth.MFASetupChallenge
			session, setup, err = d.Auth.AuthenticateExternalUser(p.UserID, "oidc", input.OTP, p.AuthGeneration)
			if err == nil && setup != nil {
				markLoginAudit(r, "challenge", "enrollment_required")
				if d.OIDC.SetSetup(ticket, setup.Token) != nil {
					writeOIDCError(w, oidclogin.ErrFlow)
					return
				}
				writeJSON(w, 401, map[string]any{"mfa_setup_required": true, "setup_token": setup.Token, "enrollment": setup.Enrollment})
				return
			}
		}
		if err != nil {
			if errors.Is(err, coreauth.ErrOTPRequired) {
				markLoginAudit(r, "challenge", "second_factor_required")
				writeJSON(w, 401, map[string]bool{"mfa_required": true})
				return
			}
			if errors.Is(err, coreauth.ErrInvalidOTP) || errors.Is(err, coreauth.ErrInvalidCredentials) || errors.Is(err, coreauth.ErrMFASetupChallenge) {
				attempts.failed(attemptKey, time.Now())
			}
			writeOIDCError(w, err)
			return
		}
		if session.User.ID != p.UserID || session.User.AuthGeneration != p.AuthGeneration || !d.OIDC.ConsumePending(ticket) {
			_ = d.Auth.RevokeToken(session.AccessToken)
			writeOIDCError(w, oidclogin.ErrFlow)
			return
		}
		setOIDCCookie(w, r, d, oidcPendingCookie, "", time.Unix(1, 0))
		attempts.succeeded(attemptKey)
		if !setLoginSession(w, r, session, d.OIDC.SecureCookies()) {
			return
		}
		writeJSON(w, 200, map[string]any{"browser_session": true, "user": session.User, "expires_at": session.ExpiresAt})
	})
	mux.HandleFunc("DELETE /api/v1/authentication/oidc/pending", func(w http.ResponseWriter, r *http.Request) {
		if !allowOrigin(w, r) {
			return
		}
		d.OIDC.ConsumePending(oidcCookieValue(r, oidcPendingCookie))
		setOIDCCookie(w, r, d, oidcPendingCookie, "", time.Unix(1, 0))
		w.WriteHeader(204)
	})
}
func writeOIDCError(w http.ResponseWriter, err error) {
	status := 503
	detail := "OIDC configuration or provider is unavailable"
	switch {
	case errors.Is(err, oidclogin.ErrInvalid):
		status = 400
		detail = "invalid OIDC settings"
	case errors.Is(err, oidclogin.ErrConflict):
		status = 409
		detail = "OIDC settings changed"
	case errors.Is(err, oidclogin.ErrFlow), errors.Is(err, coreauth.ErrInvalidCredentials), errors.Is(err, coreauth.ErrInvalidOTP), errors.Is(err, coreauth.ErrMFASetupChallenge):
		status = 401
		detail = "SSO login or second factor is invalid or expired"
	case errors.Is(err, coreauth.ErrUserExists), errors.Is(err, coreauth.ErrInvalidUsername):
		status = 409
		detail = "external username is unavailable"
	}
	writeJSON(w, status, map[string]string{"detail": detail})
}
