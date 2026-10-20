package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"net/http"
	"strconv"
	"time"
)

const passwordCookie = "jms_password_change"
const passwordPath = "/api/v1/authentication/password-change"

type passwordBrowserKey struct{}

func passwordBrowserContext(r *http.Request, browser bool) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), passwordBrowserKey{}, browser))
}
func passwordError(w http.ResponseWriter, e error) {
	status, code := 503, "password_unavailable"
	switch {
	case errors.Is(e, coreauth.ErrPasswordHistory):
		status, code = 400, "password_history"
	case errors.Is(e, coreauth.ErrPasswordUnchanged):
		status, code = 400, "password_unchanged"
	case errors.Is(e, coreauth.ErrPasswordPolicy), errors.Is(e, coreauth.ErrInvalidPassword):
		status, code = 400, "password_policy"
	case errors.Is(e, coreauth.ErrPasswordChallenge):
		status, code = 401, "password_change_invalid"
	case errors.Is(e, coreauth.ErrCredentialPermission):
		status, code = 403, "password_permission"
	default:
		userError(w, e)
		return
	}
	setNoStore(w)
	writeJSON(w, status, map[string]string{"error_code": code})
}
func passwordTicket(r *http.Request, body string) (string, error) {
	cookie := ""
	if c, e := r.Cookie(passwordCookie); e == nil {
		cookie = c.Value
	}
	if cookie != "" && body != "" && subtle.ConstantTimeCompare([]byte(cookie), []byte(body)) != 1 {
		return "", coreauth.ErrPasswordChallenge
	}
	if body != "" {
		return body, nil
	}
	return cookie, nil
}
func setPasswordCookie(w http.ResponseWriter, r *http.Request, token string, expires time.Time, secure bool) {
	age := max(1, int(time.Until(expires).Seconds()))
	if token == "" {
		age = -1
		expires = time.Unix(1, 0)
	}
	http.SetCookie(w, &http.Cookie{Name: passwordCookie, Value: token, Path: passwordPath, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: secure || secureSessionCookie(r), Expires: expires, MaxAge: age})
}
func preparePasswordChange(w http.ResponseWriter, r *http.Request, session coreauth.LoginSession, secure bool) bool {
	d := policyDependencies(r)
	if d.Auth == nil || !d.Auth.PasswordChangeRequired(session.User.ID) {
		return true
	}
	challenge, e := d.Auth.BeginPasswordChange(session.AccessToken, accesspolicies.SourceIP(r.Context()))
	if e != nil {
		_ = d.Auth.RevokeToken(session.AccessToken)
		passwordError(w, e)
		return false
	}
	setExpiredSessionCookie(w, r)
	clearReviewCookie(w, r)
	setPasswordCookie(w, r, challenge.Token, challenge.ExpiresAt, secure)
	markLoginAudit(r, "challenge", "password_change_required")
	result := map[string]any{"password_change_required": true, "expires_at": challenge.ExpiresAt}
	browser := browserLoginRequest(r)
	if value, ok := r.Context().Value(passwordBrowserKey{}).(bool); ok {
		browser = value
	}
	if !browser {
		result["change_token"] = challenge.Token
	}
	writeJSON(w, 202, result)
	return false
}
func passwordPendingForRequest(d Dependencies, r *http.Request, token string) (coreauth.PasswordChallenge, error) {
	p, e := d.Auth.PasswordChangePending(token, accesspolicies.SourceIP(r.Context()))
	if e != nil {
		return p, e
	}
	if !radiusProofCurrent(d, p.Proof, p.User) || !smsProofCurrent(d, p.Proof, p.User) {
		return p, coreauth.ErrPasswordChallenge
	}
	decision, e := checkAccessPolicies(d, p.User, coreassets.Asset{}, accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context())}, true)
	if e != nil || !decision.Allowed {
		return p, coreauth.ErrPasswordChallenge
	}
	return p, nil
}
func passwordActor(r *http.Request) coreauth.UserActor {
	u, _ := PrincipalFromContext(r.Context())
	return coreauth.UserActor{ID: u.ID, Name: u.Username, AuthGeneration: u.AuthGeneration, ManageAdministrators: hasPermission(r, "roles.manage"), ManageCredentials: hasPermission(r, "users.credentials.manage")}
}
func registerPasswordSecurity(mux *http.ServeMux, d Dependencies) {
	protect := func(h http.HandlerFunc) http.Handler { return protectAdminAPI(h, d.AdminToken, d.Auth) }
	mux.Handle("GET /api/v1/settings/security/passwords", protect(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, d.Auth.PasswordPolicy()) }))
	mux.Handle("GET /api/v1/settings/security/passwords/audit", protect(func(w http.ResponseWriter, r *http.Request) {
		offset, e := strconv.Atoi(defaultQuery(r, "offset", "0"))
		limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "25"))
		if e != nil || e2 != nil {
			passwordError(w, coreauth.ErrUserState)
			return
		}
		rows, total, e := d.Auth.PasswordPolicyAudit(offset, limit)
		if e != nil {
			passwordError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": total})
	}))
	mux.Handle("PUT /api/v1/settings/security/passwords", protect(func(w http.ResponseWriter, r *http.Request) {
		var in coreauth.PasswordPolicy
		if decodeRequestJSON(w, r, &in) != nil {
			passwordError(w, coreauth.ErrPasswordPolicy)
			return
		}
		release := lockUserLifecycle(d)
		defer release()
		if !hasPermission(r, "security.manage") {
			passwordError(w, coreauth.ErrCredentialPermission)
			return
		}
		out, e := d.Auth.SavePasswordPolicy(in, passwordActor(r))
		if e != nil {
			passwordError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	for _, kind := range []string{"password", "mfa"} {
		mux.Handle("POST /api/v1/users/{userID}/"+kind+"/reset", protect(func(w http.ResponseWriter, r *http.Request) {
			var in struct {
				Revision int    `json:"revision"`
				Password string `json:"new_password"`
				Force    *bool  `json:"force_change"`
			}
			if decodeRequestJSON(w, r, &in) != nil || kind == "mfa" && (in.Password != "" || in.Force != nil) {
				passwordError(w, coreauth.ErrUserState)
				return
			}
			force := kind == "password"
			if in.Force != nil {
				force = *in.Force
			}
			release := lockUserLifecycle(d)
			defer release()
			if !hasPermission(r, "users.manage") || !hasPermission(r, "users.credentials.manage") {
				passwordError(w, coreauth.ErrCredentialPermission)
				return
			}
			row, e := d.Auth.ResetCredentials(r.PathValue("userID"), in.Revision, kind+"_reset", in.Password, force, passwordActor(r))
			if e != nil {
				passwordError(w, e)
				return
			}
			writeJSON(w, 200, row)
		}))
	}
	mux.HandleFunc("GET /api/v1/authentication/password-policy", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		writeJSON(w, 200, d.Auth.PasswordPolicy())
	})
	limiter := newLoginFailures()
	pending := func(w http.ResponseWriter, r *http.Request, token string) {
		p, e := passwordPendingForRequest(d, r, token)
		if e != nil {
			passwordError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"active": true, "password_change_required": true, "user": p.User, "expires_at": p.ExpiresAt, "policy": p.Policy})
	}
	mux.HandleFunc("GET "+passwordPath+"/pending", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		token, e := passwordTicket(r, "")
		if e != nil {
			passwordError(w, e)
			return
		}
		pending(w, r, token)
	})
	mux.HandleFunc("POST "+passwordPath+"/pending", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		var in struct {
			Token string `json:"change_token"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			passwordError(w, coreauth.ErrPasswordChallenge)
			return
		}
		token, e := passwordTicket(r, in.Token)
		if e != nil {
			passwordError(w, e)
			return
		}
		pending(w, r, token)
	})
	for _, action := range []string{"complete", "cancel"} {
		mux.HandleFunc("POST "+passwordPath+"/"+action, func(w http.ResponseWriter, r *http.Request) {
			setNoStore(w)
			if !allowOrigin(w, r) {
				return
			}
			host := remoteHost(r.RemoteAddr)
			if retry, ok := limiter.reserve(host, time.Now()); !ok {
				w.Header().Set("Retry-After", strconv.Itoa(retry))
				writeJSON(w, 429, map[string]string{"error_code": "password_rate_limit"})
				return
			}
			var in struct {
				Token    string `json:"change_token"`
				Password string `json:"new_password"`
			}
			if decodeRequestJSON(w, r, &in) != nil || action == "cancel" && in.Password != "" {
				passwordError(w, coreauth.ErrPasswordChallenge)
				return
			}
			token, e := passwordTicket(r, in.Token)
			if e != nil {
				passwordError(w, e)
				return
			}
			release := lockCalendarAccess(d, d.AccessMu)
			defer release()
			p, e := passwordPendingForRequest(d, r, token)
			if e == nil {
				loginAuditSubject(r, p.User)
				if action == "cancel" {
					e = d.Auth.CancelPasswordChange(token, accesspolicies.SourceIP(r.Context()))
				} else {
					e = d.Auth.CompletePasswordChange(token, accesspolicies.SourceIP(r.Context()), in.Password)
				}
			}
			if e != nil {
				if errors.Is(e, coreauth.ErrPasswordChallenge) {
					limiter.failed(host, time.Now())
				}
				passwordError(w, e)
				return
			}
			limiter.succeeded(host)
			setPasswordCookie(w, r, "", time.Time{}, false)
			setExpiredSessionCookie(w, r)
			writeJSON(w, 200, map[string]bool{"password_changed": action == "complete", "cancelled": action == "cancel"})
		})
	}
}
