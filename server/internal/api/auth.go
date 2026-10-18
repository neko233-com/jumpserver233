package api

import (
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
)

const (
	sessionCookieName    = "jms_sessionid"
	browserSessionHeader = "X-JMS-Browser-Session"
	loginFailureLimit    = 5
	loginFailureWindow   = 15 * time.Minute
	loginAttemptLimit    = 30
	loginAttemptWindow   = time.Minute
)

type loginFailures struct {
	mu       sync.Mutex
	byHost   map[string][]time.Time
	attempts map[string][]time.Time
	maxKeys  int
}

func newLoginFailures() *loginFailures {
	return &loginFailures{byHost: make(map[string][]time.Time), attempts: make(map[string][]time.Time), maxKeys: 4096}
}

func (l *loginFailures) reserve(host string, now time.Time) (int, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)
	_, hasFailures := l.byHost[host]
	_, hasAttempts := l.attempts[host]
	if !hasFailures && !hasAttempts && len(l.byHost)+len(l.attempts) >= l.maxKeys {
		return int(loginAttemptWindow / time.Second), false
	}
	if failures := l.byHost[host]; len(failures) >= loginFailureLimit {
		return retrySeconds(failures[0].Add(loginFailureWindow), now), false
	} else if attempts := l.attempts[host]; len(attempts) >= loginAttemptLimit {
		return retrySeconds(attempts[0].Add(loginAttemptWindow), now), false
	}
	l.attempts[host] = append(l.attempts[host], now)
	return 0, true
}

func retrySeconds(deadline, now time.Time) int {
	remaining := deadline.Sub(now)
	seconds := int((remaining + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

func (l *loginFailures) failed(host string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)
	if _, exists := l.byHost[host]; !exists && len(l.byHost)+len(l.attempts) >= l.maxKeys {
		return
	}
	l.byHost[host] = append(l.byHost[host], now)
}

func (l *loginFailures) succeeded(host string) {
	l.mu.Lock()
	delete(l.byHost, host)
	l.mu.Unlock()
}

func (l *loginFailures) pruneLocked(now time.Time) {
	for host, timestamps := range l.byHost {
		valid := timestamps[:0]
		for _, timestamp := range timestamps {
			if now.Sub(timestamp) < loginFailureWindow {
				valid = append(valid, timestamp)
			}
		}
		if len(valid) == 0 {
			delete(l.byHost, host)
		} else {
			l.byHost[host] = valid
		}
	}
	for host, timestamps := range l.attempts {
		valid := timestamps[:0]
		for _, timestamp := range timestamps {
			if now.Sub(timestamp) < loginAttemptWindow {
				valid = append(valid, timestamp)
			}
		}
		if len(valid) == 0 {
			delete(l.attempts, host)
		} else {
			l.attempts[host] = valid
		}
	}
}

func registerAuthRoutes(mux *http.ServeMux, service *coreauth.Service, adminToken string) {
	failures := newLoginFailures()
	mux.HandleFunc("GET /api/v1/authentication/status", func(w http.ResponseWriter, r *http.Request) {
		if !allowOrigin(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"bootstrap_required": service.BootstrapRequired()})
	})
	mux.Handle("GET /api/v1/settings/security/mfa", protectAdminAPI(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		setNoStore(w)
		writeJSON(w, http.StatusOK, service.MFAEnforcementSettings())
	}), adminToken, service))
	mux.Handle("PUT /api/v1/settings/security/mfa", protectAdminAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input coreauth.MFAEnforcementSettings
		if err := decodeRequestJSON(w, r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid MFA policy"})
			return
		}
		settings, err := service.SetMFAEnforcement(input.Mode)
		if err != nil {
			writeMFAError(w, err)
			return
		}
		setNoStore(w)
		writeJSON(w, http.StatusOK, settings)
	}), adminToken, service))
	mux.HandleFunc("POST /api/v1/authentication/auth/", func(w http.ResponseWriter, r *http.Request) {
		if !allowOrigin(w, r) {
			return
		}
		setNoStore(w)
		host := remoteHost(r.RemoteAddr)
		now := time.Now()
		if retryAfter, allowed := failures.reserve(host, now); !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"detail": "too many failed sign-in attempts"})
			return
		}
		var input struct {
			Username string `json:"username"`
			Password string `json:"password"`
			OTP      string `json:"otp,omitempty"`
		}
		if err := decodeRequestJSON(w, r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid sign-in request"})
			return
		}
		attemptedLoginName(r, input.Username)
		session, setup, err := service.AuthenticateWithOTPOrMFASetup(input.Username, input.Password, input.OTP)
		if setup != nil {
			markLoginAudit(r, "challenge", "enrollment_required")
			failures.succeeded(host)
			setNoStore(w)
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"detail":             "MFA setup required",
				"mfa_setup_required": true,
				"setup_token":        setup.Token,
				"enrollment":         setup.Enrollment,
			})
			return
		}
		if errors.Is(err, coreauth.ErrOTPRequired) {
			markLoginAudit(r, "challenge", "second_factor_required")
			failures.succeeded(host)
			setNoStore(w)
			writeJSON(w, http.StatusUnauthorized, map[string]any{"detail": "one-time code required", "mfa_required": true})
			return
		}
		if errors.Is(err, coreauth.ErrInvalidCredentials) {
			markLoginAudit(r, "failed", "credentials_rejected")
			failures.failed(host, now)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "invalid username or password"})
			return
		}
		if err != nil {
			if errors.Is(err, coreauth.ErrAuthenticationBusy) || errors.Is(err, coreauth.ErrSessionLimit) {
				w.Header().Set("Retry-After", "1")
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"detail": "authentication service is busy"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "sign-in failed"})
			return
		}
		failures.succeeded(host)
		writeLoginResult(w, r, http.StatusOK, session)
	})
	mux.HandleFunc("POST /api/v1/authentication/mfa/setup/confirm", func(w http.ResponseWriter, r *http.Request) {
		if !allowOrigin(w, r) {
			return
		}
		setNoStore(w)
		host := remoteHost(r.RemoteAddr)
		now := time.Now()
		if retryAfter, allowed := failures.reserve(host, now); !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"detail": "too many failed MFA setup attempts"})
			return
		}
		var input struct {
			SetupToken string `json:"setup_token"`
			OTP        string `json:"otp"`
		}
		if err := decodeRequestJSON(w, r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid MFA setup confirmation"})
			return
		}
		session, err := service.ConfirmMFASetupChallenge(input.SetupToken, input.OTP)
		if err != nil {
			if errors.Is(err, coreauth.ErrInvalidOTP) || errors.Is(err, coreauth.ErrMFASetupChallenge) || errors.Is(err, coreauth.ErrMFAEnrollmentExpired) {
				failures.failed(host, now)
			}
			if errors.Is(err, coreauth.ErrMFASetupChallenge) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "MFA setup challenge is invalid or expired"})
				return
			}
			writeMFAError(w, err)
			return
		}
		failures.succeeded(host)
		writeLoginResult(w, r, http.StatusOK, session)
	})
	mux.HandleFunc("POST /api/v1/authentication/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		if !allowOrigin(w, r) {
			return
		}
		if !canBootstrap(r, adminToken) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "local access or administrator token required"})
			return
		}
		var input struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := decodeRequestJSON(w, r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid administrator setup request"})
			return
		}
		if _, err := service.Bootstrap(input.Username, input.Password); err != nil {
			writeAuthError(w, err)
			return
		}
		session, err := service.Authenticate(input.Username, input.Password)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "administrator setup succeeded but sign-in failed"})
			return
		}
		writeLoginResult(w, r, http.StatusCreated, session)
	})
	mux.HandleFunc("POST /api/v1/authentication/expire-session/", func(w http.ResponseWriter, r *http.Request) {
		if !allowOrigin(w, r) {
			return
		}
		setNoStore(w)
		token, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			if cookie, err := r.Cookie(sessionCookieName); err == nil {
				token, ok = cookie.Value, true
			}
		}
		if ok {
			if u, valid := service.ValidateToken(token); valid {
				loginAuditSubject(r, u)
			}
			if err := service.RevokeToken(token); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "could not revoke login session"})
				return
			}
		}
		setExpiredSessionCookie(w, r)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /api/v1/authentication/session/", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		token, hasAuthorization := bearerToken(r.Header.Get("Authorization"))
		if !hasAuthorization {
			if r.Header.Get("Authorization") != "" {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "authentication required"})
				return
			}
			cookie, err := r.Cookie(sessionCookieName)
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "authentication required"})
				return
			}
			token = cookie.Value
		}
		user, valid := service.ValidateToken(token)
		if !valid {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "authentication required"})
			return
		}
		if !enforceLoginPolicy(w, r, user) {
			return
		}
		writeJSON(w, http.StatusOK, user)
	})
	mux.Handle("GET /api/v1/users/me", protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := PrincipalFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "identity unavailable"})
			return
		}
		setNoStore(w)
		writeJSON(w, http.StatusOK, user)
	}), adminToken, service))
	mux.Handle("POST /api/v1/users/me/password/change", protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		user, ok := PrincipalFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "identity unavailable"})
			return
		}
		var input struct {
			CurrentPassword string `json:"current_password"`
			NewPassword     string `json:"new_password"`
		}
		if err := decodeRequestJSON(w, r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid password-change request"})
			return
		}
		token, hasBearer := bearerToken(r.Header.Get("Authorization"))
		if !hasBearer {
			if cookie, err := r.Cookie(sessionCookieName); err == nil {
				token = cookie.Value
			}
		}
		if err := service.ChangePassword(user.ID, token, input.CurrentPassword, input.NewPassword); err != nil {
			writePasswordChangeError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}), adminToken, service))
	mux.Handle("GET /api/v1/users/me/access-keys", protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		user, ok := PrincipalFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "identity unavailable"})
			return
		}
		keys, err := service.ListAccessKeys(user.ID)
		if err != nil {
			writeAccessKeyError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, keys)
	}), adminToken, service))
	mux.Handle("POST /api/v1/users/me/access-keys", protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		user, ok := PrincipalFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "identity unavailable"})
			return
		}
		credentials, err := service.CreateAccessKey(user.ID)
		if err != nil {
			writeAccessKeyError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, credentials)
	}), adminToken, service))
	mux.Handle("DELETE /api/v1/users/me/access-keys/{keyID}", protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		user, ok := PrincipalFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "identity unavailable"})
			return
		}
		if err := service.DeleteAccessKey(user.ID, r.PathValue("keyID")); err != nil {
			writeAccessKeyError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}), adminToken, service))
	mux.Handle("GET /api/v1/users/me/tokens", protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		user, ok := PrincipalFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "identity unavailable"})
			return
		}
		tokens, err := service.ListPermanentTokens(user.ID)
		if err != nil {
			writePermanentTokenError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, tokens)
	}), adminToken, service))
	mux.Handle("POST /api/v1/users/me/tokens", protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		user, ok := PrincipalFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "identity unavailable"})
			return
		}
		credentials, err := service.CreatePermanentToken(user.ID)
		if err != nil {
			writePermanentTokenError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, credentials)
	}), adminToken, service))
	mux.Handle("DELETE /api/v1/users/me/tokens/{tokenID}", protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		user, ok := PrincipalFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "identity unavailable"})
			return
		}
		if err := service.DeletePermanentToken(user.ID, r.PathValue("tokenID")); err != nil {
			writePermanentTokenError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}), adminToken, service))
	mux.Handle("POST /api/v1/users/me/mfa/enrollment", protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := PrincipalFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "identity unavailable"})
			return
		}
		enrollment, err := service.StartMFAEnrollment(user.ID)
		if err != nil {
			writeMFAError(w, err)
			return
		}
		setNoStore(w)
		writeJSON(w, http.StatusOK, enrollment)
	}), adminToken, service))
	mux.Handle("POST /api/v1/users/me/mfa/confirm", protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := PrincipalFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "identity unavailable"})
			return
		}
		var input struct {
			OTP string `json:"otp"`
		}
		if err := decodeRequestJSON(w, r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid MFA confirmation"})
			return
		}
		updated, err := service.ConfirmMFAEnrollment(user.ID, input.OTP)
		if err != nil {
			writeMFAError(w, err)
			return
		}
		setNoStore(w)
		writeJSON(w, http.StatusOK, updated)
	}), adminToken, service))
	mux.Handle("POST /api/v1/users/me/mfa/recovery-codes", protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		user, ok := PrincipalFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "identity unavailable"})
			return
		}
		var input struct {
			Password string `json:"password"`
			OTP      string `json:"otp"`
		}
		if err := decodeRequestJSON(w, r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid MFA recovery-code request"})
			return
		}
		codes, err := service.RegenerateMFARecoveryCodes(user.ID, input.Password, input.OTP, requestSessionToken(r))
		if err != nil {
			writeMFAError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, codes)
	}), adminToken, service))
	mux.Handle("POST /api/v1/users/me/mfa/disable", protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := PrincipalFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "identity unavailable"})
			return
		}
		var input struct {
			Password string `json:"password"`
			OTP      string `json:"otp"`
		}
		if err := decodeRequestJSON(w, r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid MFA disable request"})
			return
		}
		updated, err := service.DisableMFA(user.ID, input.Password, input.OTP, requestSessionToken(r))
		if err != nil {
			writeMFAError(w, err)
			return
		}
		setNoStore(w)
		writeJSON(w, http.StatusOK, updated)
	}), adminToken, service))
	mux.Handle("GET /api/v1/users", protectAdminAPI(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		setNoStore(w)
		writeJSON(w, http.StatusOK, service.ListUsers())
	}), adminToken, service))
	mux.Handle("POST /api/v1/users", protectAdminAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := decodeRequestJSON(w, r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid user payload"})
			return
		}
		if input.Role == "" {
			input.Role = coreauth.RoleOperator
		}
		principal, _ := PrincipalFromContext(r.Context())
		if input.Role == coreauth.RoleAdmin && principal.Role != coreauth.RoleAdmin && !hasPermission(r, "roles.manage") {
			writeJSON(w, 403, map[string]string{"detail": "creating an administrator requires role-management permission"})
			return
		}
		user, err := service.CreateUser(input.Username, input.Password, input.Role)
		if err != nil {
			writeAuthError(w, err)
			return
		}
		setNoStore(w)
		writeJSON(w, http.StatusCreated, user)
	}), adminToken, service))
}

func writeMFAError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, coreauth.ErrExternalReauthRequired):
		writeJSON(w, 403, map[string]string{"detail": "a recent SSO session is required"})
	case errors.Is(err, coreauth.ErrMFAKeyUnavailable):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"detail": "MFA encryption is unavailable"})
	case errors.Is(err, coreauth.ErrUserNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "user not found"})
	case errors.Is(err, coreauth.ErrMFAAlreadyEnabled), errors.Is(err, coreauth.ErrMFAEnrollmentMissing):
		writeJSON(w, http.StatusConflict, map[string]string{"detail": "MFA state does not allow this operation"})
	case errors.Is(err, coreauth.ErrMFAEnrollmentExpired):
		writeJSON(w, http.StatusGone, map[string]string{"detail": "MFA enrollment has expired"})
	case errors.Is(err, coreauth.ErrMFARequiredByPolicy):
		writeJSON(w, http.StatusConflict, map[string]string{"detail": "global MFA policy requires MFA to remain enabled"})
	case errors.Is(err, coreauth.ErrInvalidMFAEnforcement):
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid global MFA enforcement mode"})
	case errors.Is(err, coreauth.ErrInvalidOTP):
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "one-time code is invalid"})
	case errors.Is(err, coreauth.ErrInvalidCredentials):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "current credentials are invalid"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "MFA operation failed"})
	}
}

func writePasswordChangeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, coreauth.ErrPasswordHistory), errors.Is(err, coreauth.ErrPasswordPolicy):
		passwordError(w, err)
	case errors.Is(err, coreauth.ErrUserRevision):
		userError(w, err)
	case errors.Is(err, coreauth.ErrExternalIdentity):
		writeJSON(w, 403, map[string]string{"detail": "password is managed by the identity provider"})
	case errors.Is(err, coreauth.ErrInvalidPassword), errors.Is(err, coreauth.ErrPasswordUnchanged):
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "new password is invalid"})
	case errors.Is(err, coreauth.ErrInvalidCredentials):
		writeJSON(w, http.StatusForbidden, map[string]string{"detail": "current password is invalid"})
	case errors.Is(err, coreauth.ErrPasswordChanged):
		writeJSON(w, http.StatusConflict, map[string]string{"detail": "password changed concurrently"})
	case errors.Is(err, coreauth.ErrAuthenticationBusy):
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"detail": "authentication service is busy"})
	case errors.Is(err, coreauth.ErrUserNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "user not found"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "password change failed"})
	}
}

func writeAccessKeyError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, coreauth.ErrAccessKeyUnavailable):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"detail": "AccessKey encryption is unavailable"})
	case errors.Is(err, coreauth.ErrAccessKeyLimit):
		writeJSON(w, http.StatusConflict, map[string]string{"detail": "AccessKey limit reached"})
	case errors.Is(err, coreauth.ErrAccessKeyNotFound), errors.Is(err, coreauth.ErrUserNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "AccessKey not found"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "AccessKey operation failed"})
	}
}

func setNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Pragma", "no-cache")
}

func setLoginSession(w http.ResponseWriter, r *http.Request, session coreauth.LoginSession, forceSecure ...bool) bool {
	secure := len(forceSecure) > 0 && forceSecure[0]
	if !prepareNewLogin(w, r, session, secure) {
		return false
	}
	if !commitLoginAudit(w, r, session) {
		return false
	}
	writeSessionCookie(w, r, session, secure)
	return true
}
func writeSessionCookie(w http.ResponseWriter, r *http.Request, session coreauth.LoginSession, forceSecure bool) {
	setNoStore(w)
	maxAge := int(time.Until(session.ExpiresAt).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    session.AccessToken,
		Path:     "/",
		Expires:  session.ExpiresAt,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secureSessionCookie(r) || forceSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func writeLoginResult(w http.ResponseWriter, r *http.Request, status int, session coreauth.LoginSession) {
	if !setLoginSession(w, r, session) {
		return
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get(browserSessionHeader)), "cookie") {
		writeJSON(w, status, map[string]any{
			"browser_session": true,
			"user":            session.User,
			"expires_at":      session.ExpiresAt,
		})
		return
	}
	writeJSON(w, status, session)
}

func setExpiredSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(1, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secureSessionCookie(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func writePermanentTokenError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, coreauth.ErrPermanentTokenLimit):
		writeJSON(w, http.StatusConflict, map[string]string{"detail": "permanent token limit reached"})
	case errors.Is(err, coreauth.ErrPermanentTokenNotFound), errors.Is(err, coreauth.ErrUserNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "permanent token not found"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "permanent token operation failed"})
	}
}

func allowOrigin(w http.ResponseWriter, r *http.Request) bool {
	if !allowedRequestOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"detail": "origin is not allowed"})
		return false
	}
	return true
}

func canBootstrap(r *http.Request, adminToken string) bool {
	if adminToken == "" {
		return isLoopbackRemote(r.RemoteAddr)
	}
	token, ok := bearerToken(r.Header.Get("Authorization"))
	return ok && subtle.ConstantTimeCompare([]byte(token), []byte(adminToken)) == 1
}

func bearerToken(value string) (string, bool) {
	scheme, token, ok := strings.Cut(value, " ")
	return token, ok && strings.EqualFold(scheme, "Bearer") && token != ""
}

func requestSessionToken(r *http.Request) string {
	if token, ok := bearerToken(r.Header.Get("Authorization")); ok {
		return token
	}
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		return cookie.Value
	}
	return ""
}

func remoteHost(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil || host == "" {
		return "unknown"
	}
	return host
}

func writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, coreauth.ErrBootstrapRequired), errors.Is(err, coreauth.ErrBootstrapComplete), errors.Is(err, coreauth.ErrUserExists):
		writeJSON(w, http.StatusConflict, map[string]string{"detail": "user setup conflicts with an existing account"})
	case errors.Is(err, coreauth.ErrInvalidUsername), errors.Is(err, coreauth.ErrInvalidPassword), errors.Is(err, coreauth.ErrInvalidRole):
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": err.Error()})
	case errors.Is(err, coreauth.ErrAuthenticationBusy), errors.Is(err, coreauth.ErrSessionLimit):
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"detail": "authentication service is busy"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "user operation failed"})
	}
}
