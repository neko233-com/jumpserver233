package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/passkeyclient"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/logintickets"
	"github.com/neko233-com/jumpserver233/server/internal/core/passkeys"
)

const passkeyLoginCookie = "jms_passkey_flow"
const passkeyRegisterCookie = "jms_passkey_register"
const passkeyPendingCookie = "jms_passkey_pending"
const passkeyCookiePath = "/api/v1/authentication/passkey"
const passkeyRegisterPath = "/api/v1/users/me/passkeys"

func passkeyCookie(r *http.Request, name string) string {
	c, e := r.Cookie(name)
	if e != nil || len(c.Value) > 128 {
		return ""
	}
	return c.Value
}
func setPasskeyCookie(w http.ResponseWriter, r *http.Request, d Dependencies, name, value string, age int) {
	path := passkeyCookiePath
	if name == passkeyRegisterCookie {
		path = passkeyRegisterPath
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: path, HttpOnly: true, Secure: secureSessionCookie(r) || strings.HasPrefix(d.PublicURL, "https://"), SameSite: http.SameSiteStrictMode, MaxAge: age})
}
func registerPasskeyRoutes(mux *http.ServeMux, d Dependencies) {
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	admin := func(h http.HandlerFunc) http.Handler { return protectAdminAPI(h, d.AdminToken, d.Auth) }
	attempts := newLoginFailures()
	reserve := func(w http.ResponseWriter, key string) bool {
		if retry, ok := attempts.reserve(key, time.Now()); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			writeJSON(w, 429, map[string]string{"detail": "Passkey attempt limit reached"})
			return false
		}
		return true
	}
	mux.Handle("GET /api/v1/settings/security/passkeys", admin(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, d.Passkeys.Snapshot()) }))
	mux.Handle("PUT /api/v1/settings/security/passkeys", admin(func(w http.ResponseWriter, r *http.Request) {
		var in passkeys.Config
		if decodeRequestJSON(w, r, &in) != nil {
			writePasskeyError(w, passkeys.ErrInvalid)
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		out, e := d.Passkeys.Save(in, u.ID, u.Username)
		if e != nil {
			writePasskeyError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("GET /api/v1/settings/security/passkeys/audit", admin(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, d.Passkeys.Audit("")) }))
	mux.Handle("GET /api/v1/users/me/passkeys", protect(func(w http.ResponseWriter, r *http.Request) {
		u, _ := PrincipalFromContext(r.Context())
		writeJSON(w, 200, map[string]any{"settings": d.Passkeys.Snapshot(), "credentials": d.Passkeys.List(u.ID)})
	}))
	mux.Handle("POST /api/v1/users/me/passkeys/registration/start", protect(func(w http.ResponseWriter, r *http.Request) {
		u, _ := PrincipalFromContext(r.Context())
		if !reserve(w, "manage:"+u.ID) {
			return
		}
		var in struct {
			Name     string `json:"name"`
			Password string `json:"password"`
			OTP      string `json:"otp"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			writePasskeyError(w, passkeys.ErrInvalid)
			return
		}
		version := d.Auth.PasskeyManagementVersion(u.ID)
		if e := d.Auth.VerifyPasskeyManagement(u.ID, in.Password, in.OTP, requestSessionToken(r)); e != nil {
			attempts.failed("manage:"+u.ID, time.Now())
			writePasskeyError(w, e)
			return
		}
		if version == "" || version != d.Auth.PasskeyManagementVersion(u.ID) {
			writePasskeyError(w, passkeys.ErrConflict)
			return
		}
		d.Passkeys.Cancel(passkeyCookie(r, passkeyRegisterCookie))
		start, e := d.Passkeys.BeginRegistration(u, in.Name, requestSessionToken(r), version)
		if e != nil {
			writePasskeyError(w, e)
			return
		}
		setPasskeyCookie(w, r, d, passkeyRegisterCookie, start.Token, 300)
		writeJSON(w, 200, start.Options)
	}))
	mux.Handle("POST /api/v1/users/me/passkeys/registration/finish", protect(func(w http.ResponseWriter, r *http.Request) {
		u, _ := PrincipalFromContext(r.Context())
		token := passkeyCookie(r, passkeyRegisterCookie)
		setPasskeyCookie(w, r, d, passkeyRegisterCookie, "", -1)
		var in struct {
			Credential json.RawMessage `json:"credential"`
		}
		if decodeRequestJSON(w, r, &in) != nil || !d.Auth.PasskeyManagementReady(u.ID) {
			d.Passkeys.Cancel(token)
			writePasskeyError(w, passkeys.ErrFlow)
			return
		}
		out, e := d.Passkeys.FinishRegistration(token, requestSessionToken(r), u, in.Credential, d.Auth.PasskeyManagementVersion(u.ID))
		if e != nil {
			writePasskeyError(w, e)
			return
		}
		attempts.succeeded("manage:" + u.ID)
		writeJSON(w, 201, out)
	}))
	mux.Handle("DELETE /api/v1/users/me/passkeys/registration", protect(func(w http.ResponseWriter, r *http.Request) {
		d.Passkeys.Cancel(passkeyCookie(r, passkeyRegisterCookie))
		setPasskeyCookie(w, r, d, passkeyRegisterCookie, "", -1)
		w.WriteHeader(204)
	}))
	mux.Handle("DELETE /api/v1/users/me/passkeys/{id}", protect(func(w http.ResponseWriter, r *http.Request) {
		u, _ := PrincipalFromContext(r.Context())
		if !reserve(w, "manage:"+u.ID) {
			return
		}
		var in struct {
			Password string `json:"password"`
			OTP      string `json:"otp"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			writePasskeyError(w, passkeys.ErrInvalid)
			return
		}
		if e := d.Auth.VerifyPasskeyManagement(u.ID, in.Password, in.OTP, requestSessionToken(r)); e != nil {
			attempts.failed("manage:"+u.ID, time.Now())
			writePasskeyError(w, e)
			return
		}
		if e := d.Passkeys.Delete(u, r.PathValue("id")); e != nil {
			writePasskeyError(w, e)
			return
		}
		attempts.succeeded("manage:" + u.ID)
		w.WriteHeader(204)
	}))
	mux.Handle("PATCH /api/v1/users/me/passkeys/{id}", protect(func(w http.ResponseWriter, r *http.Request) {
		u, _ := PrincipalFromContext(r.Context())
		var in struct {
			Name string `json:"name"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			writePasskeyError(w, passkeys.ErrInvalid)
			return
		}
		out, e := d.Passkeys.Rename(u, r.PathValue("id"), in.Name)
		if e != nil {
			writePasskeyError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("GET /api/v1/authentication/passkey/status", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		writeJSON(w, 200, map[string]bool{"enabled": d.Passkeys.Snapshot().Available && !d.Auth.BootstrapRequired()})
	})
	mux.HandleFunc("POST /api/v1/authentication/passkey/start", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		if d.Auth.BootstrapRequired() {
			writePasskeyError(w, passkeys.ErrDisabled)
			return
		}
		if !reserve(w, "host:"+remoteHost(r.RemoteAddr)) {
			return
		}
		d.Passkeys.Cancel(passkeyCookie(r, passkeyLoginCookie))
		d.Passkeys.Tickets.Consume(passkeyCookie(r, passkeyPendingCookie))
		setPasskeyCookie(w, r, d, passkeyPendingCookie, "", -1)
		start, e := d.Passkeys.BeginLogin()
		if e != nil {
			writePasskeyError(w, e)
			return
		}
		setPasskeyCookie(w, r, d, passkeyLoginCookie, start.Token, 300)
		writeJSON(w, 200, start.Options)
	})
	mux.HandleFunc("POST /api/v1/authentication/passkey/verify", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		if !reserve(w, "host:"+remoteHost(r.RemoteAddr)) {
			return
		}
		token := passkeyCookie(r, passkeyLoginCookie)
		setPasskeyCookie(w, r, d, passkeyLoginCookie, "", -1)
		var in struct {
			Credential json.RawMessage `json:"credential"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			d.Passkeys.Cancel(token)
			writePasskeyError(w, passkeys.ErrFlow)
			return
		}
		pending, e := d.Passkeys.FinishLogin(token, in.Credential)
		if e != nil {
			writePasskeyError(w, e)
			return
		}
		setPasskeyCookie(w, r, d, passkeyPendingCookie, pending, 300)
		writeJSON(w, 200, map[string]bool{"pending": true})
	})
	mux.HandleFunc("GET /api/v1/authentication/passkey/pending", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		p, e := d.Passkeys.Pending(passkeyCookie(r, passkeyPendingCookie), false)
		if e != nil {
			writePasskeyError(w, e)
			return
		}
		u, ok := d.Auth.UserByID(p.UserID)
		if !ok {
			writePasskeyError(w, passkeys.ErrFlow)
			return
		}
		writeJSON(w, 200, map[string]bool{"active": true, "mfa_required": u.MFAEnabled})
	})
	mux.HandleFunc("POST /api/v1/authentication/passkey/complete", func(w http.ResponseWriter, r *http.Request) {
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
			writePasskeyError(w, passkeys.ErrFlow)
			return
		}
		completeExternalBrowserLogin(w, r, d.Auth, d.Passkeys, "passkey", passkeyCookie(r, passkeyPendingCookie), in.OTP, in.SetupToken, attempts, strings.HasPrefix(d.PublicURL, "https://"), func() { setPasskeyCookie(w, r, d, passkeyPendingCookie, "", -1) }, writePasskeyError)
	})
	mux.HandleFunc("DELETE /api/v1/authentication/passkey/pending", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		d.Passkeys.Cancel(passkeyCookie(r, passkeyLoginCookie))
		d.Passkeys.Tickets.Consume(passkeyCookie(r, passkeyPendingCookie))
		setPasskeyCookie(w, r, d, passkeyLoginCookie, "", -1)
		setPasskeyCookie(w, r, d, passkeyPendingCookie, "", -1)
		w.WriteHeader(204)
	})
}
func writePasskeyError(w http.ResponseWriter, e error) {
	status := 503
	detail := "Passkey operation unavailable"
	switch {
	case errors.Is(e, passkeys.ErrInvalid), errors.Is(e, passkeyclient.ErrConfig):
		status = 400
	case errors.Is(e, passkeys.ErrNotFound):
		status = 404
	case errors.Is(e, passkeys.ErrConflict):
		status = 409
	case errors.Is(e, passkeys.ErrCapacity):
		status = 429
	case errors.Is(e, coreauth.ErrExternalReauthRequired), errors.Is(e, coreauth.ErrMFARequiredByPolicy):
		status = 403
	case errors.Is(e, passkeys.ErrDisabled), errors.Is(e, passkeys.ErrFlow), errors.Is(e, passkeys.ErrClone), errors.Is(e, passkeyclient.ErrCredential), errors.Is(e, logintickets.ErrTicket), errors.Is(e, coreauth.ErrOTPRequired), errors.Is(e, coreauth.ErrInvalidOTP), errors.Is(e, coreauth.ErrInvalidCredentials), errors.Is(e, coreauth.ErrMFASetupChallenge), errors.Is(e, coreauth.ErrUserNotFound):
		status = 401
		detail = "Passkey or second-factor verification rejected"
	}
	writeJSON(w, status, map[string]string{"detail": detail})
}
