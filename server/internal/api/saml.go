package api

import (
	"errors"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/samlclient"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/logintickets"
	"github.com/neko233-com/jumpserver233/server/internal/core/samllogin"
)

const samlFlowCookie = "jms_saml_flow"
const samlPendingCookie = "jms_saml_pending"
const samlCookiePath = "/api/v1/authentication/saml"

func samlCookie(r *http.Request, name string) string {
	c, e := r.Cookie(name)
	if e != nil || len(c.Value) > 400 {
		return ""
	}
	return externalReadFlowCookie(r, name, c.Value)
}
func setSAMLCookie(w http.ResponseWriter, r *http.Request, d Dependencies, name, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: externalSetFlowCookie(r, name, value), Path: externalCookiePath(r, samlCookiePath), HttpOnly: true, Secure: secureSessionCookie(r) || d.SAML.SecureCookies(), SameSite: http.SameSiteLaxMode, MaxAge: age})
}
func registerSAMLRoutes(mux *http.ServeMux, d Dependencies) {
	protect := func(h http.HandlerFunc) http.Handler { return protectAdminAPI(h, d.AdminToken, d.Auth) }
	attempts := newLoginFailures()
	reserve := func(w http.ResponseWriter, key string) bool {
		if retry, ok := attempts.reserve(key, time.Now()); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			writeJSON(w, 429, map[string]string{"detail": "SAML login attempt limit reached"})
			return false
		}
		return true
	}
	mux.Handle("GET /api/v1/settings/security/saml", protect(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, d.SAML.Snapshot()) }))
	mux.Handle("PUT /api/v1/settings/security/saml", protect(func(w http.ResponseWriter, r *http.Request) {
		var in samllogin.Config
		if decodeRequestJSON(w, r, &in) != nil {
			writeSAMLError(w, samllogin.ErrInvalid)
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		result, e := d.SAML.Save(in, u.ID, u.Username)
		if e != nil {
			writeSAMLError(w, e)
			return
		}
		writeJSON(w, 200, result)
	}))
	mux.Handle("GET /api/v1/settings/security/saml/audit", protect(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, d.SAML.Audit()) }))
	mux.Handle("POST /api/v1/settings/security/saml/users", protect(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Subject  string `json:"subject"`
			Username string `json:"username"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			writeSAMLError(w, samllogin.ErrInvalid)
			return
		}
		c := d.SAML.Snapshot()
		if c.IDPEntityID == "" {
			writeSAMLError(w, samllogin.ErrInvalid)
			return
		}
		u, e := ensureExternalForRequest(r, d.Auth, "saml", d.SAML.Namespace(), in.Subject, in.Username, true)
		if e != nil {
			writeSAMLError(w, e)
			return
		}
		writeJSON(w, 201, u)
	}))
	mux.HandleFunc("GET /api/v1/authentication/saml/status", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		writeJSON(w, 200, map[string]bool{"enabled": d.SAML.Available() && !d.Auth.BootstrapRequired()})
	})
	mux.HandleFunc("GET /api/v1/authentication/saml/start", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		if d.Auth.BootstrapRequired() {
			writeSAMLError(w, samllogin.ErrDisabled)
			return
		}
		if !reserve(w, "host:"+remoteHost(r.RemoteAddr)) {
			return
		}
		d.SAML.Tickets.Consume(samlCookie(r, samlPendingCookie))
		setSAMLCookie(w, r, d, samlPendingCookie, "", -1)
		start, e := d.SAML.Begin()
		if e != nil {
			http.Redirect(w, r, d.SAML.ReturnURL("/login?saml_error=1"), 303)
			return
		}
		setSAMLCookie(w, r, d, samlFlowCookie, start.Proof, 600)
		markLoginAudit(r, "started", "")
		http.Redirect(w, r, start.URL, 303)
	})
	mux.HandleFunc("GET /api/v1/authentication/saml/metadata", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		raw, e := d.SAML.Metadata()
		if e != nil {
			writeSAMLError(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(raw)
	})
	mux.HandleFunc("POST /api/v1/authentication/saml/acs", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		w.Header().Set("Referrer-Policy", "no-referrer")
		fail := func() {
			markLoginAudit(r, "failed", "flow_rejected")
			http.Redirect(w, r, d.SAML.ReturnURL("/login?saml_error=1"), 303)
		}
		if !reserve(w, "host:"+remoteHost(r.RemoteAddr)) {
			return
		}
		media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if e != nil || media != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" {
			fail()
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1500000)
		if r.ParseForm() != nil || len(r.PostForm["RelayState"]) != 1 || len(r.PostForm["SAMLResponse"]) != 1 || len(r.PostForm) != 2 {
			fail()
			return
		}
		code, e := d.SAML.Accept(r.PostForm.Get("RelayState"), r.PostForm.Get("SAMLResponse"))
		if e != nil {
			fail()
			return
		}
		markLoginAudit(r, "external_verified", "external_identity_verified")
		http.Redirect(w, r, d.SAML.ReturnURL("/api/v1/authentication/saml/finalize?code="+code), 303)
	})
	mux.HandleFunc("GET /api/v1/authentication/saml/finalize", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		w.Header().Set("Referrer-Policy", "no-referrer")
		proof := samlCookie(r, samlFlowCookie)
		setSAMLCookie(w, r, d, samlFlowCookie, "", -1)
		fail := func() {
			markLoginAudit(r, "failed", "flow_rejected")
			http.Redirect(w, r, d.SAML.ReturnURL("/login?saml_error=1"), 303)
		}
		q := r.URL.Query()
		if len(q["code"]) != 1 || len(q) != 1 {
			fail()
			return
		}
		id, e := d.SAML.Finalize(q.Get("code"), proof)
		if e != nil {
			fail()
			return
		}
		user, e := ensureExternalForRequest(r, d.Auth, "saml", id.Issuer, id.Subject, "", id.Provision)
		if e != nil {
			fail()
			return
		}
		ticket, e := d.SAML.NewPending(user.ID, id.Revision, user.AuthGeneration)
		if e != nil {
			fail()
			return
		}
		loginAuditSubject(r, user)
		markLoginAudit(r, "external_verified", "external_identity_verified")
		setSAMLCookie(w, r, d, samlPendingCookie, ticket, 300)
		http.Redirect(w, r, d.SAML.ReturnURL("/login?saml=continue"), 303)
	})
	mux.HandleFunc("GET /api/v1/authentication/saml/pending", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		p, e := d.SAML.Pending(samlCookie(r, samlPendingCookie), false)
		if e != nil {
			writeSAMLError(w, e)
			return
		}
		u, ok := d.Auth.UserByID(p.UserID)
		if !ok || (u.Source != "saml" || u.SourceID != externalSourceID(r)) {
			writeSAMLError(w, samllogin.ErrFlow)
			return
		}
		writeJSON(w, 200, map[string]bool{"active": true, "mfa_required": u.MFAEnabled})
	})
	mux.HandleFunc("POST /api/v1/authentication/saml/complete", func(w http.ResponseWriter, r *http.Request) {
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
			writeSAMLError(w, samllogin.ErrFlow)
			return
		}
		completeExternalBrowserLogin(w, r, d.Auth, d.SAML, "saml", samlCookie(r, samlPendingCookie), in.OTP, in.SetupToken, attempts, d.SAML.SecureCookies(), func() { setSAMLCookie(w, r, d, samlPendingCookie, "", -1) }, writeSAMLError)
	})
	mux.HandleFunc("DELETE /api/v1/authentication/saml/pending", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		d.SAML.Tickets.Consume(samlCookie(r, samlPendingCookie))
		setSAMLCookie(w, r, d, samlPendingCookie, "", -1)
		w.WriteHeader(204)
	})
}
func writeSAMLError(w http.ResponseWriter, e error) {
	status := 503
	detail := "SAML configuration or provider unavailable"
	switch {
	case errors.Is(e, samllogin.ErrInvalid), errors.Is(e, samlclient.ErrConfig):
		status = 400
	case errors.Is(e, samllogin.ErrConflict):
		status = 409
	case errors.Is(e, samlclient.ErrResponse), errors.Is(e, samllogin.ErrDisabled), errors.Is(e, samllogin.ErrFlow), errors.Is(e, logintickets.ErrTicket), errors.Is(e, coreauth.ErrUserNotFound), errors.Is(e, coreauth.ErrInvalidOTP), errors.Is(e, coreauth.ErrInvalidCredentials), errors.Is(e, coreauth.ErrMFASetupChallenge):
		status = 401
		detail = "SAML login or second factor rejected"
	case errors.Is(e, coreauth.ErrUserExists), errors.Is(e, coreauth.ErrInvalidUsername):
		status = 409
	}
	writeJSON(w, status, map[string]string{"detail": detail})
}
