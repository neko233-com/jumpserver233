package api

import (
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/connector/enterpriseoauth"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/enterpriselogin"
	"github.com/neko233-com/jumpserver233/server/internal/core/logintickets"
	"net/http"
	"strconv"
	"time"
)

func enterpriseLoginError(w http.ResponseWriter, e error) {
	status, code := 503, "enterprise_login_unavailable"
	switch {
	case errors.Is(e, enterpriselogin.ErrInvalid), errors.Is(e, enterpriseoauth.ErrConfig), errors.Is(e, coreauth.ErrInvalidUsername):
		status, code = 400, "enterprise_login_invalid"
	case errors.Is(e, enterpriselogin.ErrConflict), errors.Is(e, coreauth.ErrUserExists):
		status, code = 409, "enterprise_login_conflict"
	case errors.Is(e, enterpriselogin.ErrFlow), errors.Is(e, enterpriselogin.ErrDisabled), errors.Is(e, enterpriseoauth.ErrIdentity), errors.Is(e, logintickets.ErrTicket), errors.Is(e, coreauth.ErrInvalidCredentials), errors.Is(e, coreauth.ErrUserNotFound), errors.Is(e, coreauth.ErrInvalidOTP), errors.Is(e, coreauth.ErrMFASetupChallenge):
		status, code = 401, "enterprise_login_rejected"
	case errors.Is(e, enterpriselogin.ErrCapacity), errors.Is(e, enterpriseoauth.ErrCapacity):
		status, code = 429, "enterprise_login_capacity"
	}
	setNoStore(w)
	writeJSON(w, status, map[string]string{"error_code": code})
}
func enterpriseCookie(r *http.Request, name string) string {
	c, e := r.Cookie(name)
	if e != nil || len(c.Value) > 400 {
		return ""
	}
	return externalReadFlowCookie(r, name, c.Value)
}
func setEnterpriseCookie(w http.ResponseWriter, r *http.Request, d Dependencies, kind, name, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: externalSetFlowCookie(r, name, value), Path: externalCookiePath(r, "/api/v1/authentication/"+kind), HttpOnly: true, Secure: secureSessionCookie(r) || d.EnterpriseLogin.SecureCookies(), SameSite: http.SameSiteLaxMode, MaxAge: age})
}
func registerEnterpriseLoginRoutes(mux *http.ServeMux, d Dependencies, kind string) {
	if d.EnterpriseLogin == nil || !enterpriseoauth.Kind(kind) {
		return
	}
	protect := func(h http.HandlerFunc) http.Handler { return protectAdminAPI(h, d.AdminToken, d.Auth) }
	settings := "/api/v1/settings/security/" + kind
	base := "/api/v1/authentication/" + kind
	flowCookie := "jms_" + kind + "_flow"
	pendingCookie := "jms_" + kind + "_pending"
	attempts := newLoginFailures()
	reserve := func(w http.ResponseWriter, r *http.Request) bool {
		if retry, ok := attempts.reserve("host:"+remoteHost(r.RemoteAddr), time.Now()); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			writeJSON(w, 429, map[string]string{"error_code": "enterprise_login_capacity"})
			return false
		}
		return true
	}
	mux.Handle("GET "+settings, protect(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, d.EnterpriseLogin.Snapshot()) }))
	mux.Handle("PUT "+settings, protect(func(w http.ResponseWriter, r *http.Request) {
		var in enterpriselogin.Input
		if decodeRequestJSON(w, r, &in) != nil {
			enterpriseLoginError(w, enterpriselogin.ErrInvalid)
			return
		}
		actor, _ := PrincipalFromContext(r.Context())
		out, e := d.EnterpriseLogin.Save(in, actor.ID, actor.Username)
		if e != nil {
			enterpriseLoginError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("GET "+settings+"/audit", protect(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, d.EnterpriseLogin.Audit()) }))
	mux.Handle("POST "+settings+"/check", protect(func(w http.ResponseWriter, r *http.Request) {
		if e := d.EnterpriseLogin.Check(r.Context()); e != nil {
			enterpriseLoginError(w, e)
			return
		}
		writeJSON(w, 200, map[string]bool{"application_credentials_available": true})
	}))
	mux.Handle("POST "+settings+"/users", protect(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Subject  string `json:"subject"`
			Username string `json:"username"`
		}
		if decodeRequestJSON(w, r, &in) != nil || in.Subject == "" {
			enterpriseLoginError(w, enterpriselogin.ErrInvalid)
			return
		}
		namespace := d.EnterpriseLogin.Namespace()
		if namespace == "" {
			enterpriseLoginError(w, enterpriselogin.ErrInvalid)
			return
		}
		user, e := ensureExternalForRequest(r, d.Auth, kind, namespace, in.Subject, in.Username, true)
		if e != nil {
			enterpriseLoginError(w, e)
			return
		}
		writeJSON(w, 201, user)
	}))
	mux.HandleFunc("GET "+base+"/status", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		writeJSON(w, 200, map[string]bool{"enabled": d.EnterpriseLogin.Snapshot().Enabled && !d.Auth.BootstrapRequired()})
	})
	mux.HandleFunc("GET "+base+"/start", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) || !reserve(w, r) {
			return
		}
		if d.Auth.BootstrapRequired() {
			enterpriseLoginError(w, enterpriselogin.ErrDisabled)
			return
		}
		d.EnterpriseLogin.Tickets.Consume(enterpriseCookie(r, pendingCookie))
		setEnterpriseCookie(w, r, d, kind, pendingCookie, "", -1)
		start, e := d.EnterpriseLogin.Begin()
		if e != nil {
			enterpriseLoginError(w, e)
			return
		}
		setEnterpriseCookie(w, r, d, kind, flowCookie, start.Proof, 600)
		markLoginAudit(r, "started", "")
		w.Header().Set("Referrer-Policy", "no-referrer")
		http.Redirect(w, r, start.URL, 303)
	})
	mux.HandleFunc("GET "+base+"/callback", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		w.Header().Set("Referrer-Policy", "no-referrer")
		proof := enterpriseCookie(r, flowCookie)
		setEnterpriseCookie(w, r, d, kind, flowCookie, "", -1)
		fail := func() {
			if len(r.URL.Query()["state"]) == 1 {
				d.EnterpriseLogin.Cancel(r.URL.Query().Get("state"), proof)
			}
			markLoginAudit(r, "failed", "flow_rejected")
			http.Redirect(w, r, d.EnterpriseLogin.ReturnURL("/login?enterprise_error=1"), 303)
		}
		q := r.URL.Query()
		codes := q["code"]
		if kind == "dingtalk" {
			if len(codes)+len(q["authCode"]) != 1 {
				fail()
				return
			}
			if len(codes) == 0 {
				codes = q["authCode"]
			}
		}
		if len(q["state"]) != 1 || len(codes) != 1 || q.Has("error") {
			fail()
			return
		}
		if !reserve(w, r) {
			return
		}
		identity, e := d.EnterpriseLogin.Finish(r.Context(), q.Get("state"), proof, codes[0])
		if e != nil {
			fail()
			return
		}
		user, e := ensureExternalForRequest(r, d.Auth, kind, identity.Issuer, identity.Subject, "", identity.Provision)
		if e != nil {
			fail()
			return
		}
		ticket, e := d.EnterpriseLogin.NewPending(user.ID, identity.Revision, user.AuthGeneration)
		if e != nil {
			fail()
			return
		}
		loginAuditSubject(r, user)
		markLoginAudit(r, "external_verified", "external_identity_verified")
		setEnterpriseCookie(w, r, d, kind, pendingCookie, ticket, 300)
		http.Redirect(w, r, d.EnterpriseLogin.ReturnURL("/login?enterprise="+kind+"&continue=1"), 303)
	})
	mux.HandleFunc("GET "+base+"/pending", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		p, e := d.EnterpriseLogin.Pending(enterpriseCookie(r, pendingCookie), false)
		if e != nil {
			enterpriseLoginError(w, e)
			return
		}
		u, ok := d.Auth.ActiveUserByID(p.UserID)
		if !ok || u.Source != kind || u.SourceID != externalSourceID(r) || u.AuthGeneration != p.AuthGeneration {
			enterpriseLoginError(w, enterpriselogin.ErrFlow)
			return
		}
		writeJSON(w, 200, map[string]bool{"active": true, "mfa_required": u.MFAEnabled})
	})
	mux.HandleFunc("POST "+base+"/complete", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) || !reserve(w, r) {
			return
		}
		var in struct {
			OTP        string `json:"otp"`
			SetupToken string `json:"setup_token"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			enterpriseLoginError(w, enterpriselogin.ErrFlow)
			return
		}
		completeExternalBrowserLogin(w, r, d.Auth, d.EnterpriseLogin, kind, enterpriseCookie(r, pendingCookie), in.OTP, in.SetupToken, attempts, d.EnterpriseLogin.SecureCookies(), func() { setEnterpriseCookie(w, r, d, kind, pendingCookie, "", -1) }, enterpriseLoginError)
	})
	mux.HandleFunc("DELETE "+base+"/pending", func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		d.EnterpriseLogin.Tickets.Consume(enterpriseCookie(r, pendingCookie))
		setEnterpriseCookie(w, r, d, kind, pendingCookie, "", -1)
		w.WriteHeader(204)
	})
}
