package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/radiusclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/logintickets"
	"github.com/neko233-com/jumpserver233/server/internal/core/radiuslogin"
)

const radiusCookiePath = "/api/v1/authentication/radius"
const radiusPrimaryCookie = "jms_radius_challenge"
const radiusPendingCookie = "jms_radius_pending"
const factorCookiePath = "/api/v1/authentication/factor"
const factorCookie = "jms_radius_factor"

type factorSourceKey struct{}

func radiusError(w http.ResponseWriter, e error) {
	if errors.Is(e, coreauth.ErrOTPRequired) {
		writeJSON(w, 401, map[string]bool{"mfa_required": true})
		return
	}
	if errors.Is(e, coreauth.ErrInvalidOTP) || errors.Is(e, coreauth.ErrInvalidCredentials) || errors.Is(e, coreauth.ErrUserNotFound) {
		writeJSON(w, 401, map[string]string{"error_code": "radius_rejected"})
		return
	}
	status, code := 503, "radius_unavailable"
	switch {
	case errors.Is(e, radiuslogin.ErrInvalid), errors.Is(e, radiusclient.ErrConfig):
		status, code = 400, "radius_invalid"
	case errors.Is(e, radiuslogin.ErrConflict):
		status, code = 409, "radius_conflict"
	case radiuslogin.Rejected(e):
		status, code = 401, "radius_rejected"
	case errors.Is(e, radiuslogin.ErrFlow), errors.Is(e, logintickets.ErrTicket):
		status, code = 401, "radius_flow"
	case errors.Is(e, radiuslogin.ErrDisabled):
		status, code = 403, "radius_disabled"
	case errors.Is(e, radiuslogin.ErrBinding):
		status, code = 403, "radius_binding"
	case errors.Is(e, radiuslogin.ErrBusy), errors.Is(e, radiuslogin.ErrCapacity):
		status, code = 429, "radius_capacity"
	}
	setNoStore(w)
	writeJSON(w, status, map[string]string{"error_code": code})
}
func radiusCookie(r *http.Request, name string) string {
	c, e := r.Cookie(name)
	if e != nil || len(c.Value) > 128 {
		return ""
	}
	return c.Value
}
func setRadiusCookie(w http.ResponseWriter, r *http.Request, name, path, value string, secure bool) {
	age := 300
	if value == "" {
		age = -1
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: path, HttpOnly: true, Secure: secure || secureSessionCookie(r), SameSite: http.SameSiteLaxMode, MaxAge: age})
}
func selectRadiusTicket(cookie, body string) (string, error) {
	if cookie != "" && body != "" && cookie != body {
		return "", radiuslogin.ErrFlow
	}
	if body != "" {
		return body, nil
	}
	return cookie, nil
}
func radiusRequired(d Dependencies, u coreauth.User) bool {
	if d.RADIUS == nil {
		return false
	}
	privileged := u.Role == coreauth.RoleAdmin || len(globalLoginPermissions(d, u).Permissions) > 0
	return d.RADIUS.Required(u.ID, privileged)
}
func radiusProofCurrent(d Dependencies, proof string, u coreauth.User) bool {
	if !radiusRequired(d, u) {
		return true
	}
	stamp, e := d.Auth.LoginProofSecondaryStamp(proof, u.ID)
	return e == nil && d.RADIUS.ValidStamp(stamp)
}
func prepareRadiusFactor(w http.ResponseWriter, r *http.Request, session coreauth.LoginSession, secure bool) bool {
	d := policyDependencies(r)
	if !radiusRequired(d, session.User) {
		return true
	}
	if d.RADIUS.ValidStamp(d.Auth.SessionSecondaryStamp(session.AccessToken)) {
		return true
	}
	fail := func(e error) {
		_ = d.Auth.RevokeToken(session.AccessToken)
		markLoginAudit(r, "failed", "authentication_unavailable")
		radiusError(w, e)
	}
	remote, e := d.RADIUS.RemoteFor(session.User.ID, session.User.Username, session.User.Source)
	if e != nil {
		fail(e)
		return false
	}
	proof, e := d.Auth.QuarantineLogin(session.AccessToken)
	if e != nil {
		fail(e)
		return false
	}
	browser := browserLoginRequest(r)
	ticket, status, e := d.RADIUS.BeginFactor(radiuslogin.FactorInput{UserID: session.User.ID, Username: session.User.Username, RemoteName: remote, SourceIP: accesspolicies.SourceIP(r.Context()), AuthSource: proof.AuthSource, Proof: proof.Proof, ExpiresAt: proof.ExpiresAt, Browser: browser, Secure: secure || secureSessionCookie(r)})
	if e != nil {
		radiusError(w, e)
		return false
	}
	clearReviewCookie(w, r)
	setExpiredSessionCookie(w, r)
	setRadiusCookie(w, r, factorCookie, factorCookiePath, ticket, secure)
	markLoginAudit(r, "challenge", "second_factor_required")
	out := map[string]any{"radius_factor_required": true, "factor_required": true, "factor": "radius", "expires_at": status.ExpiresAt}
	if !browser {
		out["factor_token"] = ticket
	}
	writeJSON(w, 202, out)
	return false
}

type radiusBrowserFlow struct {
	s      *radiuslogin.Service
	source string
}

func (f radiusBrowserFlow) Pending(t string, a bool) (logintickets.Ticket, error) {
	return f.s.Pending(t, a, f.source)
}
func (f radiusBrowserFlow) Consume(t string, r int) bool { return f.s.Consume(t, r, f.source) }
func (f radiusBrowserFlow) SetSetup(t, v string) error {
	if _, e := f.s.Pending(t, false, f.source); e != nil {
		return e
	}
	return f.s.SetSetup(t, v)
}
func registerRadiusRoutes(mux *http.ServeMux, d Dependencies) {
	protect := func(h http.HandlerFunc) http.Handler { return protectAdminAPI(h, d.AdminToken, d.Auth) }
	attempts := newLoginFailures()
	reserve := func(w http.ResponseWriter, r *http.Request) bool {
		if retry, ok := attempts.reserve(remoteHost(r.RemoteAddr), time.Now()); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			writeJSON(w, 429, map[string]string{"error_code": "radius_capacity"})
			return false
		}
		return true
	}
	mux.Handle("GET /api/v1/settings/security/radius", protect(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, d.RADIUS.Snapshot()) }))
	mux.Handle("GET /api/v1/settings/security/radius/users", protect(func(w http.ResponseWriter, r *http.Request) {
		users := make([]map[string]string, 0)
		for _, user := range d.Auth.ListUsers() {
			users = append(users, map[string]string{"id": user.ID, "username": user.Username})
		}
		writeJSON(w, 200, users)
	}))
	mux.Handle("PUT /api/v1/settings/security/radius", protect(func(w http.ResponseWriter, r *http.Request) {
		var in radiuslogin.Input
		if decodeRequestJSONLimit(w, r, &in, 256<<10) != nil {
			radiusError(w, radiuslogin.ErrInvalid)
			return
		}
		for _, id := range in.FactorUserIDs {
			if _, ok := d.Auth.UserByID(id); !ok {
				radiusError(w, radiuslogin.ErrInvalid)
				return
			}
		}
		for id := range in.Bindings {
			if _, ok := d.Auth.UserByID(id); !ok {
				radiusError(w, radiuslogin.ErrInvalid)
				return
			}
		}
		u, _ := PrincipalFromContext(r.Context())
		release := lockCalendarAccess(d, d.AccessMu)
		defer release()
		out, e := d.RADIUS.Save(in, u.ID, u.Username)
		if e != nil {
			radiusError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("GET /api/v1/settings/security/radius/audit", protect(func(w http.ResponseWriter, r *http.Request) {
		offset, e := strconv.Atoi(defaultQuery(r, "offset", "0"))
		limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "25"))
		if e != nil || e2 != nil {
			radiusError(w, radiuslogin.ErrInvalid)
			return
		}
		rows, n, e := d.RADIUS.Audit(offset, limit)
		if e != nil {
			radiusError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": n})
	}))
	mux.Handle("POST /api/v1/settings/security/radius/check", protect(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Endpoint string `json:"endpoint"`
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			radiusError(w, radiuslogin.ErrInvalid)
			return
		}
		reply, e := d.RADIUS.Probe(r.Context(), in.Endpoint, in.Username, in.Password)
		if e != nil {
			radiusError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"response_authenticated": true, "result": reply.Code})
	}))
	mux.Handle("POST /api/v1/settings/security/radius/users", protect(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Subject  string `json:"subject"`
			Username string `json:"username"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			radiusError(w, radiuslogin.ErrInvalid)
			return
		}
		c := d.RADIUS.Snapshot()
		if !radiuslogin.ValidSubject(in.Subject) {
			radiusError(w, radiuslogin.ErrInvalid)
			return
		}
		if !c.Enabled {
			radiusError(w, radiuslogin.ErrDisabled)
			return
		}
		u, e := d.Auth.EnsureExternalUser("radius", "radius:"+c.Realm, in.Subject, in.Username, true)
		if e == nil {
			e = d.RADIUS.BindVerifiedUser(u.ID, in.Subject, c.Revision)
		}
		if e != nil {
			radiusError(w, e)
			return
		}
		writeJSON(w, 201, u)
	}))
	mux.HandleFunc("GET /api/v1/authentication/radius/status", func(w http.ResponseWriter, r *http.Request) {
		if !allowOrigin(w, r) {
			return
		}
		setNoStore(w)
		writeJSON(w, 200, map[string]bool{"enabled": d.RADIUS.Snapshot().Enabled && !d.Auth.BootstrapRequired()})
	})
	primaryResult := func(w http.ResponseWriter, r *http.Request, out radiuslogin.PrimaryResult, e error) {
		if e != nil {
			attempts.failed(remoteHost(r.RemoteAddr), time.Now())
			markLoginAudit(r, "failed", "credentials_rejected")
			radiusError(w, e)
			return
		}
		if out.Challenge {
			setRadiusCookie(w, r, radiusPrimaryCookie, radiusCookiePath, out.Ticket, false)
			reply := map[string]any{"radius_challenge_required": true, "round": out.Status.Round, "expires_at": out.Status.ExpiresAt}
			if !browserLoginRequest(r) {
				reply["challenge_token"] = out.Ticket
			}
			markLoginAudit(r, "challenge", "second_factor_required")
			writeJSON(w, 202, reply)
			return
		}
		setRadiusCookie(w, r, radiusPrimaryCookie, radiusCookiePath, "", false)
		id := out.Identity
		user, e := d.Auth.EnsureExternalUser("radius", id.Issuer, id.Subject, "", id.Provision)
		if e == nil {
			e = d.RADIUS.BindVerifiedUser(user.ID, id.Subject, id.Revision)
		}
		if e != nil {
			radiusError(w, e)
			return
		}
		ticket, e := d.RADIUS.NewPending(user.ID, id.Revision, accesspolicies.SourceIP(r.Context()), user.AuthGeneration)
		if e != nil {
			radiusError(w, e)
			return
		}
		setRadiusCookie(w, r, radiusPendingCookie, radiusCookiePath, ticket, false)
		loginAuditSubject(r, user)
		markLoginAudit(r, "external_verified", "external_identity_verified")
		reply := map[string]any{"radius_primary_verified": true, "expires_at": time.Now().UTC().Add(5 * time.Minute)}
		if !browserLoginRequest(r) {
			reply["pending_token"] = ticket
		}
		writeJSON(w, 202, reply)
	}
	mux.HandleFunc("POST /api/v1/authentication/radius/login", func(w http.ResponseWriter, r *http.Request) {
		if !allowOrigin(w, r) || !reserve(w, r) {
			return
		}
		setNoStore(w)
		if d.Auth.BootstrapRequired() {
			radiusError(w, radiuslogin.ErrDisabled)
			return
		}
		var in struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			radiusError(w, radiuslogin.ErrInvalid)
			return
		}
		attemptedLoginName(r, in.Username)
		out, e := d.RADIUS.StartPrimary(r.Context(), in.Username, in.Password, accesspolicies.SourceIP(r.Context()))
		primaryResult(w, r, out, e)
	})
	mux.HandleFunc("POST /api/v1/authentication/radius/challenge", func(w http.ResponseWriter, r *http.Request) {
		if !allowOrigin(w, r) || !reserve(w, r) {
			return
		}
		setNoStore(w)
		var in struct {
			Token    string `json:"challenge_token"`
			Response string `json:"response"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			radiusError(w, radiuslogin.ErrInvalid)
			return
		}
		ticket, e := selectRadiusTicket(radiusCookie(r, radiusPrimaryCookie), in.Token)
		if e != nil {
			radiusError(w, e)
			return
		}
		out, e := d.RADIUS.AnswerPrimary(r.Context(), ticket, accesspolicies.SourceIP(r.Context()), in.Response)
		primaryResult(w, r, out, e)
	})
	mux.HandleFunc("GET /api/v1/authentication/radius/challenge", func(w http.ResponseWriter, r *http.Request) {
		if !allowOrigin(w, r) {
			return
		}
		setNoStore(w)
		out, e := d.RADIUS.Status(radiusCookie(r, radiusPrimaryCookie), accesspolicies.SourceIP(r.Context()), "primary")
		if e != nil {
			radiusError(w, e)
			return
		}
		writeJSON(w, 200, out)
	})
	mux.HandleFunc("GET /api/v1/authentication/radius/pending", func(w http.ResponseWriter, r *http.Request) {
		if !allowOrigin(w, r) {
			return
		}
		setNoStore(w)
		p, e := d.RADIUS.Pending(radiusCookie(r, radiusPendingCookie), false, accesspolicies.SourceIP(r.Context()))
		if e != nil {
			radiusError(w, e)
			return
		}
		u, ok := d.Auth.ActiveUserByID(p.UserID)
		if !ok {
			radiusError(w, radiuslogin.ErrFlow)
			return
		}
		writeJSON(w, 200, map[string]bool{"active": true, "mfa_required": u.MFAEnabled})
	})
	mux.HandleFunc("POST /api/v1/authentication/radius/complete", func(w http.ResponseWriter, r *http.Request) {
		if !allowOrigin(w, r) || !reserve(w, r) {
			return
		}
		setNoStore(w)
		var in struct {
			Token string `json:"pending_token"`
			OTP   string `json:"otp"`
			Setup string `json:"setup_token"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			radiusError(w, radiuslogin.ErrInvalid)
			return
		}
		ticket, e := selectRadiusTicket(radiusCookie(r, radiusPendingCookie), in.Token)
		if e != nil {
			radiusError(w, e)
			return
		}
		completeExternalBrowserLogin(w, r, d.Auth, radiusBrowserFlow{d.RADIUS, accesspolicies.SourceIP(r.Context())}, "radius", ticket, in.OTP, in.Setup, attempts, false, func() { setRadiusCookie(w, r, radiusPendingCookie, radiusCookiePath, "", false) }, radiusError)
	})
	mux.HandleFunc("DELETE /api/v1/authentication/radius/pending", func(w http.ResponseWriter, r *http.Request) {
		if !allowOrigin(w, r) {
			return
		}
		if p, e := d.RADIUS.Pending(radiusCookie(r, radiusPendingCookie), false, accesspolicies.SourceIP(r.Context())); e == nil {
			d.RADIUS.Consume(radiusCookie(r, radiusPendingCookie), p.Revision, accesspolicies.SourceIP(r.Context()))
		}
		_ = d.RADIUS.Cancel(radiusCookie(r, radiusPrimaryCookie), accesspolicies.SourceIP(r.Context()), "primary")
		setRadiusCookie(w, r, radiusPendingCookie, radiusCookiePath, "", false)
		setRadiusCookie(w, r, radiusPrimaryCookie, radiusCookiePath, "", false)
		w.WriteHeader(204)
	})
	registerRadiusFactorRoutes(mux, d, reserve)
}
func registerRadiusFactorRoutes(mux *http.ServeMux, d Dependencies, reserve func(http.ResponseWriter, *http.Request) bool) {
	mux.HandleFunc("GET "+factorCookiePath+"/pending", func(w http.ResponseWriter, r *http.Request) {
		if !allowOrigin(w, r) {
			return
		}
		setNoStore(w)
		ticket := radiusCookie(r, factorCookie)
		if ticket == "" {
			writeJSON(w, 200, map[string]bool{"active": false})
			return
		}
		status, e := d.RADIUS.Status(ticket, accesspolicies.SourceIP(r.Context()), "factor")
		if e != nil {
			radiusError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"active": status.State == "pending", "status": status})
	})
	mux.HandleFunc("POST "+factorCookiePath+"/complete", func(w http.ResponseWriter, r *http.Request) {
		if !allowOrigin(w, r) || !reserve(w, r) {
			return
		}
		setNoStore(w)
		var in struct {
			Token    string `json:"factor_token"`
			Response string `json:"response"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			radiusError(w, radiuslogin.ErrInvalid)
			return
		}
		ticket, e := selectRadiusTicket(radiusCookie(r, factorCookie), in.Token)
		if e != nil {
			radiusError(w, e)
			return
		}
		verified, status, e := d.RADIUS.VerifyFactor(r.Context(), ticket, accesspolicies.SourceIP(r.Context()), in.Response)
		if e != nil {
			markLoginAudit(r, "failed", "second_factor_rejected")
			radiusError(w, e)
			return
		}
		if verified.Proof == "" {
			markLoginAudit(r, "challenge", "second_factor_required")
			writeJSON(w, 202, map[string]any{"radius_challenge_required": true, "round": status.Round, "expires_at": status.ExpiresAt})
			return
		}
		session, e := d.Auth.ResumeLoginProof(verified.Proof)
		if e == nil && session.User.ID != verified.UserID {
			_ = d.Auth.RevokeToken(session.AccessToken)
			e = radiuslogin.ErrFlow
		}
		if e == nil {
			e = d.Auth.SetSessionSecondaryStamp(session.AccessToken, verified.UserID, verified.Stamp)
		}
		if e != nil {
			if session.AccessToken != "" {
				_ = d.Auth.RevokeToken(session.AccessToken)
			}
			radiusError(w, radiuslogin.ErrFlow)
			return
		}
		setRadiusCookie(w, r, factorCookie, factorCookiePath, "", verified.Secure)
		r = r.WithContext(context.WithValue(r.Context(), factorSourceKey{}, verified.AuthSource))
		loginAuditSubject(r, session.User)
		loginAuditReview(r, "", verified.AuthSource)
		if verified.Browser {
			r.Header.Set(browserSessionHeader, "cookie")
		}
		writeLoginResult(w, r, 200, session)
	})
	mux.HandleFunc("POST "+factorCookiePath+"/cancel", func(w http.ResponseWriter, r *http.Request) {
		if !allowOrigin(w, r) {
			return
		}
		var in struct {
			Token string `json:"factor_token"`
		}
		if r.ContentLength != 0 && decodeRequestJSON(w, r, &in) != nil {
			radiusError(w, radiuslogin.ErrInvalid)
			return
		}
		ticket, e := selectRadiusTicket(radiusCookie(r, factorCookie), in.Token)
		if e == nil {
			_ = d.RADIUS.Cancel(ticket, accesspolicies.SourceIP(r.Context()), "factor")
		}
		setRadiusCookie(w, r, factorCookie, factorCookiePath, "", false)
		setExpiredSessionCookie(w, r)
		markLoginAudit(r, "cancelled", "user_cancelled")
		w.WriteHeader(204)
	})
}
