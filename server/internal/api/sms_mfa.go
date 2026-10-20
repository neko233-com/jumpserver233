package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/smsmfa"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
)

const smsCookie = "jms_sms_factor"
const smsPath = "/api/v1/authentication/sms"

func smsError(w http.ResponseWriter, e error) {
	status, code := 503, "sms_unavailable"
	switch {
	case errors.Is(e, smsmfa.ErrInvalid):
		status, code = 400, "sms_invalid"
	case errors.Is(e, smsmfa.ErrConflict), errors.Is(e, coreauth.ErrUserRevision):
		status, code = 409, "sms_conflict"
	case errors.Is(e, smsmfa.ErrFlow), errors.Is(e, smsmfa.ErrRejected), errors.Is(e, coreauth.ErrInvalidCredentials), errors.Is(e, coreauth.ErrInvalidOTP), errors.Is(e, coreauth.ErrInvalidLoginProof), errors.Is(e, coreauth.ErrExternalReauthRequired):
		status, code = 401, "sms_rejected"
	case errors.Is(e, smsmfa.ErrDisabled):
		status, code = 403, "sms_disabled"
	case errors.Is(e, smsmfa.ErrRate):
		status, code = 429, "sms_rate_limit"
		w.Header().Set("Retry-After", "60")
	case errors.Is(e, smsmfa.ErrCapacity):
		status, code = 429, "sms_capacity"
	case errors.Is(e, workgate.ErrDraining):
		status, code = 503, "sms_unavailable"
	}
	setNoStore(w)
	writeJSON(w, status, map[string]string{"error_code": code})
}
func smsPrivileged(d Dependencies, u coreauth.User) bool {
	return u.Role == coreauth.RoleAdmin || len(globalLoginPermissions(d, u).Permissions) > 0
}
func smsRequired(d Dependencies, u coreauth.User) bool {
	return d.SMSMFA != nil && d.SMSMFA.Required(u, smsPrivileged(d, u))
}
func smsProofCurrent(d Dependencies, proof string, u coreauth.User) bool {
	if !smsRequired(d, u) {
		return true
	}
	stamp, e := d.Auth.LoginProofSMSStamp(proof, u.ID)
	return e == nil && d.SMSMFA.ValidStamp(u.ID, stamp)
}
func setSMSCookie(w http.ResponseWriter, r *http.Request, ticket string, secure bool) {
	age := 300
	if ticket == "" {
		age = -1
	}
	http.SetCookie(w, &http.Cookie{Name: smsCookie, Value: ticket, Path: smsPath, MaxAge: age, HttpOnly: true, Secure: secure || secureSessionCookie(r), SameSite: http.SameSiteLaxMode})
}
func smsTicket(r *http.Request, body string) (string, error) {
	cookie := ""
	if c, e := r.Cookie(smsCookie); e == nil {
		cookie = c.Value
	}
	if len(cookie) > 128 || len(body) > 128 || cookie != "" && body != "" && cookie != body {
		return "", smsmfa.ErrFlow
	}
	if body != "" {
		return body, nil
	}
	return cookie, nil
}
func prepareSMSFactor(w http.ResponseWriter, r *http.Request, session coreauth.LoginSession, secure bool) bool {
	d := policyDependencies(r)
	if !smsRequired(d, session.User) {
		return true
	}
	if d.SMSMFA.ValidStamp(session.User.ID, d.Auth.SessionSMSStamp(session.AccessToken)) {
		return true
	}
	proof, e := d.Auth.QuarantineLogin(session.AccessToken)
	if e != nil {
		_ = d.Auth.RevokeToken(session.AccessToken)
		smsError(w, e)
		return false
	}
	browser := browserLoginRequest(r)
	ticket, status, e := d.SMSMFA.BeginLogin(r.Context(), smsmfa.BeginInput{UserID: session.User.ID, Proof: proof.Proof, AuthSource: proof.AuthSource, SourceIP: accesspolicies.SourceIP(r.Context()), ExpiresAt: proof.ExpiresAt, Browser: browser, Secure: secure || secureSessionCookie(r)})
	if e != nil {
		markLoginAudit(r, "failed", "authentication_unavailable")
		smsError(w, e)
		return false
	}
	clearReviewCookie(w, r)
	setExpiredSessionCookie(w, r)
	setSMSCookie(w, r, ticket, secure)
	markLoginAudit(r, "challenge", "second_factor_required")
	out := map[string]any{"sms_factor_required": true, "factor_required": true, "factor": "sms", "expires_at": status.ExpiresAt, "status": status}
	if !browser {
		out["factor_token"] = ticket
	}
	writeJSON(w, 202, out)
	return false
}
func registerSMSMFARoutes(mux *http.ServeMux, d Dependencies) {
	protect := func(h http.HandlerFunc) http.Handler {
		return protectAdminAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			setNoStore(w)
			if !hasPermission(r, "security.manage") {
				writeJSON(w, 403, map[string]string{"error_code": "sms_denied"})
				return
			}
			h(w, r)
		}), d.AdminToken, d.Auth)
	}
	settings := "/api/v1/settings/security/sms-mfa"
	mux.Handle("GET "+settings, protect(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, d.SMSMFA.Snapshot()) }))
	mux.Handle("GET "+settings+"/audit", protect(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, d.SMSMFA.Audit()) }))
	mux.Handle("PUT "+settings, protect(func(w http.ResponseWriter, r *http.Request) {
		var in smsmfa.Input
		if decodeRequestJSON(w, r, &in) != nil {
			smsError(w, smsmfa.ErrInvalid)
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		release := lockCalendarAccess(d, d.AccessMu)
		defer release()
		out, e := d.SMSMFA.Save(in, u.ID)
		if e != nil {
			smsError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	authenticated := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	mux.Handle("GET /api/v1/users/me/sms-mfa", authenticated(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		u, ok := PrincipalFromContext(r.Context())
		if !ok {
			smsError(w, smsmfa.ErrFlow)
			return
		}
		phone, _, e := d.Auth.SMSContact(u.ID)
		if e != nil {
			smsError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"available": d.SMSMFA.Available(), "enabled": u.SMSMFAEnabled, "forced": d.SMSMFA.Forced(u, smsPrivileged(d, u)), "masked_phone": smsmfa.MaskedPhone(phone)})
	}))
	attempts := newLoginFailures()
	reserve := func(w http.ResponseWriter, r *http.Request) bool {
		host := remoteHost(r.RemoteAddr)
		if retry, ok := attempts.reserve(host, time.Now()); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			smsError(w, smsmfa.ErrRate)
			return false
		}
		return true
	}
	mux.Handle("POST /api/v1/users/me/sms-mfa/enroll", authenticated(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !allowOrigin(w, r) || !reserve(w, r) {
			return
		}
		u, ok := PrincipalFromContext(r.Context())
		if !ok {
			smsError(w, smsmfa.ErrFlow)
			return
		}
		var in struct{ Phone, Password, OTP string }
		if decodeRequestJSON(w, r, &in) != nil {
			smsError(w, smsmfa.ErrInvalid)
			return
		}
		if in.Phone == "" && d.SMSMFA.Forced(u, smsPrivileged(d, u)) {
			smsError(w, smsmfa.ErrDisabled)
			return
		}
		token := requestSessionToken(r)
		if u.SMSMFAEnabled && !d.SMSMFA.ValidStamp(u.ID, d.Auth.SessionSMSStamp(token)) {
			smsError(w, smsmfa.ErrRejected)
			return
		}
		verified, stamp, e := d.Auth.VerifySMSManagement(u.ID, in.Password, in.OTP, token)
		if e != nil {
			attempts.failed(remoteHost(r.RemoteAddr), time.Now())
			smsError(w, e)
			return
		}
		ticket, status, e := d.SMSMFA.BeginBinding(r.Context(), verified, stamp, in.Phone, accesspolicies.SourceIP(r.Context()), secureSessionCookie(r))
		if e != nil {
			smsError(w, e)
			return
		}
		setSMSCookie(w, r, ticket, secureSessionCookie(r))
		if browserLoginRequest(r) {
			writeJSON(w, 202, status)
		} else {
			writeJSON(w, 202, map[string]any{"factor_token": ticket, "status": status})
		}
	}))
	pending := func(w http.ResponseWriter, r *http.Request, body string) {
		setNoStore(w)
		if !allowOrigin(w, r) {
			return
		}
		ticket, e := smsTicket(r, body)
		if e != nil {
			smsError(w, e)
			return
		}
		out, e := d.SMSMFA.Status(ticket, accesspolicies.SourceIP(r.Context()))
		if e != nil {
			smsError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}
	mux.HandleFunc("GET "+smsPath+"/pending", func(w http.ResponseWriter, r *http.Request) { pending(w, r, "") })
	mux.HandleFunc("POST "+smsPath+"/pending", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Token string `json:"factor_token"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			smsError(w, smsmfa.ErrInvalid)
			return
		}
		pending(w, r, in.Token)
	})
	for _, action := range []string{"bind", "resend", "complete", "cancel"} {
		mux.HandleFunc("POST "+smsPath+"/"+action, func(w http.ResponseWriter, r *http.Request) {
			setNoStore(w)
			if !allowOrigin(w, r) || !reserve(w, r) {
				return
			}
			var in struct {
				Token     string `json:"factor_token"`
				Phone     string `json:"phone"`
				Code      string `json:"code"`
				RequestID string `json:"request_id"`
			}
			if decodeRequestJSON(w, r, &in) != nil {
				smsError(w, smsmfa.ErrInvalid)
				return
			}
			ticket, e := smsTicket(r, in.Token)
			if e != nil {
				smsError(w, e)
				return
			}
			ip := accesspolicies.SourceIP(r.Context())
			if id, source := d.SMSMFA.AuditSubject(ticket, ip); id != "" {
				if u, ok := d.Auth.ActiveUserByID(id); ok {
					loginAuditSubject(r, u)
				}
				loginAuditReview(r, "", source)
			}
			switch action {
			case "bind", "resend":
				var status smsmfa.Status
				if action == "bind" {
					status, e = d.SMSMFA.BindLoginPhone(r.Context(), ticket, ip, in.Phone, in.RequestID)
				} else {
					if in.Phone != "" || in.Code != "" {
						smsError(w, smsmfa.ErrInvalid)
						return
					}
					status, e = d.SMSMFA.Resend(r.Context(), ticket, ip, in.RequestID)
				}
				if e != nil {
					smsError(w, e)
					return
				}
				writeJSON(w, 200, status)
			case "cancel":
				if in.Phone != "" || in.Code != "" {
					smsError(w, smsmfa.ErrInvalid)
					return
				}
				if e = d.SMSMFA.Cancel(ticket, ip); e != nil {
					smsError(w, e)
					return
				}
				setSMSCookie(w, r, "", false)
				markLoginAudit(r, "cancelled", "user_cancelled")
				w.WriteHeader(204)
			case "complete":
				if in.Phone != "" {
					smsError(w, smsmfa.ErrInvalid)
					return
				}
				var session coreauth.LoginSession
				var user coreauth.User
				var completed smsmfa.Verified
				e = d.SMSMFA.Finish(r.Context(), ticket, ip, in.Code, func(v smsmfa.Verified, stamp func() string) error {
					completed = v
					var e error
					switch v.Kind {
					case "login":
						session, e = d.Auth.ResumeLoginProof(v.Proof)
					case "login-enroll":
						session, e = d.Auth.ResumeLoginProofWithSMSContact(v.Proof, v.Phone, v.Generation)
					case "enroll":
						user, e = d.Auth.SetVerifiedSMSContact(v.UserID, v.Phone, v.Generation)
					case "disable":
						user, e = d.Auth.SetVerifiedSMSContact(v.UserID, "", v.Generation)
					default:
						return smsmfa.ErrFlow
					}
					if e != nil {
						return e
					}
					if session.AccessToken != "" {
						if session.User.ID != v.UserID {
							return smsmfa.ErrFlow
						}
						e = d.Auth.SetSessionSMSStamp(session.AccessToken, v.UserID, stamp())
					}
					return e
				})
				if e != nil {
					if session.AccessToken != "" {
						_ = d.Auth.RevokeToken(session.AccessToken)
					}
					attempts.failed(remoteHost(r.RemoteAddr), time.Now())
					markLoginAudit(r, "failed", "second_factor_rejected")
					smsError(w, e)
					return
				}
				setSMSCookie(w, r, "", completed.Secure)
				attempts.succeeded(remoteHost(r.RemoteAddr))
				if session.AccessToken == "" {
					setExpiredSessionCookie(w, r)
					writeJSON(w, 200, map[string]any{"binding_updated": true, "user": user})
					return
				}
				r = r.WithContext(context.WithValue(r.Context(), factorSourceKey{}, completed.AuthSource))
				if completed.Browser {
					r.Header.Set(browserSessionHeader, "cookie")
				}
				writeLoginResult(w, r, 200, session)
			}
		})
	}
}
