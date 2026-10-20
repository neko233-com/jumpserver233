package api

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"github.com/neko233-com/jumpserver233/server/internal/core/loginaudit"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
)

type loginAuditKey struct{}
type loginAuditAttempt struct {
	input    loginaudit.Input
	recorded bool
}

func auditedLoginStep(r *http.Request) (method, stage string, ok bool) {
	_, p := identityScopedPath(r.URL.Path)
	switch p {
	case "/api/v1/authentication/auth/", "/api/v1/authentication/bootstrap":
		return "local", "primary", r.Method == "POST"
	case "/api/v1/authentication/mfa/setup/confirm":
		return "local", "mfa", r.Method == "POST"
	case "/api/v1/authentication/expire-session/":
		return "unknown", "logout", r.Method == "POST"
	case "/api/v1/authentication/login-review/complete":
		return "unknown", "session", r.Method == "POST"
	case "/api/v1/authentication/login-review/cancel":
		return "unknown", "review", r.Method == "POST"
	case "/api/v1/authentication/factor/complete", "/api/v1/authentication/factor/cancel", "/api/v1/authentication/radius/challenge":
		return "radius", "mfa", r.Method == "POST"
	case "/api/v1/authentication/sms/complete", "/api/v1/authentication/sms/cancel", "/api/v1/authentication/sms/bind", "/api/v1/authentication/sms/resend":
		return "unknown", "mfa", r.Method == "POST"
	}
	for _, source := range []string{"ldap", "oidc", "saml", "cas", "passkey", "radius", "wecom", "dingtalk", "feishu"} {
		prefix := "/api/v1/authentication/" + source + "/"
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		step := strings.TrimPrefix(p, prefix)
		if (step == "login" || step == "verify") && r.Method == "POST" {
			return source, "primary", true
		}
		if step == "complete" && r.Method == "POST" {
			return source, "mfa", true
		}
		if step == "pending" && r.Method == "DELETE" {
			return source, "external", true
		}
		if (step == "start" && r.Method == "GET" || step == "start" && source == "passkey" && r.Method == "POST") || step == "callback" && r.Method == "GET" || step == "acs" && r.Method == "POST" {
			return source, "external", true
		}
		if source == "saml" && step == "finalize" && r.Method == "GET" {
			return source, "external", true
		}
	}
	return "", "", false
}
func auditAttempt(r *http.Request) *loginAuditAttempt {
	a, _ := r.Context().Value(loginAuditKey{}).(*loginAuditAttempt)
	return a
}
func markLoginAudit(r *http.Request, outcome, reason string) {
	if a := auditAttempt(r); a != nil {
		a.input.Outcome = outcome
		a.input.Reason = reason
	}
}
func attemptedLoginName(r *http.Request, name string) {
	if a := auditAttempt(r); a != nil {
		for _, c := range name {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_@.+-", c)) {
				return
			}
		}
		if len(name) <= 128 {
			a.input.AttemptedName = name
		}
	}
}
func loginAuditSubject(r *http.Request, user coreauth.User) {
	if a := auditAttempt(r); a != nil {
		a.input.UserID = user.ID
		a.input.Username = eventfeed.MetadataText(user.Username, 128)
	}
}
func loginAuditReview(r *http.Request, id, method string) {
	if a := auditAttempt(r); a != nil {
		a.input.ReviewID = id
		if method != "" {
			a.input.Method = method
		}
	}
}
func withLoginAudit(next http.Handler, d Dependencies) http.Handler {
	if d.LoginAudit == nil || d.Auth == nil || d.Tenant {
		return next
	}
	var trusted []netip.Prefix
	for _, raw := range d.TrustedProxies {
		if p, e := netip.ParsePrefix(raw); e == nil {
			trusted = append(trusted, p)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, stage, ok := auditedLoginStep(r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		client := "browser"
		if r.URL.Path == "/api/v1/authentication/auth/" || r.URL.Path == "/api/v1/authentication/bootstrap" || r.URL.Path == "/api/v1/authentication/mfa/setup/confirm" || strings.HasPrefix(r.URL.Path, radiusCookiePath+"/") || strings.HasPrefix(r.URL.Path, factorCookiePath+"/") {
			if !browserLoginRequest(r) {
				client = "api"
			}
		}
		a := &loginAuditAttempt{input: loginaudit.Input{Method: method, Stage: stage, Client: client, SourceIP: requestSourceIP(r, trusted)}}
		r = r.WithContext(context.WithValue(r.Context(), loginAuditKey{}, a))
		capture := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(capture, r)
		if a.recorded {
			return
		}
		if a.input.Outcome == "" {
			switch {
			case capture.status == 429:
				a.input.Outcome = "throttled"
				a.input.Reason = "attempt_limit"
			case capture.status == 403:
				a.input.Outcome = "denied"
				a.input.Reason = "origin_rejected"
			case capture.status == 401:
				a.input.Outcome = "failed"
				a.input.Reason = "identity_rejected"
			case capture.status >= 500:
				a.input.Outcome = "service_error"
				a.input.Reason = "authentication_unavailable"
			case capture.status >= 400:
				a.input.Outcome = "invalid_request"
				a.input.Reason = "request_invalid"
			case r.Method == "DELETE" || stage == "logout":
				a.input.Outcome = "cancelled"
				a.input.Reason = "user_cancelled"
			default:
				a.input.Outcome = "service_error"
				a.input.Reason = "authentication_unavailable"
			}
		}
		if _, e := d.LoginAudit.Append(a.input); e != nil {
			slog.Warn("platform login audit unavailable")
		}
	})
}

// Commit the successful grant before a session cookie or token can leave the
// server. An audit failure revokes the newly created session.
func commitLoginAudit(w http.ResponseWriter, r *http.Request, session coreauth.LoginSession) bool {
	d := policyDependencies(r)
	if d.LoginAudit == nil {
		return true
	}
	a := auditAttempt(r)
	in := loginaudit.Input{Method: loginAuthSource(r, session.User), SourceIP: accesspolicies.SourceIP(r.Context()), Client: "unknown"}
	if a != nil {
		in = a.input
		a.recorded = true
	}
	in.UserID = session.User.ID
	in.Username = eventfeed.MetadataText(session.User.Username, 128)
	in.Outcome = "succeeded"
	in.Stage = "session"
	in.Reason = "session_issued"
	if in.Method == "unknown" || in.Method == "local" {
		in.Method = loginAuthSource(r, session.User)
	}
	if in.SourceIP == "" {
		in.SourceIP = "unknown"
	}
	if _, e := d.LoginAudit.Append(in); e != nil {
		_ = d.Auth.RevokeToken(session.AccessToken)
		setExpiredSessionCookie(w, r)
		setNoStore(w)
		writeJSON(w, 503, map[string]string{"error_code": "login_audit_unavailable", "detail": "platform login audit unavailable"})
		return false
	}
	return true
}
