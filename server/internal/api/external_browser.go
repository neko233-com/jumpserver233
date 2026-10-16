package api

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strconv"
	"time"

	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/logintickets"
)

type externalBrowserFlow interface {
	Pending(string, bool) (logintickets.Ticket, error)
	SetSetup(string, string) error
	Consume(string, int) bool
}

// LDAP and CAS use the same browser-bound local MFA/session completion path.
func completeExternalBrowserLogin(w http.ResponseWriter, r *http.Request, auth *coreauth.Service, flow externalBrowserFlow, source, ticket, otp, setupToken string, failures *loginFailures, secure bool, clear func(), writeError func(http.ResponseWriter, error)) {
	p, e := flow.Pending(ticket, true)
	if e != nil {
		writeError(w, e)
		return
	}
	user, ok := auth.UserByID(p.UserID)
	if !ok || (source != "passkey" && user.Source != source) {
		writeError(w, logintickets.ErrTicket)
		return
	}
	key := "mfa:" + p.UserID
	if retry, ok := failures.reserve(key, time.Now()); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		writeJSON(w, 429, map[string]string{"detail": "external second-factor attempt limit reached"})
		return
	}
	var session coreauth.LoginSession
	if setupToken != "" {
		if p.SetupToken == "" || subtle.ConstantTimeCompare([]byte(p.SetupToken), []byte(setupToken)) != 1 {
			failures.failed(key, time.Now())
			writeError(w, logintickets.ErrTicket)
			return
		}
		if source == "passkey" {
			session, e = auth.ConfirmPasskeyMFASetupChallenge(setupToken, otp, p.UserID, p.CredentialID)
		} else {
			session, e = auth.ConfirmMFASetupChallenge(setupToken, otp, p.UserID)
		}
	} else {
		var setup *coreauth.MFASetupChallenge
		if source == "passkey" {
			session, setup, e = auth.AuthenticatePasskeyUser(p.UserID, p.CredentialID, otp)
		} else {
			session, setup, e = auth.AuthenticateExternalUser(p.UserID, source, otp)
		}
		if e == nil && setup != nil {
			if flow.SetSetup(ticket, setup.Token) != nil {
				writeError(w, logintickets.ErrTicket)
				return
			}
			writeJSON(w, 401, map[string]any{"mfa_setup_required": true, "setup_token": setup.Token, "enrollment": setup.Enrollment})
			return
		}
	}
	if errors.Is(e, coreauth.ErrOTPRequired) {
		writeJSON(w, 401, map[string]bool{"mfa_required": true})
		return
	}
	if e != nil {
		if errors.Is(e, coreauth.ErrInvalidOTP) || errors.Is(e, coreauth.ErrInvalidCredentials) || errors.Is(e, coreauth.ErrMFASetupChallenge) {
			failures.failed(key, time.Now())
		}
		writeError(w, e)
		return
	}
	if session.User.ID != p.UserID || session.User.Source != user.Source || !flow.Consume(ticket, p.Revision) {
		_ = auth.RevokeToken(session.AccessToken)
		writeError(w, logintickets.ErrTicket)
		return
	}
	failures.succeeded(key)
	clear()
	if !setLoginSession(w, r, session, secure) {
		return
	}
	writeJSON(w, 200, map[string]any{"browser_session": true, "user": session.User, "expires_at": session.ExpiresAt})
}
