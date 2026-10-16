package api

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/loginreviews"
)

const reviewCookieName = "jms_login_review"
const reviewCookiePath = "/api/v1/authentication/login-review"

func browserLoginRequest(r *http.Request) bool {
	switch r.URL.Path {
	case "/api/v1/authentication/auth/", "/api/v1/authentication/mfa/setup/confirm", "/api/v1/authentication/bootstrap":
		return strings.EqualFold(strings.TrimSpace(r.Header.Get(browserSessionHeader)), "cookie")
	default:
		return true
	}
}
func setReviewCookie(w http.ResponseWriter, r *http.Request, token string, expires time.Time, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: reviewCookieName, Value: token, Path: reviewCookiePath, HttpOnly: true, Secure: secure || secureSessionCookie(r), SameSite: http.SameSiteLaxMode, Expires: expires, MaxAge: max(1, int(time.Until(expires).Seconds()))})
}
func clearReviewCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: reviewCookieName, Value: "", Path: reviewCookiePath, HttpOnly: true, Secure: secureSessionCookie(r), SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0)})
}
func loginAuthSource(r *http.Request, user coreauth.User) string {
	if strings.HasPrefix(r.URL.Path, "/api/v1/authentication/passkey/") {
		return "passkey"
	}
	if user.Source != "" {
		return user.Source
	}
	return "local"
}

// Only freshly authenticated sessions enter this gate. Standing API credentials
// pass deny rules without creating another primary-authentication review.
func prepareNewLogin(w http.ResponseWriter, r *http.Request, session coreauth.LoginSession, secure bool) bool {
	d := policyDependencies(r)
	origin := accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context())}
	decision, e := checkAccessPolicies(d, session.User, coreassets.Asset{}, origin, true)
	fail := func(err error) {
		if d.Auth != nil {
			_ = d.Auth.RevokeToken(session.AccessToken)
		}
		writePolicyDenied(w, err)
	}
	if e != nil || !decision.Allowed {
		fail(e)
		return false
	}
	if decision.Action != "review" && decision.Action != "notify" {
		if _, cookieError := r.Cookie(reviewCookieName); cookieError == nil {
			clearReviewCookie(w, r)
		}
		return true
	}
	if d.LoginReviews == nil || d.Auth == nil {
		fail(loginreviews.ErrInvalid)
		return false
	}
	rule, e := d.AccessPolicies.Get(decision.RuleID)
	if e != nil || rule.Revision != decision.RuleRevision || rule.Action != decision.Action {
		fail(loginreviews.ErrInvalidated)
		return false
	}
	in := loginreviews.Input{UserID: session.User.ID, Username: session.User.Username, SourceIP: origin.SourceIP, AuthSource: loginAuthSource(r, session.User), RuleID: rule.ID, RuleName: rule.Name, RuleRevision: rule.Revision, ApproverIDs: rule.ApproverIDs, ApproverGroupIDs: rule.ApproverGroupIDs, Browser: browserLoginRequest(r), Secure: secure || secureSessionCookie(r)}
	if decision.Action == "notify" {
		if e = d.LoginReviews.Notify(in); e != nil {
			fail(e)
			return false
		}
		if _, cookieError := r.Cookie(reviewCookieName); cookieError == nil {
			clearReviewCookie(w, r)
		}
		return true
	}
	proof, e := d.Auth.QuarantineLogin(session.AccessToken)
	if e != nil {
		fail(e)
		return false
	}
	in.Proof = proof.Proof
	in.ExpiresAt = proof.ExpiresAt
	in.AuthSource = proof.AuthSource
	item, ticket, e := d.LoginReviews.Begin(in)
	if e != nil {
		writeLoginReviewError(w, e)
		return false
	}
	setNoStore(w)
	setExpiredSessionCookie(w, r)
	setReviewCookie(w, r, ticket, item.ExpiresAt, in.Secure)
	result := map[string]any{"login_review_required": true, "review_id": item.ID, "expires_at": item.ExpiresAt}
	if !in.Browser {
		result["review_token"] = ticket
	}
	writeJSON(w, http.StatusAccepted, result)
	return false
}
func checkReviewedLogin(d Dependencies, p loginreviews.Payload) error {
	if d.Auth == nil || d.AccessPolicies == nil || d.Auth.ValidateLoginProof(p.Proof, p.UserID) != nil {
		return loginreviews.ErrInvalidated
	}
	user, ok := d.Auth.UserByID(p.UserID)
	if !ok {
		return loginreviews.ErrInvalidated
	}
	if p.ReviewedBy != "" {
		reviewer, found := d.Auth.UserByID(p.ReviewedBy)
		if p.ReviewedBy == "admin-token" && d.AdminToken != "" {
			reviewer = coreauth.User{ID: p.ReviewedBy, Role: coreauth.RoleAdmin}
			found = true
		}
		var groups []string
		if d.Groups != nil {
			groups = d.Groups.GroupIDsForUser(reviewer.ID)
		}
		if !found || !effectivePermissions(reviewer, d.RBAC, d.Groups).Allows("reviews.platform_login.manage") || !loginreviews.ReviewerAllowed(p.Review, reviewer.ID, groups) {
			return loginreviews.ErrInvalidated
		}
	}
	decision, e := checkAccessPolicies(d, user, coreassets.Asset{}, accesspolicies.Origin{SourceIP: p.SourceIP}, true)
	if e != nil {
		return e
	}
	if !decision.Allowed || decision.Action != "review" || decision.RuleID != p.RuleID || decision.RuleRevision != p.RuleRevision {
		return loginreviews.ErrInvalidated
	}
	return nil
}
func readReviewTicket(w http.ResponseWriter, r *http.Request) (string, bool) {
	var input struct {
		ReviewToken string `json:"review_token"`
	}
	if r.Method != "GET" && r.ContentLength != 0 {
		if decodeRequestJSON(w, r, &input) != nil {
			writeLoginReviewError(w, loginreviews.ErrInvalid)
			return "", false
		}
	}
	cookie := ""
	if value, e := r.Cookie(reviewCookieName); e == nil {
		cookie = value.Value
	}
	if cookie != "" && input.ReviewToken != "" && subtle.ConstantTimeCompare([]byte(cookie), []byte(input.ReviewToken)) != 1 {
		writeLoginReviewError(w, loginreviews.ErrInvalid)
		return "", false
	}
	if input.ReviewToken != "" {
		return input.ReviewToken, true
	}
	return cookie, true
}
func registerPlatformLoginReviewRoutes(mux *http.ServeMux, d Dependencies) {
	status := func(w http.ResponseWriter, r *http.Request) {
		if !allowOrigin(w, r) {
			return
		}
		setNoStore(w)
		ticket, ok := readReviewTicket(w, r)
		if !ok {
			return
		}
		if ticket == "" {
			writeJSON(w, 200, map[string]bool{"active": false})
			return
		}
		item, e := d.LoginReviews.Status(ticket, accesspolicies.SourceIP(r.Context()))
		if errors.Is(e, loginreviews.ErrNotFound) {
			clearReviewCookie(w, r)
			writeJSON(w, 200, map[string]bool{"active": false})
			return
		}
		if e != nil {
			writeLoginReviewError(w, e)
			return
		}
		deadline := item.ExpiresAt
		if item.State == loginreviews.Approved && item.ReviewedAt != nil && item.ReviewedAt.Add(time.Minute).Before(deadline) {
			deadline = item.ReviewedAt.Add(time.Minute)
		}
		writeJSON(w, 200, map[string]any{"active": true, "review_id": item.ID, "state": item.State, "expires_at": deadline})
	}
	mux.HandleFunc("GET "+reviewCookiePath+"/pending", status)
	mux.HandleFunc("POST "+reviewCookiePath+"/status", status)
	mux.HandleFunc("POST "+reviewCookiePath+"/cancel", func(w http.ResponseWriter, r *http.Request) {
		if !allowOrigin(w, r) {
			return
		}
		setNoStore(w)
		ticket, ok := readReviewTicket(w, r)
		if !ok {
			return
		}
		e := d.LoginReviews.Cancel(ticket, accesspolicies.SourceIP(r.Context()), d.Auth.RevokeReviewedSession)
		if e != nil && !errors.Is(e, loginreviews.ErrNotFound) && !errors.Is(e, loginreviews.ErrState) {
			writeLoginReviewError(w, e)
			return
		}
		clearReviewCookie(w, r)
		setExpiredSessionCookie(w, r)
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST "+reviewCookiePath+"/complete", func(w http.ResponseWriter, r *http.Request) {
		if !allowOrigin(w, r) {
			return
		}
		setNoStore(w)
		ticket, ok := readReviewTicket(w, r)
		if !ok {
			return
		}
		result, e := d.LoginReviews.Complete(ticket, accesspolicies.SourceIP(r.Context()), func(p loginreviews.Payload) (coreauth.LoginSession, error) {
			if e := checkReviewedLogin(d, p); e != nil {
				return coreauth.LoginSession{}, e
			}
			session, e := d.Auth.ResumeLoginProof(p.Proof)
			if errors.Is(e, coreauth.ErrInvalidLoginProof) {
				e = loginreviews.ErrInvalidated
			}
			return session, e
		}, d.Auth.RevokeToken)
		if e != nil {
			writeLoginReviewError(w, e)
			return
		}
		clearReviewCookie(w, r)
		writeSessionCookie(w, r, result.Session, result.Secure)
		if result.Browser {
			writeJSON(w, 200, map[string]any{"browser_session": true, "user": result.Session.User, "expires_at": result.Session.ExpiresAt})
		} else {
			writeJSON(w, 200, result.Session)
		}
	})
	protect := func(h http.HandlerFunc) http.Handler { return protectAdminAPI(h, d.AdminToken, d.Auth) }
	pagination := func(w http.ResponseWriter, r *http.Request) (int, int, bool) {
		offset, limit := 0, 50
		var e error
		if v := r.URL.Query().Get("offset"); v != "" {
			offset, e = strconv.Atoi(v)
		}
		if v := r.URL.Query().Get("limit"); v != "" && e == nil {
			limit, e = strconv.Atoi(v)
		}
		if e != nil || offset < 0 || limit < 1 || limit > 200 {
			writeLoginReviewError(w, loginreviews.ErrInvalid)
			return 0, 0, false
		}
		return offset, limit, true
	}
	mux.Handle("GET /api/v1/login-reviews", protect(func(w http.ResponseWriter, r *http.Request) {
		offset, limit, ok := pagination(w, r)
		if !ok {
			return
		}
		filter := r.URL.Query().Get("state")
		valid := filter == ""
		for _, value := range []string{loginreviews.Pending, loginreviews.Approved, loginreviews.Denied, loginreviews.Expired, loginreviews.Cancelled, loginreviews.Consumed, loginreviews.Invalidated, loginreviews.Notified} {
			if filter == value {
				valid = true
			}
		}
		if !valid {
			writeLoginReviewError(w, loginreviews.ErrInvalid)
			return
		}
		items, total, e := d.LoginReviews.List(filter, offset, limit)
		if e != nil {
			writeLoginReviewError(w, e)
			return
		}
		actor, _ := PrincipalFromContext(r.Context())
		var groupIDs []string
		if d.Groups != nil {
			groupIDs = d.Groups.GroupIDsForUser(actor.ID)
		}
		type view struct {
			loginreviews.Review
			CanReview bool `json:"can_review"`
		}
		views := make([]view, 0, len(items))
		for _, item := range items {
			views = append(views, view{Review: item, CanReview: item.State == loginreviews.Pending && loginreviews.ReviewerAllowed(item, actor.ID, groupIDs)})
		}
		writeJSON(w, 200, map[string]any{"results": views, "total": total, "offset": offset, "limit": limit})
	}))
	mux.Handle("GET /api/v1/login-reviews/audit", protect(func(w http.ResponseWriter, r *http.Request) {
		offset, limit, ok := pagination(w, r)
		if !ok {
			return
		}
		items, total := d.LoginReviews.Audit(offset, limit)
		writeJSON(w, 200, map[string]any{"results": items, "total": total})
	}))
	resolve := func(approve bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			actor, _ := PrincipalFromContext(r.Context())
			var groups []string
			if d.Groups != nil {
				groups = d.Groups.GroupIDsForUser(actor.ID)
			}
			e := d.LoginReviews.Resolve(r.PathValue("reviewID"), actor.ID, groups, approve, func(p loginreviews.Payload) error { return checkReviewedLogin(d, p) })
			if e != nil {
				writeLoginReviewError(w, e)
				return
			}
			w.WriteHeader(204)
		}
	}
	mux.Handle("POST /api/v1/login-reviews/{reviewID}/approve", protect(resolve(true)))
	mux.Handle("POST /api/v1/login-reviews/{reviewID}/deny", protect(resolve(false)))
}
func writeLoginReviewError(w http.ResponseWriter, e error) {
	setNoStore(w)
	status := 503
	code := "login_review_unavailable"
	switch {
	case errors.Is(e, loginreviews.ErrInvalid):
		status = 400
		code = "login_review_invalid"
	case errors.Is(e, loginreviews.ErrNotFound):
		status = 404
		code = "login_review_not_found"
	case errors.Is(e, loginreviews.ErrState):
		status = 409
		code = "login_review_state"
	case errors.Is(e, loginreviews.ErrReviewer):
		status = 403
		code = "login_review_reviewer"
	case errors.Is(e, loginreviews.ErrInvalidated):
		status = 409
		code = "login_review_invalidated"
	case errors.Is(e, loginreviews.ErrCapacity):
		status = 429
		code = "login_review_capacity"
	}
	writeJSON(w, status, map[string]string{"detail": "platform login review could not be completed", "code": code})
}
