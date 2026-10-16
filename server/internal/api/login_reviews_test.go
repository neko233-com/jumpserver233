package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/loginreviews"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func reviewEnv(t *testing.T) *policyTestEnv {
	t.Helper()
	e := newPolicyEnv(t)
	var err error
	dir := t.TempDir()
	e.d.Auth, err = coreauth.OpenServiceWithVaultKey(filepath.Join(dir, "users.json"), make([]byte, 32))
	require.NoError(t, err)
	e.admin, err = e.d.Auth.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, err)
	e.operator, err = e.d.Auth.CreateUser("policy.operator", "synthetic-policy-password", coreauth.RoleOperator)
	require.NoError(t, err)
	a, err := e.d.Auth.Authenticate("admin", bootstrapPassword)
	require.NoError(t, err)
	o, err := e.d.Auth.Authenticate(e.operator.Username, "synthetic-policy-password")
	require.NoError(t, err)
	e.adminToken = a.AccessToken
	e.token = o.AccessToken
	e.d.LoginReviews, err = loginreviews.Open(filepath.Join(dir, "reviews.json"), make([]byte, 32), nil)
	require.NoError(t, err)
	e.router = NewRouter("test", e.d)
	return e
}
func reviewRule(t *testing.T, e *policyTestEnv, action string) accesspolicies.Rule {
	t.Helper()
	r, err := e.d.AccessPolicies.Save("", accesspolicies.Input{Name: "platform sign-in", Kind: accesspolicies.Login, UserID: e.operator.ID, Action: action, Enabled: true, Priority: 50, Timezone: "UTC"}, e.admin.ID, nil)
	require.NoError(t, err)
	return r
}
func startReview(t *testing.T, e *policyTestEnv, browser bool) (string, string, *http.Cookie) {
	t.Helper()
	headers := map[string]string{}
	if browser {
		headers[browserSessionHeader] = "cookie"
	}
	w := e.send(t, "POST", "/api/v1/authentication/auth/", map[string]string{"username": e.operator.Username, "password": "synthetic-policy-password"}, "", "192.0.2.5:4567", headers)
	require.Equal(t, 202, w.Code, w.Body.String())
	assert.Contains(t, w.Header().Get("Cache-Control"), "no-store")
	var result struct {
		ID       string `json:"review_id"`
		Token    string `json:"review_token"`
		Required bool   `json:"login_review_required"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.True(t, result.Required)
	assert.NotContains(t, w.Body.String(), "access_token")
	assert.NotContains(t, w.Body.String(), "proof")
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == reviewCookieName {
			cookie = c
		}
		if c.Name == sessionCookieName {
			assert.Less(t, c.MaxAge, 0)
		}
	}
	require.NotNil(t, cookie)
	assert.True(t, cookie.HttpOnly)
	assert.Equal(t, reviewCookiePath, cookie.Path)
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	if browser {
		assert.Empty(t, result.Token)
	} else {
		assert.Equal(t, cookie.Value, result.Token)
	}
	return result.ID, cookie.Value, cookie
}
func TestPlatformLoginReviewBrowserApprovalAndReplay(t *testing.T) {
	e := reviewEnv(t)
	reviewRule(t, e, "review")
	id, ticket, cookie := startReview(t, e, true)
	assert.Equal(t, 401, e.send(t, "GET", "/api/v1/users/me", nil, ticket, "192.0.2.5:4567").Code)
	assert.Equal(t, 403, e.send(t, "POST", "/api/v1/login-reviews/"+id+"/approve", nil, e.token, "192.0.2.5:4567").Code)
	assert.Equal(t, 409, e.send(t, "POST", reviewCookiePath+"/complete", map[string]string{"review_token": ticket}, "", "192.0.2.5:4567").Code)
	require.Equal(t, 204, e.send(t, "POST", "/api/v1/login-reviews/"+id+"/approve", nil, e.adminToken, "192.0.2.6:1").Code)
	assert.Equal(t, 404, e.send(t, "POST", reviewCookiePath+"/complete", map[string]string{"review_token": ticket}, "", "192.0.2.6:1").Code)
	w := e.send(t, "POST", reviewCookiePath+"/complete", map[string]string{}, "", "192.0.2.5:4567", map[string]string{"Cookie": cookie.String()})
	require.Equal(t, 200, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"browser_session":true`)
	assert.NotContains(t, w.Body.String(), "access_token")
	token := ""
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName {
			assert.True(t, c.HttpOnly)
			token = c.Value
		}
	}
	require.NotEmpty(t, token)
	assert.Equal(t, 200, e.send(t, "GET", "/api/v1/users/me", nil, token, "192.0.2.5:4567").Code)
	assert.Equal(t, 409, e.send(t, "POST", reviewCookiePath+"/complete", map[string]string{"review_token": ticket}, "", "192.0.2.5:4567").Code)
	// The original cancellation request may race the completion response.
	assert.Equal(t, 204, e.send(t, "POST", reviewCookiePath+"/cancel", map[string]string{"review_token": ticket}, "", "192.0.2.5:4567").Code)
	assert.Equal(t, 401, e.send(t, "GET", "/api/v1/users/me", nil, token, "192.0.2.5:4567").Code)
	for _, path := range []string{"/api/v1/login-reviews", "/api/v1/login-reviews/audit"} {
		response := e.send(t, "GET", path, nil, e.adminToken, "192.0.2.6:1")
		require.Equal(t, 200, response.Code)
		for _, secret := range []string{ticket, token, "opaque-proof", "ticket_hash", "completed_session_hash"} {
			assert.NotContains(t, response.Body.String(), secret)
		}
	}
}
func TestPlatformLoginReviewCurrentPolicyCredentialsAndReviewer(t *testing.T) {
	for _, change := range []string{"policy revision", "policy disabled", "password", "mfa required", "reviewer permission"} {
		t.Run(change, func(t *testing.T) {
			e := reviewEnv(t)
			rule := reviewRule(t, e, "review")
			id, ticket, _ := startReview(t, e, false)
			reviewerToken := e.adminToken
			reviewerID := e.admin.ID
			var binding rbac.Binding
			if change == "reviewer permission" {
				u, err := e.d.Auth.CreateUser("reviewer", "synthetic-reviewer-password", coreauth.RoleOperator)
				require.NoError(t, err)
				role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "review only", Permissions: []string{"reviews.platform_login.manage"}}, e.admin.ID, e.admin.Username)
				require.NoError(t, err)
				binding, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: u.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
				require.NoError(t, err)
				session, err := e.d.Auth.Authenticate(u.Username, "synthetic-reviewer-password")
				require.NoError(t, err)
				reviewerToken = session.AccessToken
				reviewerID = u.ID
			}
			require.Equal(t, 204, e.send(t, "POST", "/api/v1/login-reviews/"+id+"/approve", nil, reviewerToken, "192.0.2.6:1").Code, reviewerID)
			switch change {
			case "policy revision", "policy disabled":
				in := rule.Input
				in.Revision = rule.Revision
				if change == "policy revision" {
					in.Name = "edited"
				} else {
					in.Enabled = false
				}
				_, err := e.d.AccessPolicies.Save(rule.ID, in, e.admin.ID, nil)
				require.NoError(t, err)
			case "password":
				require.NoError(t, e.d.Auth.ChangePassword(e.operator.ID, e.token, "synthetic-policy-password", "synthetic-new-policy-password"))
			case "mfa required":
				_, err := e.d.Auth.SetMFAEnforcement(coreauth.MFAEnforcementAll)
				require.NoError(t, err)
			case "reviewer permission":
				_, err := e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: binding.SubjectType, SubjectID: binding.SubjectID, RoleIDs: []string{}, Revision: binding.Revision}, e.admin.ID, e.admin.Username)
				require.NoError(t, err)
			}
			w := e.send(t, "POST", reviewCookiePath+"/complete", map[string]string{"review_token": ticket}, "", "192.0.2.5:4567")
			assert.Equal(t, 409, w.Code, w.Body.String())
			assert.Contains(t, w.Body.String(), "login_review_invalidated")
		})
	}
}
func TestPlatformLoginReviewDenyCancelNotifyOriginsAndScope(t *testing.T) {
	e := reviewEnv(t)
	rule := reviewRule(t, e, "review")
	id, ticket, cookie := startReview(t, e, false)
	assert.Equal(t, 403, e.send(t, "POST", reviewCookiePath+"/complete", map[string]string{"review_token": ticket}, "", "192.0.2.5:4567", map[string]string{"Origin": "https://untrusted.invalid"}).Code)
	assert.Equal(t, 400, e.send(t, "POST", reviewCookiePath+"/status", map[string]string{"review_token": strings.Repeat("x", 43)}, "", "192.0.2.5:4567", map[string]string{"Cookie": cookie.String()}).Code)
	require.Equal(t, 204, e.send(t, "POST", "/api/v1/login-reviews/"+id+"/deny", nil, e.adminToken, "192.0.2.6:1").Code)
	assert.Equal(t, 409, e.send(t, "POST", reviewCookiePath+"/complete", map[string]string{"review_token": ticket}, "", "192.0.2.5:4567").Code)
	in := rule.Input
	in.Revision = rule.Revision
	in.Action = "notify"
	_, err := e.d.AccessPolicies.Save(rule.ID, in, e.admin.ID, nil)
	require.NoError(t, err)
	w := e.send(t, "POST", "/api/v1/authentication/auth/", map[string]string{"username": e.operator.Username, "password": "synthetic-policy-password"}, "", "192.0.2.5:4567", map[string]string{browserSessionHeader: "cookie"})
	require.Equal(t, 200, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"browser_session":true`)
	events, total, err := e.d.LoginReviews.List(loginreviews.Notified, 0, 10)
	require.NoError(t, err)
	require.Equal(t, 1, total)
	assert.Equal(t, e.operator.ID, events[0].UserID)
	assert.Equal(t, 403, e.send(t, "GET", "/api/v1/login-reviews", nil, e.token, "192.0.2.5:4567").Code)
}
func TestPlatformLoginReviewSelectedReviewerAndSelfApproval(t *testing.T) {
	e := reviewEnv(t)
	rule := reviewRule(t, e, "review")
	in := rule.Input
	in.Revision = rule.Revision
	in.ApproverIDs = []string{e.operator.ID}
	_, err := e.d.AccessPolicies.Save(rule.ID, in, e.admin.ID, nil)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{"access-reviewer"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	id, ticket, _ := startReview(t, e, false)
	for _, token := range []string{e.token, e.adminToken} {
		w := e.send(t, "POST", "/api/v1/login-reviews/"+id+"/approve", nil, token, "192.0.2.6:1")
		assert.Equal(t, 403, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), "login_review_reviewer")
	}
	assert.Equal(t, 204, e.send(t, "POST", reviewCookiePath+"/cancel", map[string]string{"review_token": ticket}, "", "192.0.2.5:4567").Code)
}

// Every verified external completion uses the same new-session gate.
func TestPlatformLoginReviewExternalCompletionGate(t *testing.T) {
	for _, source := range []string{"oidc", "ldap", "cas", "saml", "passkey"} {
		t.Run(source, func(t *testing.T) {
			e := reviewEnv(t)
			var login coreauth.LoginSession
			var err error
			if source == "passkey" {
				e.d.Auth.SetPasskeyAllowed(func(string, string) bool { return true })
				login, _, err = e.d.Auth.AuthenticatePasskeyUser(e.operator.ID, "synthetic-credential", "")
			} else {
				e.d.Auth.SetExternalSourceAllowed(source, func(string) bool { return true })
				e.operator, err = e.d.Auth.EnsureExternalUser(source, "https://synthetic.invalid", "subject", "external."+source, true)
				require.NoError(t, err)
				login, _, err = e.d.Auth.AuthenticateExternalUser(e.operator.ID, source, "")
			}
			require.NoError(t, err)
			reviewRule(t, e, "review")
			r := httptest.NewRequest("POST", "/api/v1/authentication/"+source+"/complete", nil)
			r.RemoteAddr = "192.0.2.5:4567"
			w := httptest.NewRecorder()
			withAccessPolicies(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { assert.False(t, setLoginSession(w, r, login)) }), e.d).ServeHTTP(w, r)
			assert.Equal(t, 202, w.Code, w.Body.String())
			_, valid := e.d.Auth.ValidateToken(login.AccessToken)
			assert.False(t, valid)
		})
	}
}
