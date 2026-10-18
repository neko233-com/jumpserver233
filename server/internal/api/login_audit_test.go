package api

import (
	"context"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/ldaplogin"
	"github.com/neko233-com/jumpserver233/server/internal/core/loginaudit"
	"github.com/neko233-com/jumpserver233/server/internal/core/notifications"
	"github.com/neko233-com/jumpserver233/server/internal/core/oidclogin"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/testsupport/ldapserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func loginAuditEnv(t *testing.T) *policyTestEnv {
	t.Helper()
	e := reviewEnv(t)
	var err error
	e.d.LoginAudit, err = loginaudit.Open(filepath.Join(t.TempDir(), "audit"), make([]byte, 32), nil)
	require.NoError(t, err)
	t.Cleanup(e.d.LoginAudit.Close)
	e.d.Notifications, err = notifications.Open(filepath.Join(t.TempDir(), "global-notifications"), make([]byte, 32), nil)
	require.NoError(t, err)
	t.Cleanup(e.d.Notifications.Close)
	e.d.PlatformNotifications = true
	e.router = NewRouter("test", e.d)
	return e
}

func isolatedLoginAudit(t *testing.T) *loginaudit.Store {
	t.Helper()
	s, e := loginaudit.Open(t.TempDir(), make([]byte, 32), nil)
	require.NoError(t, e)
	t.Cleanup(s.Close)
	return s
}
func assertGrantedAudit(t *testing.T, s *loginaudit.Store, method string) {
	t.Helper()
	p, e := s.List(loginaudit.Filter{Limit: 200}, nil)
	require.NoError(t, e)
	require.NotEmpty(t, p.Results)
	assert.Equal(t, "succeeded", p.Results[0].Outcome)
	assert.Equal(t, method, p.Results[0].Method)
	assert.Equal(t, "session", p.Results[0].Stage)
	totals, e := s.Summary(loginaudit.Filter{}, nil)
	require.NoError(t, e)
	assert.Equal(t, 1, totals.Succeeded)
}
func TestLoginAuditAllNativeAuthenticationMethods(t *testing.T) {
	t.Run("ldap", func(t *testing.T) {
		e := ldapEnv(t)
		s := isolatedLoginAudit(t)
		e.router = NewRouter("test", Dependencies{Auth: e.auth, LDAP: e.ldap, LoginAudit: s})
		cfg := e.ldap.Snapshot().Config
		cfg.ProvisionNew = true
		_, err := e.ldap.Save(ldaplogin.Input{Config: cfg}, "admin", "admin")
		require.NoError(t, err)
		done := oidcSend(t, e.router, "POST", "/api/v1/authentication/ldap/login", `{"username":"directory.user","password":"`+ldapserver.Password+`"}`)
		require.Equal(t, 200, done.Code)
		assertGrantedAudit(t, s, "ldap")
	})
	t.Run("oidc", func(t *testing.T) {
		e := oidcEnv(t)
		s := isolatedLoginAudit(t)
		e.router = NewRouter("test", Dependencies{Auth: e.auth, OIDC: e.oidc, LoginAudit: s})
		cfg := e.oidc.Snapshot().Config
		cfg.ProvisionNew = true
		_, err := e.oidc.Save(oidclogin.Input{Config: cfg}, "admin", "admin")
		require.NoError(t, err)
		callback := oidcCallback(t, e)
		done := oidcSend(t, e.router, "POST", "/api/v1/authentication/oidc/complete", "{}", cookieNamed(t, callback, oidcPendingCookie))
		require.Equal(t, 200, done.Code)
		assertGrantedAudit(t, s, "oidc")
	})
	t.Run("saml", func(t *testing.T) {
		e := samlEnv(t)
		s := isolatedLoginAudit(t)
		e.router = NewRouter("test", Dependencies{Auth: e.auth, SAML: e.saml, LoginAudit: s})
		cfg := e.saml.Snapshot()
		cfg.ProvisionNew = true
		_, err := e.saml.Save(cfg, "admin", "admin")
		require.NoError(t, err)
		callback := samlCallback(t, e)
		done := oidcSend(t, e.router, "POST", "/api/v1/authentication/saml/complete", "{}", cookieNamed(t, callback, samlPendingCookie))
		require.Equal(t, 200, done.Code)
		assertGrantedAudit(t, s, "saml")
	})
	t.Run("cas", func(t *testing.T) {
		e := casEnv(t)
		s := isolatedLoginAudit(t)
		e.router = NewRouter("test", Dependencies{Auth: e.auth, CAS: e.cas, LoginAudit: s})
		cfg := e.cas.Snapshot()
		cfg.ProvisionNew = true
		_, err := e.cas.Save(cfg, "admin", "admin")
		require.NoError(t, err)
		callback := casCallback(t, e)
		done := oidcSend(t, e.router, "POST", "/api/v1/authentication/cas/complete", "{}", cookieNamed(t, callback, casPendingCookie))
		require.Equal(t, 200, done.Code)
		assertGrantedAudit(t, s, "cas")
	})
	t.Run("passkey", func(t *testing.T) {
		e := passkeyEnv(t)
		s := isolatedLoginAudit(t)
		e.router = NewRouter("test", Dependencies{Auth: e.auth, Passkeys: e.keys, LoginAudit: s, PublicURL: "https://console.example.invalid"})
		_, a := registerPasskey(t, e, e.admin)
		pending := pendingPasskey(t, e, a)
		done := passkeySend(t, e.router, "POST", passkeyCookiePath+"/complete", map[string]string{}, "", pending)
		require.Equal(t, 200, done.Code)
		assertGrantedAudit(t, s, "passkey")
	})
}
func TestLoginAuditMFAChallengeOnlyGrantsAfterSecondFactor(t *testing.T) {
	e := loginAuditEnv(t)
	enrollment, err := e.d.Auth.StartMFAEnrollment(e.operator.ID)
	require.NoError(t, err)
	_, err = e.d.Auth.ConfirmMFAEnrollment(e.operator.ID, apiTOTPCode(t, enrollment.Secret, uint64(time.Now().Unix()/30)))
	require.NoError(t, err)
	challenge := e.send(t, "POST", "/api/v1/authentication/auth/", map[string]string{"username": e.operator.Username, "password": "synthetic-policy-password"}, "", "192.0.2.5:4567")
	require.Equal(t, 401, challenge.Code)
	row := loginAuditRows(t, e)[0]
	assert.Equal(t, "challenge", row.Outcome)
	assert.Equal(t, "second_factor_required", row.Reason)
	totals, err := e.d.LoginAudit.Summary(loginaudit.Filter{}, nil)
	require.NoError(t, err)
	assert.Zero(t, totals.Succeeded)
	done := e.send(t, "POST", "/api/v1/authentication/auth/", map[string]string{"username": e.operator.Username, "password": "synthetic-policy-password", "otp": apiTOTPCode(t, enrollment.Secret, uint64(time.Now().Unix()/30)+1)}, "", "192.0.2.5:4567")
	require.Equal(t, 200, done.Code)
	assertGrantedAudit(t, e.d.LoginAudit, "local")
}

func TestLoginAuditCSVFormulaSafetyAndExportAuditFailure(t *testing.T) {
	e := loginAuditEnv(t)
	_, err := e.d.LoginAudit.Append(loginaudit.Input{Method: "local", Stage: "session", Outcome: "succeeded", UserID: e.operator.ID, Username: "=SYNTHETIC()", SourceIP: "192.0.2.5"})
	require.NoError(t, err)
	out := e.send(t, "GET", "/api/v1/audits/logins/export.csv", nil, e.token, "192.0.2.5:4567")
	require.Equal(t, 200, out.Code)
	assert.Contains(t, out.Body.String(), "'=SYNTHETIC()")
	assert.Equal(t, "exported", loginAuditRows(t, e)[0].Outcome)
	e.d.LoginAudit.Close()
	out = e.send(t, "GET", "/api/v1/audits/logins/export.csv", nil, e.token, "192.0.2.5:4567")
	assert.Equal(t, 503, out.Code)
	assert.NotContains(t, out.Body.String(), "SYNTHETIC")
}
func TestPlatformNotificationAudienceRevocationAndReviewState(t *testing.T) {
	e := loginAuditEnv(t)
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "global auditor", Permissions: []string{"audit.logins.view_all"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	row, err := e.d.LoginAudit.Append(loginaudit.Input{Method: "local", Stage: "session", Outcome: "succeeded", UserID: e.admin.ID, Username: e.admin.Username, SourceIP: "192.0.2.5"})
	require.NoError(t, err)
	source := notifications.Source{ID: row.ID, Action: row.Notification}
	allowed, err := platformLoginNotificationAllowed(context.Background(), e.d, e.operator.ID, source)
	require.NoError(t, err)
	assert.True(t, allowed)
	_, err = e.d.RBAC.SaveRole(role.ID, rbac.RoleInput{Name: role.Name, Revision: role.Revision, Permissions: []string{}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	allowed, err = platformLoginNotificationAllowed(context.Background(), e.d, e.operator.ID, source)
	require.NoError(t, err)
	assert.False(t, allowed)
	reviewRule(t, e, "review")
	id, _, _ := startReview(t, e, false)
	batch, err := loginaudit.ReviewSource(e.d.LoginReviews)(context.Background(), "")
	require.NoError(t, err)
	require.NoError(t, e.d.LoginAudit.Import(batch))
	pending := loginAuditRows(t, e)[0]
	source = notifications.Source{ID: pending.ID, Action: pending.Notification}
	allowed, err = platformLoginNotificationAllowed(context.Background(), e.d, e.admin.ID, source)
	require.NoError(t, err)
	assert.True(t, allowed)
	require.Equal(t, 204, e.send(t, "POST", "/api/v1/login-reviews/"+id+"/approve", nil, e.adminToken, "192.0.2.6:1234").Code)
	allowed, err = platformLoginNotificationAllowed(context.Background(), e.d, e.admin.ID, source)
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestPlatformLoginAuditDoesNotInheritOrganizationRoles(t *testing.T) {
	e := loginAuditEnv(t)
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "organization-only audit grant", Permissions: []string{"audit.logins.view_all", "notifications.manage"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	e.d.GlobalRBAC, err = rbac.Open(filepath.Join(t.TempDir(), "global-roles.json"), nil)
	require.NoError(t, err)
	e.router = NewRouter("test", e.d)
	assert.Equal(t, 403, e.send(t, "GET", "/api/v1/audits/logins?scope=all", nil, e.token, "192.0.2.5:4567").Code)
	assert.Equal(t, 403, e.send(t, "GET", "/api/v1/platform-notifications/settings", nil, e.token, "192.0.2.5:4567").Code)
}
func loginAuditRows(t *testing.T, e *policyTestEnv) []loginaudit.Record {
	t.Helper()
	out, err := e.d.LoginAudit.List(loginaudit.Filter{Limit: 200}, nil)
	require.NoError(t, err)
	return out.Results
}
func TestLoginAuditSuccessChallengeFailureAndGlobalPermission(t *testing.T) {
	e := loginAuditEnv(t)
	success := e.send(t, "POST", "/api/v1/authentication/auth/", map[string]string{"username": e.operator.Username, "password": "synthetic-policy-password"}, "", "192.0.2.5:4567")
	require.Equal(t, 200, success.Code)
	bad := e.send(t, "POST", "/api/v1/authentication/auth/", map[string]string{"username": e.operator.Username, "password": "synthetic-wrong-password"}, "", "192.0.2.6:4567")
	require.Equal(t, 401, bad.Code)
	rows := loginAuditRows(t, e)
	require.Len(t, rows, 2)
	assert.Equal(t, "failed", rows[0].Outcome)
	assert.Empty(t, rows[0].UserID)
	assert.Equal(t, e.operator.ID, rows[1].UserID)
	assert.Equal(t, "session", rows[1].Stage)
	raw, err := json.Marshal(rows)
	require.NoError(t, err)
	assert.False(t, strings.Contains(string(raw), "synthetic-policy-password"), "credential escaped metadata")
	mine := e.send(t, "GET", "/api/v1/audits/logins", nil, e.token, "192.0.2.5:4567")
	require.Equal(t, 200, mine.Code)
	var own loginaudit.Page
	require.NoError(t, json.Unmarshal(mine.Body.Bytes(), &own))
	assert.Equal(t, 1, own.Total)
	assert.Equal(t, 403, e.send(t, "GET", "/api/v1/audits/logins?scope=all", nil, e.token, "192.0.2.5:4567").Code)
	assert.Equal(t, 404, e.send(t, "GET", "/api/v1/audits/logins/"+rows[0].ID, nil, e.token, "192.0.2.5:4567").Code)
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "Login audit reader", Permissions: []string{"audit.logins.view_all"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 200, e.send(t, "GET", "/api/v1/audits/logins?scope=all", nil, e.token, "192.0.2.5:4567").Code)
	assert.Equal(t, 403, e.send(t, "GET", "/api/v1/audits/logins/export.csv?scope=all", nil, e.token, "192.0.2.5:4567").Code)
	_, err = e.d.RBAC.SaveRole(role.ID, rbac.RoleInput{Name: role.Name, Revision: role.Revision, Permissions: []string{}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 403, e.send(t, "GET", "/api/v1/audits/logins?scope=all", nil, e.token, "192.0.2.5:4567").Code)
	assert.NotContains(t, rbac.OrganizationCatalog(), "audit.logins.view_all")
}
func TestLoginAuditReviewDoesNotClaimSessionBeforeCompletion(t *testing.T) {
	e := loginAuditEnv(t)
	reviewRule(t, e, "review")
	id, ticket, _ := startReview(t, e, false)
	rows := loginAuditRows(t, e)
	require.Len(t, rows, 1)
	assert.Equal(t, "review_pending", rows[0].Outcome)
	assert.Equal(t, id, rows[0].ReviewID)
	batch, err := loginaudit.ReviewSource(e.d.LoginReviews)(context.Background(), "")
	require.NoError(t, err)
	require.NoError(t, e.d.LoginAudit.Import(batch))
	assert.Equal(t, 204, e.send(t, "POST", "/api/v1/login-reviews/"+id+"/approve", nil, e.adminToken, "192.0.2.6:1234").Code)
	for _, r := range loginAuditRows(t, e) {
		assert.NotEqual(t, "succeeded", r.Outcome)
	}
	out := e.send(t, "POST", reviewCookiePath+"/complete", map[string]string{"review_token": ticket}, "", "192.0.2.5:4567")
	require.Equal(t, 200, out.Code)
	rows = loginAuditRows(t, e)
	assert.Equal(t, "succeeded", rows[0].Outcome)
	assert.Equal(t, id, rows[0].ReviewID)
}
func TestLoginAuditUnavailableRevokesGrantAndNeverSendsToken(t *testing.T) {
	e := loginAuditEnv(t)
	s, err := e.d.Auth.Authenticate(e.operator.Username, "synthetic-policy-password")
	require.NoError(t, err)
	e.d.LoginAudit.Close()
	r := httptest.NewRequest("POST", "/api/v1/authentication/auth/", nil)
	recorder := httptest.NewRecorder()
	h := withAccessPolicies(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { writeLoginResult(w, r, 200, s) }), e.d)
	h.ServeHTTP(recorder, r)
	assert.Equal(t, 503, recorder.Code)
	_, valid := e.d.Auth.ValidateToken(s.AccessToken)
	assert.False(t, valid)
	assert.False(t, strings.Contains(recorder.Body.String(), s.AccessToken), "session token escaped failed audit")
	for _, c := range recorder.Result().Cookies() {
		if c.Name == sessionCookieName {
			assert.Less(t, c.MaxAge, 0)
		}
	}
}
func TestLoginAuditTrustedSourcePolicyAndNotificationIsolation(t *testing.T) {
	e := loginAuditEnv(t)
	e.d.TrustedProxies = []string{"10.0.0.0/8"}
	e.router = NewRouter("test", e.d)
	e.rule(t, accesspolicies.Login, "", "203.0.113.0/24")
	denied := e.send(t, "POST", "/api/v1/authentication/auth/", map[string]string{"username": e.operator.Username, "password": "synthetic-policy-password"}, "", "10.0.0.2:1234", map[string]string{"X-Forwarded-For": "203.0.113.9"})
	require.Equal(t, 403, denied.Code)
	r := loginAuditRows(t, e)[0]
	assert.Equal(t, "203.0.113.9", r.SourceIP)
	assert.Equal(t, "denied", r.Outcome)
	assert.Equal(t, "source_policy", r.Reason)
	// The same forged header from an untrusted peer cannot change the origin.
	success := e.send(t, "POST", "/api/v1/authentication/auth/", map[string]string{"username": e.operator.Username, "password": "synthetic-policy-password"}, "", "192.0.2.5:1234", map[string]string{"X-Forwarded-For": "203.0.113.9"})
	require.Equal(t, 200, success.Code)
	e.d.Notifications.Tick()
	inbox := e.send(t, "GET", "/api/v1/platform-notifications/inbox", nil, e.token, "192.0.2.5:1234")
	require.Equal(t, 200, inbox.Code)
	assert.Contains(t, inbox.Body.String(), "platform_login_succeeded")
	assert.NotContains(t, inbox.Body.String(), "192.0.2.5")
	assert.Equal(t, 404, e.send(t, "GET", "/api/v1/notifications/inbox", nil, e.token, "192.0.2.5:1234").Code)
}
