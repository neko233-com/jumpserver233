package api

import (
	"encoding/json"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func resetAPIUser(t *testing.T, e *policyTestEnv, password string) {
	t.Helper()
	w := e.send(t, "POST", "/api/v1/users/"+e.operator.ID+"/password/reset", map[string]any{"revision": 1, "new_password": password}, e.adminToken, "192.0.2.1:1")
	require.Equal(t, 200, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), password)
}
func TestPasswordAPIRestrictedCookieAndReplay(t *testing.T) {
	e := reviewEnv(t)
	resetAPIUser(t, e, "synthetic-reset-password-233")
	w := e.send(t, "POST", "/api/v1/authentication/auth/", map[string]string{"username": e.operator.Username, "password": "synthetic-reset-password-233"}, "", "192.0.2.1:1", map[string]string{browserSessionHeader: "cookie"})
	require.Equal(t, 202, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), "change_token")
	assert.NotContains(t, w.Body.String(), "access_token")
	ticket := ""
	for _, c := range w.Result().Cookies() {
		if c.Name == passwordCookie {
			ticket = c.Value
			assert.True(t, c.HttpOnly)
			assert.Equal(t, passwordPath, c.Path)
		}
		if c.Name == sessionCookieName {
			assert.Less(t, c.MaxAge, 0)
		}
	}
	require.NotEmpty(t, ticket)
	w = e.send(t, "GET", passwordPath+"/pending", nil, "", "192.0.2.1:1", map[string]string{"Cookie": passwordCookie + "=" + ticket})
	require.Equal(t, 200, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), "proof")
	assert.NotContains(t, w.Body.String(), ticket)
	assert.Equal(t, 401, e.send(t, "GET", "/api/v1/users/me", nil, e.token, "192.0.2.1:1").Code)
	for _, test := range []struct {
		remote, token, password string
		status                  int
	}{{"192.0.2.2:1", ticket, "synthetic-new-password-233", 401}, {"192.0.2.1:1", ticket, "short", 400}} {
		w = e.send(t, "POST", passwordPath+"/complete", map[string]string{"change_token": test.token, "new_password": test.password}, "", test.remote)
		assert.Equal(t, test.status, w.Code, w.Body.String())
	}
	w = e.send(t, "POST", passwordPath+"/complete", map[string]string{"change_token": ticket, "new_password": "synthetic-new-password-233"}, "", "192.0.2.1:1")
	require.Equal(t, 200, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), "access_token")
	assert.Contains(t, w.Body.String(), `"password_changed":true`)
	assert.Equal(t, 401, e.send(t, "POST", passwordPath+"/complete", map[string]string{"change_token": ticket, "new_password": "synthetic-another-password"}, "", "192.0.2.1:1").Code)
	w = e.send(t, "POST", "/api/v1/authentication/auth/", map[string]string{"username": e.operator.Username, "password": "synthetic-new-password-233"}, "", "192.0.2.1:1")
	assert.Equal(t, 200, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "access_token")
}
func TestPasswordAPIRequiresRADIUSBeforeCredentialChange(t *testing.T) {
	e := radiusEnv(t)
	resetAPIUser(t, e, "synthetic-radius-reset-233")
	w := e.send(t, "POST", "/api/v1/authentication/auth/", map[string]string{"username": e.operator.Username, "password": "synthetic-radius-reset-233"}, "", "192.0.2.1:1")
	require.Equal(t, 202, w.Code, w.Body.String())
	v := radiusJSON(t, w)
	assert.Equal(t, true, v["radius_factor_required"])
	assert.NotContains(t, v, "password_change_required")
	factor := v["factor_token"].(string)
	w = e.send(t, "POST", factorCookiePath+"/complete", map[string]string{"factor_token": factor, "response": "654321"}, "", "192.0.2.1:1")
	require.Equal(t, 202, w.Code, w.Body.String())
	v = radiusJSON(t, w)
	assert.Equal(t, true, v["password_change_required"])
	assert.NotContains(t, v, "access_token")
	ticket := v["change_token"].(string)
	w = e.send(t, "POST", passwordPath+"/complete", map[string]string{"change_token": ticket, "new_password": "synthetic-radius-final-233"}, "", "192.0.2.1:1")
	assert.Equal(t, 200, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), "access_token")
	w = e.send(t, "POST", "/api/v1/authentication/auth/", map[string]string{"username": e.operator.Username, "password": "synthetic-radius-final-233"}, "", "192.0.2.1:1")
	assert.Equal(t, 202, w.Code)
	assert.Contains(t, w.Body.String(), "radius_factor_required")
}
func TestPasswordAPIRecoveryHasIndependentPermission(t *testing.T) {
	e := reviewEnv(t)
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "User manager", Permissions: []string{"users.manage"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	target, err := e.d.Auth.CreateUser("recovery.target", "synthetic-target-password-233", coreauth.RoleOperator)
	require.NoError(t, err)
	route := "/api/v1/users/" + target.ID + "/mfa/reset"
	w := e.send(t, "POST", route, map[string]int{"revision": 1}, e.token, "192.0.2.1:1")
	assert.Equal(t, 403, w.Code)
	_, err = e.d.RBAC.SaveRole(role.ID, rbac.RoleInput{Name: role.Name, Permissions: []string{"users.manage", "users.credentials.manage"}, Revision: role.Revision}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	w = e.send(t, "POST", route, map[string]int{"revision": 1}, e.token, "192.0.2.1:1")
	require.Equal(t, 200, w.Code, w.Body.String())
	w = e.send(t, "POST", "/api/v1/users/"+e.admin.ID+"/mfa/reset", map[string]int{"revision": 1}, e.token, "192.0.2.1:1")
	assert.Equal(t, 403, w.Code)
	w = e.send(t, "POST", "/api/v1/users/"+e.operator.ID+"/mfa/reset", map[string]int{"revision": 1}, e.token, "192.0.2.1:1")
	assert.Equal(t, 409, w.Code)
}
func TestPasswordAPIPolicyRevisionReauthenticationAndStrictBodies(t *testing.T) {
	e := reviewEnv(t)
	assert.Equal(t, 403, e.send(t, "GET", "/api/v1/settings/security/passwords", nil, e.token, "192.0.2.1:1").Code)
	w := e.send(t, "GET", "/api/v1/authentication/password-policy", nil, "", "192.0.2.1:1")
	require.Equal(t, 200, w.Code)
	assert.Contains(t, w.Header().Get("Cache-Control"), "no-store")
	var p coreauth.PasswordPolicy
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &p))
	p.MinLength = 16
	p.HistoryCount = 2
	w = e.send(t, "PUT", "/api/v1/settings/security/passwords", p, e.adminToken, "192.0.2.1:1")
	require.Equal(t, 200, w.Code, w.Body.String())
	assert.Equal(t, 401, e.send(t, "GET", "/api/v1/users/me", nil, e.adminToken, "192.0.2.1:1").Code)
	login, err := e.d.Auth.Authenticate(e.admin.Username, bootstrapPassword)
	require.NoError(t, err)
	w = e.send(t, "GET", "/api/v1/settings/security/passwords/audit", nil, login.AccessToken, "192.0.2.1:1")
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), `"total":1`)
	assert.Equal(t, 409, e.send(t, "PUT", "/api/v1/settings/security/passwords", p, login.AccessToken, "192.0.2.1:1").Code)
	w = e.send(t, "POST", "/api/v1/users/"+e.operator.ID+"/mfa/reset", map[string]any{"revision": 2, "new_password": "must-not-be-used"}, login.AccessToken, "192.0.2.1:1")
	assert.Equal(t, 400, w.Code)
}
