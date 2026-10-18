package api

import (
	"encoding/json"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

func TestUserLifecycleOIDCPendingCannotReviveAfterRevocation(t *testing.T) {
	e := oidcEnv(t)
	u, err := e.auth.EnsureOIDCUser(e.provider.Issuer, "lifecycle-subject", "", true)
	require.NoError(t, err)
	ticket, err := e.oidc.NewPending(u.ID, e.oidc.Snapshot().Revision, u.AuthGeneration)
	require.NoError(t, err)
	a, ok := e.auth.ValidateToken(e.adminToken)
	require.True(t, ok)
	_, err = e.auth.ChangeUsers([]coreauth.UserChange{{ID: u.ID, Action: "revoke", UserUpdate: coreauth.UserUpdate{Revision: 1}}}, coreauth.UserActor{ID: a.ID, Name: a.Username, ManageAdministrators: true})
	require.NoError(t, err)
	w := oidcSend(t, e.router, "POST", "/api/v1/authentication/oidc/complete", `{}`, &http.Cookie{Name: oidcPendingCookie, Value: ticket})
	assert.Equal(t, 401, w.Code)
	w = oidcSend(t, e.router, "GET", "/api/v1/authentication/oidc/pending", ``, &http.Cookie{Name: oidcPendingCookie, Value: ticket})
	assert.Equal(t, 401, w.Code)
}
func TestUserLifecycleAPIPermissionsRevisionAndAtomicAudit(t *testing.T) {
	e := newPolicyEnv(t)
	get := func(token, path string) int { return e.send(t, "GET", path, nil, token, "192.0.2.1:1").Code }
	assert.Equal(t, 403, get(e.token, "/api/v1/users/management"))
	assert.Equal(t, 403, get(e.token, "/api/v1/users/audit"))
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "User manager", Permissions: []string{"users.manage"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 200, get(e.token, "/api/v1/users/management?scope=all&limit=25"))
	w := e.send(t, "PUT", "/api/v1/users/"+e.admin.ID, map[string]any{"revision": 1, "name": "changed"}, e.token, "192.0.2.1:1")
	assert.Equal(t, 403, w.Code)
	assert.Contains(t, w.Body.String(), "user_admin")
	w = e.send(t, "PUT", "/api/v1/users/"+e.operator.ID, map[string]any{"revision": 1, "role": "admin"}, e.token, "192.0.2.1:1")
	assert.Equal(t, 403, w.Code)
	w = e.send(t, "POST", "/api/v1/users/actions", map[string]any{"changes": []any{map[string]any{"id": e.operator.ID, "revision": 1, "action": "update", "name": "private comment never in audit"}, map[string]any{"id": e.admin.ID, "revision": 99, "action": "revoke"}}}, e.adminToken, "192.0.2.1:1")
	assert.Equal(t, 409, w.Code)
	row, err := e.d.Auth.ManagedUser(e.operator.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, row.Revision)
	w = e.send(t, "PUT", "/api/v1/users/"+e.operator.ID, map[string]any{"revision": 1, "is_active": false, "comment": "private metadata"}, e.adminToken, "192.0.2.1:1")
	require.Equal(t, 200, w.Code, w.Body.String())
	assert.Equal(t, 401, get(e.token, "/api/v1/users/me"))
	w = e.send(t, "DELETE", "/api/v1/users/"+e.operator.ID+"?revision=2", nil, e.adminToken, "192.0.2.1:1")
	require.Equal(t, 200, w.Code, w.Body.String())
	assert.Equal(t, 200, get(e.adminToken, "/api/v1/users/"+e.operator.ID))
	w = e.send(t, "POST", "/api/v1/users/"+e.operator.ID+"/restore", map[string]any{"revision": 3}, e.adminToken, "192.0.2.1:1")
	require.Equal(t, 200, w.Code, w.Body.String())
	row, err = e.d.Auth.ManagedUser(e.operator.ID)
	require.NoError(t, err)
	assert.Equal(t, "disabled", row.State)
	w = e.send(t, "GET", "/api/v1/users/audit?limit=25", nil, e.adminToken, "192.0.2.1:1")
	require.Equal(t, 200, w.Code)
	assert.NotContains(t, w.Body.String(), "private metadata")
	var audit struct {
		Results []coreauth.UserEvent
		Total   int
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &audit))
	assert.Equal(t, 3, audit.Total)
	for _, path := range []string{"/api/v1/users/management?limit=101", "/api/v1/users/management?scope=invalid", "/api/v1/users/audit?offset=-1"} {
		assert.Equal(t, 400, get(e.adminToken, path))
	}
	w = e.send(t, "PUT", "/api/v1/users/"+e.operator.ID, map[string]any{"revision": 4, "password": "forbidden"}, e.adminToken, "192.0.2.1:1")
	assert.Equal(t, 400, w.Code)
}
func TestUserLifecycleRADIUSPendingCannotReviveAfterDisableEnable(t *testing.T) {
	e := radiusEnv(t)
	ticket := startRadiusFactor(t, e, false)
	for _, active := range []bool{false, true} {
		u, err := e.d.Auth.ManagedUser(e.operator.ID)
		require.NoError(t, err)
		_, err = e.d.Auth.ChangeUsers([]coreauth.UserChange{{ID: u.ID, Action: "update", UserUpdate: coreauth.UserUpdate{Revision: u.Revision, IsActive: &active}}}, coreauth.UserActor{ID: e.admin.ID, Name: e.admin.Username, ManageAdministrators: true})
		require.NoError(t, err)
	}
	w := e.send(t, "POST", factorCookiePath+"/complete", map[string]string{"factor_token": ticket, "response": "654321"}, "", "192.0.2.5:1")
	assert.Equal(t, 401, w.Code)
}
