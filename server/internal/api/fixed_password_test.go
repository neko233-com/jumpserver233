package api

import (
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/core/rotationplans"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFixedPasswordPlanAPIIsWriteOnlyScopedAndRechecksPermissionOnReplay(t *testing.T) {
	e := rotationAPIEnv(t)
	permissions := []string{"assets.view_all", "assets.rotate", "accounts.rotation.view", "accounts.rotation.manage", "accounts.rotation.execute"}
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "Fixed rotation QA", Permissions: permissions}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	input := rotationplans.SaveInput{PlanInput: rotationplans.PlanInput{Name: "Protected API plan", Kind: "manual", PasswordMode: "fixed", Targets: []rotationplans.Selection{{AccountID: e.asset.ID}}}, RequestID: "fixed-api-save", FixedPassword: strings.Repeat("Ab2!", 16)}
	request := func(method, path string, value any) *httptest.ResponseRecorder {
		return e.send(t, method, path, value, e.token, "192.0.2.3:4000")
	}
	assert.Equal(t, 403, request("POST", "/api/v1/accounts/rotation-plans", input).Code)
	role, err = e.d.RBAC.SaveRole(role.ID, rbac.RoleInput{Name: role.Name, Revision: role.Revision, Permissions: append(permissions, "accounts.rotation.fixed_password")}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	created := request("POST", "/api/v1/accounts/rotation-plans", input)
	require.Equal(t, 201, created.Code)
	var plan rotationplans.Plan
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &plan))
	assert.Equal(t, "fixed", plan.PasswordMode)
	assert.NotContains(t, created.Body.String(), input.FixedPassword)
	assert.NotContains(t, created.Body.String(), "fixed_secret_id")
	retry := request("POST", "/api/v1/accounts/rotation-plans", input)
	require.Equal(t, 201, retry.Code)
	assert.Contains(t, retry.Body.String(), plan.ID)
	changed := input
	changed.FixedPassword = strings.Repeat("Cd3#", 16)
	assert.Equal(t, 409, request("POST", "/api/v1/accounts/rotation-plans", changed).Code)
	for _, path := range []string{"/api/v1/accounts/rotation-plans", "/api/v1/accounts/rotation-plans/" + plan.ID, "/api/v1/accounts/rotation-audit"} {
		reply := request("GET", path, nil)
		assert.Equal(t, 200, reply.Code)
		assert.NotContains(t, reply.Body.String(), input.FixedPassword)
	}
	_, err = e.d.RBAC.SaveRole(role.ID, rbac.RoleInput{Name: role.Name, Revision: role.Revision, Permissions: permissions}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 403, request("POST", "/api/v1/accounts/rotation-plans", input).Code)
	assert.Equal(t, 403, request("POST", "/api/v1/accounts/rotation-plans/"+plan.ID+"/runs", map[string]string{"request_id": "fixed-api-denied-run"}).Code)
	assert.Equal(t, 200, request("GET", "/api/v1/accounts/rotation-plans/"+plan.ID, nil).Code)
}
