package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/core/rotationplans"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRotationPlanRetryAPIRechecksAuthorityAndKeepsMetadataLineage(t *testing.T) {
	e := rotationAPIEnv(t)
	permissions := []string{"assets.view_all", "assets.rotate", "accounts.rotation.view", "accounts.rotation.manage", "accounts.rotation.execute"}
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "retry operator", Permissions: permissions}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	send := func(method, path string, input any) int {
		return e.send(t, method, path, input, e.token, "192.0.2.3:4000").Code
	}
	create := e.send(t, "POST", "/api/v1/accounts/rotation-plans", rotationplans.PlanInput{Name: "Retry metadata", Kind: "manual", Targets: []rotationplans.Selection{{AccountID: e.asset.ID}}}, e.token, "192.0.2.3:4000")
	require.Equal(t, 201, create.Code)
	var p rotationplans.Plan
	require.NoError(t, json.Unmarshal(create.Body.Bytes(), &p))
	submit := e.send(t, "POST", "/api/v1/accounts/rotation-plans/"+p.ID+"/runs", map[string]string{"request_id": "retry-api-source"}, e.token, "192.0.2.3:4000")
	require.Equal(t, 202, submit.Code)
	var parent rotationplans.Run
	require.NoError(t, json.Unmarshal(submit.Body.Bytes(), &parent))
	role, err = e.d.RBAC.SaveRole(role.ID, rbac.RoleInput{Name: role.Name, Revision: role.Revision, Permissions: []string{"assets.view_all", "accounts.rotation.view", "accounts.rotation.manage"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	e.d.RotationPlans.Tick()
	require.Eventually(t, func() bool { v, _ := e.d.RotationPlans.Run(parent.ID); return v.State == "failed" }, time.Second, 5*time.Millisecond)
	input := rotationplans.RetryInput{RequestID: "retry-api-child", PlanRevision: p.Revision}
	path := "/api/v1/accounts/rotation-runs/" + parent.ID + "/retry"
	assert.Equal(t, 403, send("POST", path, input))
	role, err = e.d.RBAC.SaveRole(role.ID, rbac.RoleInput{Name: role.Name, Revision: role.Revision, Permissions: permissions}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 400, send("POST", path, map[string]any{"request_id": "retry-api-invalid", "plan_revision": p.Revision, "password": "rejected-input"}))
	assert.Equal(t, 409, send("POST", path, rotationplans.RetryInput{RequestID: "retry-api-stale", PlanRevision: p.Revision + 1}))
	response := e.send(t, "POST", path, input, e.token, "198.51.100.8:4000")
	require.Equal(t, 202, response.Code, response.Body.String())
	var child rotationplans.Run
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &child))
	assert.Equal(t, parent.ID, child.ParentRunID)
	assert.Equal(t, "198.51.100.8", child.AccessOrigin.SourceIP)
	assert.NotContains(t, response.Body.String(), "fixed_password")
	assert.NotContains(t, response.Body.String(), "Intents")
	replay := e.send(t, "POST", path, input, e.token, "198.51.100.8:4000")
	require.Equal(t, 202, replay.Code)
	assert.Contains(t, replay.Body.String(), child.ID)
	assert.Equal(t, 409, send("POST", path, rotationplans.RetryInput{RequestID: input.RequestID, PlanRevision: p.Revision, ItemIDs: []string{parent.Items[0].ID}}))
	csv := e.send(t, "GET", "/api/v1/accounts/rotation-runs/"+parent.ID+"/export", nil, e.token, "192.0.2.3:4000")
	require.Equal(t, 200, csv.Code)
	assert.Contains(t, csv.Body.String(), "source_item_id")
	assert.Contains(t, csv.Body.String(), child.ID)
	_, err = e.d.RBAC.SaveRole(role.ID, rbac.RoleInput{Name: role.Name, Revision: role.Revision, Permissions: []string{"assets.view_all", "accounts.rotation.view"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 403, send("POST", path, input))
}
