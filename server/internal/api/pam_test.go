package api

import (
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPAMAPIRequiresCurrentIndependentAuthorityAndReplaysPlatformReceipt(t *testing.T) {
	e := newPolicyEnv(t)
	path := "/api/v1/assets/" + e.asset.ID + "/pam"
	remote := "192.0.2.3:4000"
	row, err := e.d.Assets.ManagedAccount(e.asset.ID, e.asset.ID)
	require.NoError(t, err)
	input := map[string]any{"platform": "windows", "version": row.Version, "request_id": "pam-api-platform"}
	assert.Equal(t, 401, e.send(t, "PUT", path+"/platform", input, "", remote).Code)
	assert.Equal(t, 403, e.send(t, "GET", path+"/principals", nil, e.token, remote).Code)
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "PAM metadata only", Permissions: []string{"assets.view_all", "accounts.manage", "accounts.discover", "accounts.import"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	binding, err := e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 403, e.send(t, "PUT", path+"/platform", input, e.token, remote).Code)
	// Direct generic account updates cannot bypass independent rotation authority.
	direct := map[string]any{"version": row.Version, "pam": map[string]any{"platform": "windows", "enabled": false}}
	assert.Equal(t, 403, e.send(t, "PUT", "/api/v1/assets/"+e.asset.ID+"/accounts/"+e.asset.ID, direct, e.token, remote).Code)
	result := e.send(t, "PUT", path+"/platform", input, e.adminToken, remote)
	require.Equal(t, 200, result.Code, result.Body.String())
	assert.NotContains(t, result.Body.String(), "synthetic-private-password")
	replay := e.send(t, "PUT", path+"/platform", input, e.adminToken, remote)
	require.Equal(t, 200, replay.Code)
	assert.JSONEq(t, result.Body.String(), replay.Body.String())
	changed := map[string]any{"platform": "linux", "version": row.Version, "request_id": "pam-api-platform"}
	assert.Equal(t, 409, e.send(t, "PUT", path+"/platform", changed, e.adminToken, remote).Code)
	assert.Equal(t, 400, e.send(t, "POST", path+"/import-commit", map[string]any{"request_id": "pam-forgery", "preview_token": "forged", "unexpected": "field"}, e.adminToken, remote).Code)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, Revision: binding.Revision}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 403, e.send(t, "GET", path+"/principals", nil, e.token, remote).Code)
	current, err := e.d.Assets.Get(e.asset.ID)
	require.NoError(t, err)
	require.NotNil(t, current.PAM)
	assert.Equal(t, "windows", current.PAM.Platform)
	var receipt assets.AccountImportReceipt
	require.NoError(t, json.Unmarshal(result.Body.Bytes(), &receipt))
	assert.Len(t, receipt.Rows, 1)
}
