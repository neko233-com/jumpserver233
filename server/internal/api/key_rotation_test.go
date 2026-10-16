package api

import (
	"encoding/json"
	"path/filepath"
	"testing"

	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshidentity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSHKeyRoutesAndAutomaticPolicyRequireServerRotationPermission(t *testing.T) {
	root := t.TempDir()
	auth, e := coreauth.OpenService(filepath.Join(root, "users.json"))
	require.NoError(t, e)
	admin, e := auth.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, e)
	manager, e := auth.CreateUser("inventory.manager", "synthetic-manager-password-233", coreauth.RoleOperator)
	require.NoError(t, e)
	adminLogin, e := auth.Authenticate("admin", bootstrapPassword)
	require.NoError(t, e)
	managerLogin, e := auth.Authenticate(manager.Username, "synthetic-manager-password-233")
	require.NoError(t, e)
	roles, e := rbac.Open(filepath.Join(root, "rbac.json"), nil)
	require.NoError(t, e)
	binding, e := roles.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: manager.ID, RoleIDs: []string{"asset-manager"}}, admin.ID, admin.Username)
	require.NoError(t, e)
	service := testAssetService(t)
	input := coreassets.Input{Name: "key policy", Host: "host.invalid", Port: 22, Username: "qa", HostKeyFingerprint: validTestFingerprint(), CredentialType: coreassets.CredentialSSHKey, PrivateKey: string(sshidentity.PEM(""))}
	asset, e := service.Create(input)
	require.NoError(t, e)
	input.PrivateKey = ""
	router := NewRouter("test", Dependencies{Auth: auth, Assets: service, RBAC: roles})
	send := func(method, path, token string, body any, status int) []byte {
		raw, e := json.Marshal(body)
		require.NoError(t, e)
		response := doJSONRequest(t, router, method, path, string(raw), token, "127.0.0.1:43210")
		require.Equal(t, status, response.Code, response.Body.String())
		assert.NotContains(t, response.Body.String(), "PRIVATE KEY")
		return response.Body.Bytes()
	}
	on := true
	off := false
	input.KeyRotationEnabled = &on
	send("PUT", "/api/v1/assets/"+asset.ID, managerLogin.AccessToken, input, 403)
	current, e := service.Get(asset.ID)
	require.NoError(t, e)
	assert.False(t, current.KeyRotationEnabled)
	send("POST", "/api/v1/assets/"+asset.ID+"/ssh-key-rotation", managerLogin.AccessToken, map[string]any{"request_id": "manager-key-request", "expected_revision": 1}, 403)
	send("POST", "/api/v1/assets/"+asset.ID+"/ssh-key-rotation/cancel", managerLogin.AccessToken, map[string]string{"operation_id": "kr-00000000000000000000000000000000"}, 403)
	send("PUT", "/api/v1/assets/"+asset.ID, adminLogin.AccessToken, input, 200)
	send("PUT", "/api/v1/assets/"+asset.ID, managerLogin.AccessToken, input, 200)
	input.KeyRotationEnabled = &off
	send("PUT", "/api/v1/assets/"+asset.ID, managerLogin.AccessToken, input, 403)
	rotateRole, e := roles.SaveRole("", rbac.RoleInput{Name: "key-rotator", Permissions: []string{"assets.rotate", "assets.view_all"}}, admin.ID, admin.Username)
	require.NoError(t, e)
	_, e = roles.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: manager.ID, RoleIDs: []string{"asset-manager", rotateRole.ID}, Revision: binding.Revision}, admin.ID, admin.Username)
	require.NoError(t, e)
	send("PUT", "/api/v1/assets/"+asset.ID, managerLogin.AccessToken, input, 200)
	send("POST", "/api/v1/assets/"+asset.ID+"/ssh-key-rotation", managerLogin.AccessToken, map[string]any{"request_id": "invalid-zero-revision", "expected_revision": 0}, 400)
	send("POST", "/api/v1/assets/"+asset.ID+"/ssh-key-rotation", managerLogin.AccessToken, map[string]any{"request_id": "stale-key-request", "expected_revision": 999}, 409)
}
