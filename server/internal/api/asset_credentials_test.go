package api

import (
	"encoding/json"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshidentity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
)

func TestAssetKeyAPIIsWriteOnlyAndManagementRemainsAuthorized(t *testing.T) {
	root := t.TempDir()
	auth, e := coreauth.OpenService(filepath.Join(root, "users.json"))
	require.NoError(t, e)
	_, e = auth.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, e)
	admin, e := auth.Authenticate("admin", bootstrapPassword)
	require.NoError(t, e)
	_, e = auth.CreateUser("operator", "synthetic-key-operator-password", coreauth.RoleOperator)
	require.NoError(t, e)
	operator, e := auth.Authenticate("operator", "synthetic-key-operator-password")
	require.NoError(t, e)
	router := NewRouter("test", Dependencies{Auth: auth, Assets: testAssetService(t)})
	send := func(method, path, token string, input any, status int) []byte {
		raw, e := json.Marshal(input)
		require.NoError(t, e)
		w := doJSONRequest(t, router, method, path, string(raw), token, "127.0.0.1:43210")
		require.Equal(t, status, w.Code, w.Body.String())
		assert.NotContains(t, w.Body.String(), "PRIVATE KEY")
		assert.NotContains(t, w.Body.String(), sshidentity.Passphrase)
		assert.NotContains(t, w.Body.String(), `"private_key"`)
		return w.Body.Bytes()
	}
	input := coreassets.Input{Name: "key auth", Host: "private.synthetic.invalid", Username: "qa-key", Port: 22, HostKeyFingerprint: validTestFingerprint(), CredentialType: coreassets.CredentialSSHKey, PrivateKey: string(sshidentity.PEM(sshidentity.Passphrase)), PrivateKeyPassphrase: sshidentity.Passphrase}
	send("POST", "/api/v1/assets", operator.AccessToken, input, 403)
	var asset coreassets.Asset
	require.NoError(t, json.Unmarshal(send("POST", "/api/v1/assets", admin.AccessToken, input, 201), &asset))
	assert.Equal(t, coreassets.CredentialSSHKey, asset.CredentialType)
	assert.NotEmpty(t, asset.KeyFingerprint)
	input.PrivateKey = ""
	input.PrivateKeyPassphrase = ""
	input.CredentialType = ""
	input.Remark = "metadata only"
	send("PUT", "/api/v1/assets/"+asset.ID, admin.AccessToken, input, 200)
	send("GET", "/api/v1/assets", admin.AccessToken, nil, 200)
	send("POST", "/api/v1/assets/"+asset.ID+"/password-rotation", admin.AccessToken, nil, 400)
	send("POST", "/api/v1/assets/"+asset.ID+"/credential-backups", admin.AccessToken, nil, 201)
	send("GET", "/api/v1/assets/"+asset.ID+"/credential-backups", admin.AccessToken, nil, 200)
	input.CredentialType = coreassets.CredentialPassword
	send("PUT", "/api/v1/assets/"+asset.ID, admin.AccessToken, input, 400)
}
