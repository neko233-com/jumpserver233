package assets

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/core/sshcertificates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSHCertificateBindingPreservesLegacyAuthorizationUntilSelectedAndBlocksRotation(t *testing.T) {
	dir := t.TempDir()
	store, e := OpenStore(filepath.Join(dir, "assets.json"), make([]byte, 32))
	require.NoError(t, e)
	service := NewService(store, nil)
	asset, e := service.Create(Input{Name: "Certificate target", Host: "127.0.0.1", Port: 22, Username: "ops", Password: "synthetic-bootstrap-password", HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	require.NoError(t, e)
	legacy, e := service.BindConnection(asset)
	require.NoError(t, e)
	policies, e := sshcertificates.Open(filepath.Join(dir, "ssh-certificates.json"), make([]byte, 32), nil)
	require.NoError(t, e)
	defer policies.Close()
	service.SetSSHCertificates(policies)
	same, e := service.BindConnection(asset)
	require.NoError(t, e)
	assert.Equal(t, legacy, same)
	issuer, e := policies.Save("", "admin", sshcertificates.Input{Name: "CA", Provider: "builtin", Enabled: true, RequestID: "asset-ca-001"})
	require.NoError(t, e)
	_, e = service.BindSSHCertificate(asset.ID, "admin", sshcertificates.BindingInput{IssuerID: issuer.ID, RequestID: "asset-bind-ca-001"})
	require.NoError(t, e)
	_, _, _, e = store.connectionForProtocolBound(asset.ID, true, legacy)
	assert.ErrorIs(t, e, ErrConnectionChanged)
	_, _, credentials, e := store.connection(asset.ID)
	require.NoError(t, e)
	assert.Empty(t, credentials.Password)
	assert.NotEmpty(t, credentials.Certificate)
	_, e = service.RotatePassword(context.Background(), asset.ID)
	assert.ErrorIs(t, e, ErrCredentialType)
	_, e = service.RotateSSHKey(context.Background(), asset.ID, "key-ca-001", asset.CredentialRevision, "admin")
	assert.ErrorIs(t, e, ErrCredentialType)
	_, e = service.BindSSHCertificate(asset.ID, "admin", sshcertificates.BindingInput{Revision: 1, RequestID: "clear-asset-ca-001"})
	require.NoError(t, e)
	_, _, restored, e := store.connection(asset.ID)
	require.NoError(t, e)
	assert.Equal(t, "synthetic-bootstrap-password", restored.Password)
	assert.Empty(t, restored.Certificate)
}
