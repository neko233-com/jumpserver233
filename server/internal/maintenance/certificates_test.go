package maintenance

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/sshcertificates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStandaloneBackupPreservesSSHCertificateAuthorityPoliciesAndReceipts(t *testing.T) {
	opt := fixture(t)
	key, e := os.ReadFile(filepath.Join(opt.DataDir, "vault.key"))
	require.NoError(t, e)
	store, e := sshcertificates.Open(filepath.Join(opt.DataDir, "ssh-certificates.json"), key, nil)
	require.NoError(t, e)
	input := sshcertificates.Input{Name: "Recovery CA", Provider: "builtin", Enabled: true, RequestID: "backup-ca-001"}
	issuer, e := store.Save("", "admin", input)
	require.NoError(t, e)
	target := sshcertificates.Target{AssetID: "asset-cert-backup", Host: "127.0.0.1", Port: 22, Username: "ops", Fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	in := sshcertificates.BindingInput{IssuerID: issuer.ID, RequestID: "backup-bind-ca-001"}
	binding, e := store.Bind(target, "admin", in)
	require.NoError(t, e)
	first, e := store.Resolve(target, sshclient.Credentials{})
	require.NoError(t, e)
	assert.NotEmpty(t, first.Certificate)
	store.Close()
	original, e := os.ReadFile(filepath.Join(opt.DataDir, "ssh-certificates.json"))
	require.NoError(t, e)
	_, e = Create(context.Background(), opt)
	require.NoError(t, e)
	opt.DataDir = filepath.Join(filepath.Dir(opt.DataDir), "restored")
	_, e = Restore(context.Background(), opt)
	require.NoError(t, e)
	restored, e := os.ReadFile(filepath.Join(opt.DataDir, "ssh-certificates.json"))
	require.NoError(t, e)
	assert.Equal(t, original, restored)
	peer, e := sshcertificates.Open(filepath.Join(opt.DataDir, "ssh-certificates.json"), key, nil)
	require.NoError(t, e)
	defer peer.Close()
	again, e := peer.Save("", "admin", input)
	require.NoError(t, e)
	assert.Equal(t, issuer, again)
	same, e := peer.Bind(target, "admin", in)
	require.NoError(t, e)
	assert.Equal(t, binding, same)
	renewed, e := peer.Resolve(target, sshclient.Credentials{})
	require.NoError(t, e)
	assert.NotEmpty(t, renewed.Certificate)
	assert.NotEqual(t, first.PrivateKey, renewed.PrivateKey)
	repeated, e := Restore(context.Background(), opt)
	require.NoError(t, e)
	assert.True(t, repeated.Unchanged)
}
