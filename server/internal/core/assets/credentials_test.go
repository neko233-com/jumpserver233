package assets

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshidentity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xssh "golang.org/x/crypto/ssh"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func keyInput() Input {
	return Input{Name: "key host", Host: "private.synthetic.invalid", Port: 22, Username: "qa-key", HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", CredentialType: CredentialSSHKey, PrivateKey: string(sshidentity.PEM(sshidentity.Passphrase)), PrivateKeyPassphrase: sshidentity.Passphrase}
}
func TestKeyCredentialEncryptionInputPreservationBackupAndVerifiedRestore(t *testing.T) {
	file := filepath.Join(t.TempDir(), "assets.json")
	store, e := OpenStore(file, make([]byte, 32))
	require.NoError(t, e)
	service := NewService(store, nil)
	input := keyInput()
	asset, e := service.Create(input)
	require.NoError(t, e)
	assert.Equal(t, CredentialSSHKey, asset.CredentialType)
	assert.Equal(t, xssh.FingerprintSHA256(sshidentity.Signer().PublicKey()), asset.KeyFingerprint)
	_, e = store.Password(asset.ID)
	require.ErrorIs(t, e, ErrCredentialType)
	_, target, c, e := store.connection(asset.ID)
	require.NoError(t, e)
	assert.Empty(t, c.Password)
	require.NotEmpty(t, c.PrivateKey)
	assert.Equal(t, input.Host, target.Host)
	raw, e := os.ReadFile(file)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "PRIVATE KEY")
	assert.NotContains(t, string(raw), sshidentity.Passphrase)
	reopened, e := OpenStore(file, make([]byte, 32))
	require.NoError(t, e)
	_, _, c, e = reopened.connection(asset.ID)
	require.NoError(t, e)
	_, e = xssh.ParsePrivateKey(c.PrivateKey)
	require.NoError(t, e)
	input.PrivateKey = ""
	input.PrivateKeyPassphrase = ""
	input.CredentialType = ""
	input.Name = "renamed"
	updated, e := service.Update(asset.ID, input)
	require.NoError(t, e)
	assert.Equal(t, asset.KeyFingerprint, updated.KeyFingerprint)
	backups, e := store.ListCredentialBackups(asset.ID)
	require.NoError(t, e)
	assert.Empty(t, backups)
	backup, e := service.CreateCredentialBackup(asset.ID, "synthetic-admin")
	require.NoError(t, e)
	assert.Equal(t, CredentialSSHKey, backup.CredentialType)
	_, e = store.CredentialBackupPassword(asset.ID, backup.ID)
	require.ErrorIs(t, e, ErrCredentialType)
	_, other, e := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, e)
	block, e := xssh.MarshalPrivateKey(other, "")
	require.NoError(t, e)
	input.CredentialType = CredentialSSHKey
	input.PrivateKey = string(pem.EncodeToMemory(block))
	updated, e = service.Update(asset.ID, input)
	require.NoError(t, e)
	assert.NotEqual(t, asset.KeyFingerprint, updated.KeyFingerprint)
	service.verifyPassword = func(_ context.Context, _ sshclient.Target, c sshclient.Credentials, _ time.Duration) error {
		signer, e := xssh.ParsePrivateKey(c.PrivateKey)
		require.NoError(t, e)
		assert.Equal(t, asset.KeyFingerprint, xssh.FingerprintSHA256(signer.PublicKey()))
		return errors.New("synthetic remote rejection")
	}
	_, e = service.RestoreCredentialBackup(context.Background(), asset.ID, backup.ID, "synthetic-admin")
	require.ErrorIs(t, e, ErrPasswordRotationFailed)
	current, e := service.Get(asset.ID)
	require.NoError(t, e)
	assert.Equal(t, updated.KeyFingerprint, current.KeyFingerprint)
	service.verifyPassword = func(_ context.Context, _ sshclient.Target, c sshclient.Credentials, _ time.Duration) error {
		signer, e := xssh.ParsePrivateKey(c.PrivateKey)
		require.NoError(t, e)
		assert.Equal(t, asset.KeyFingerprint, xssh.FingerprintSHA256(signer.PublicKey()))
		return nil
	}
	restored, e := service.RestoreCredentialBackup(context.Background(), asset.ID, backup.ID, "synthetic-admin")
	require.NoError(t, e)
	assert.Equal(t, asset.KeyFingerprint, restored.KeyFingerprint)
	assert.Nil(t, restored.PasswordRotation)
	_, e = service.RotatePassword(context.Background(), asset.ID)
	require.ErrorIs(t, e, ErrCredentialType)
	called := false
	service.changePassword = func(context.Context, sshclient.Target, sshclient.Credentials, string, time.Duration) error {
		called = true
		return nil
	}
	service.RotateDuePasswords(context.Background())
	assert.False(t, called)
	_, _, version, e := store.CredentialBackupForRestore(asset.ID, backup.ID)
	require.NoError(t, e)
	input.PrivateKey = ""
	input.Name = "changed after verification"
	_, e = service.Update(asset.ID, input)
	require.NoError(t, e)
	require.ErrorIs(t, store.RestoreKeyCredential(asset.ID, backup.ID, version), ErrCredentialChanged)
	var records []storedAsset
	raw, e = os.ReadFile(file)
	require.NoError(t, e)
	require.NoError(t, json.Unmarshal(raw, &records))
	records[0].CredentialType = CredentialPassword
	records[0].KeyFingerprint = ""
	tampered, e := json.Marshal(records)
	require.NoError(t, e)
	bad := filepath.Join(t.TempDir(), "tampered.json")
	require.NoError(t, os.WriteFile(bad, tampered, 0600))
	_, e = OpenStore(bad, make([]byte, 32))
	require.Error(t, e)
}
func TestKeyInputRejectsAmbiguityAndPreservesPasswordCompatibility(t *testing.T) {
	store, e := OpenStore(filepath.Join(t.TempDir(), "assets.json"), make([]byte, 32))
	require.NoError(t, e)
	service := NewService(store, nil)
	for _, change := range []func(*Input){func(i *Input) { i.Password = "ambiguous" }, func(i *Input) { i.PrivateKey = "" }, func(i *Input) { i.PrivateKeyPassphrase = "wrong" }, func(i *Input) { i.CredentialType = "unknown" }} {
		input := keyInput()
		change(&input)
		_, e = service.Create(input)
		assert.ErrorIs(t, e, ErrInvalidInput)
	}
	input := keyInput()
	input.CredentialType = CredentialPassword
	input.PrivateKey = ""
	input.PrivateKeyPassphrase = ""
	input.Password = "synthetic-password-long-enough-for-restore-233"
	asset, e := service.Create(input)
	require.NoError(t, e)
	backup, e := service.CreateCredentialBackup(asset.ID, "synthetic-admin")
	require.NoError(t, e)
	key := keyInput()
	_, e = service.Update(asset.ID, key)
	require.NoError(t, e)
	service.changePassword = func(_ context.Context, _ sshclient.Target, c sshclient.Credentials, password string, _ time.Duration) error {
		assert.NotEmpty(t, c.PrivateKey)
		assert.Equal(t, input.Password, password)
		return errors.New("synthetic ambiguous completion")
	}
	service.verifyPassword = func(_ context.Context, _ sshclient.Target, c sshclient.Credentials, _ time.Duration) error {
		if c.Password == input.Password {
			return nil
		}
		return errors.New("rejected")
	}
	restored, e := service.RestoreCredentialBackup(context.Background(), asset.ID, backup.ID, "synthetic-admin")
	require.NoError(t, e)
	assert.Equal(t, CredentialPassword, restored.CredentialType)
	assert.Empty(t, restored.KeyFingerprint)
	assert.NotNil(t, restored.PasswordRotation)
	password, e := store.Password(asset.ID)
	require.NoError(t, e)
	assert.Equal(t, input.Password, password)
}
