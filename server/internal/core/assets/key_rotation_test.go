package assets

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xssh "golang.org/x/crypto/ssh"
)

type fakeKeyHost struct {
	password         string
	allowed          map[string]bool
	failVerify       bool
	failRetire       bool
	installAmbiguous bool
	operation        string
	installs         int
	retires          int
}
type fakeKeyUpdater struct {
	host      *fakeKeyHost
	operation string
}

func (f *fakeKeyUpdater) Prepare(old, next []byte) (sshclient.KeyPlan, error) {
	pub, e := xssh.ParsePublicKey(next)
	if e != nil {
		return sshclient.KeyPlan{}, e
	}
	p := sshclient.KeyPlan{OperationID: f.operation, OldPublic: old, NewPublic: next, NewLines: []string{strings.TrimSpace(string(xssh.MarshalAuthorizedKey(pub))) + " jumpserver233/" + f.operation}}
	if len(old) > 0 {
		oldPub, e := xssh.ParsePublicKey(old)
		if e != nil {
			return p, e
		}
		p.OldLines = []string{strings.TrimSpace(string(xssh.MarshalAuthorizedKey(oldPub))) + " old"}
	}
	return p, nil
}
func (f *fakeKeyUpdater) Install(p sshclient.KeyPlan) error {
	pub, e := xssh.ParsePublicKey(p.NewPublic)
	if e != nil {
		return e
	}
	f.host.allowed[xssh.FingerprintSHA256(pub)] = true
	f.host.installs++
	if f.host.installAmbiguous {
		return errors.New("synthetic lost install reply")
	}
	return nil
}
func (f *fakeKeyUpdater) Retire(p sshclient.KeyPlan) error {
	f.host.retires++
	if f.host.failRetire {
		return errors.New("synthetic lost cleanup reply")
	}
	if len(p.OldPublic) > 0 {
		pub, e := xssh.ParsePublicKey(p.OldPublic)
		if e != nil {
			return e
		}
		delete(f.host.allowed, xssh.FingerprintSHA256(pub))
	}
	return nil
}
func (f *fakeKeyUpdater) Rollback(p sshclient.KeyPlan) error {
	pub, e := xssh.ParsePublicKey(p.NewPublic)
	if e != nil {
		return e
	}
	delete(f.host.allowed, xssh.FingerprintSHA256(pub))
	return nil
}
func (f *fakeKeyUpdater) Release() error { f.host.operation = ""; return nil }
func (f *fakeKeyUpdater) Close() error   { return nil }
func wireFakeKeys(service *Service, host *fakeKeyHost) {
	service.keyPreflight = func(context.Context, sshclient.Target, sshclient.Credentials, []byte, []byte) error { return nil }
	service.keyUpdater = func(_ context.Context, _ sshclient.Target, _ sshclient.Credentials, operation string) (KeyUpdater, error) {
		host.operation = operation
		return &fakeKeyUpdater{host: host, operation: operation}, nil
	}
	service.verifyPassword = func(_ context.Context, _ sshclient.Target, c sshclient.Credentials, _ time.Duration) error {
		if c.Password != "" && c.Password == host.password {
			return nil
		}
		if len(c.PrivateKey) > 0 {
			signer, e := xssh.ParsePrivateKey(c.PrivateKey)
			if e == nil && !host.failVerify && host.allowed[xssh.FingerprintSHA256(signer.PublicKey())] {
				return nil
			}
		}
		return errors.New("synthetic rejected credential")
	}
}
func keyRotationEnv(t *testing.T) (*Service, *Store, Asset, *fakeKeyHost, string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "assets.json")
	store, e := OpenStore(file, make([]byte, 32))
	require.NoError(t, e)
	service := NewService(store, nil)
	asset, e := service.Create(Input{Name: "key lifecycle", Host: "host.invalid", Port: 22, Username: "qa", Password: "synthetic-old-password", HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	require.NoError(t, e)
	host := &fakeKeyHost{password: "synthetic-old-password", allowed: map[string]bool{}}
	wireFakeKeys(service, host)
	return service, store, asset, host, file
}
func TestSSHKeyInstallRotationIdempotencyAndStaleRevision(t *testing.T) {
	service, store, asset, host, _ := keyRotationEnv(t)
	installed, e := service.RotateSSHKey(context.Background(), asset.ID, "install-request-1", asset.CredentialRevision, "admin")
	require.NoError(t, e)
	assert.Equal(t, CredentialSSHKey, installed.CredentialType)
	assert.EqualValues(t, 2, installed.CredentialRevision)
	assert.False(t, store.HasPendingSSHKeyChange(asset.ID))
	assert.Nil(t, installed.PasswordRotation)
	oldFP := installed.KeyFingerprint
	before := host.installs
	replay, e := service.RotateSSHKey(context.Background(), asset.ID, "install-request-1", 1, "admin")
	require.NoError(t, e)
	assert.Equal(t, oldFP, replay.KeyFingerprint)
	assert.Equal(t, before, host.installs)
	_, e = service.RotateSSHKey(context.Background(), asset.ID, "stale-request-1", 1, "admin")
	require.ErrorIs(t, e, ErrCredentialChanged)
	rotated, e := service.RotateSSHKey(context.Background(), asset.ID, "rotate-request-2", 2, "admin")
	require.NoError(t, e)
	assert.EqualValues(t, 3, rotated.CredentialRevision)
	assert.NotEqual(t, oldFP, rotated.KeyFingerprint)
	assert.False(t, host.allowed[oldFP])
	assert.True(t, host.allowed[rotated.KeyFingerprint])
	backups, e := store.ListCredentialBackups(asset.ID)
	require.NoError(t, e)
	assert.Len(t, backups, 2)
}
func TestSSHKeyPendingJournalSurvivesRestartAndCompletesCleanup(t *testing.T) {
	service, store, asset, host, file := keyRotationEnv(t)
	host.failRetire = true
	_, e := service.RotateSSHKey(context.Background(), asset.ID, "cleanup-request-1", 1, "admin")
	require.ErrorIs(t, e, ErrSSHKeyRotationFailed)
	p, data, e := store.PendingSSHKeyChange(asset.ID)
	require.NoError(t, e)
	assert.Equal(t, "cleanup", p.Phase)
	assert.NotNil(t, data.Plan)
	raw, e := os.ReadFile(file)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), host.password)
	assert.NotContains(t, string(raw), "PRIVATE KEY")
	revision := store.assets[asset.ID].CredentialRevision
	reopened, e := OpenStore(file, make([]byte, 32))
	require.NoError(t, e)
	recovery := NewService(reopened, nil)
	host.failRetire = false
	wireFakeKeys(recovery, host)
	require.NoError(t, reopened.RecordSSHKeyAttempt(asset.ID, "", time.Now().Add(-2*time.Hour)))
	recovery.RecoverPendingSSHKeyChanges(context.Background())
	assert.False(t, reopened.HasPendingSSHKeyChange(asset.ID))
	current, e := recovery.Get(asset.ID)
	require.NoError(t, e)
	assert.Equal(t, data.NewFingerprint, current.KeyFingerprint)
	assert.Equal(t, revision, current.CredentialRevision)
	var records []storedAsset
	require.NoError(t, json.Unmarshal(raw, &records))
	records[0].PendingKeyChange.Phase = "install"
	tampered, e := json.Marshal(records)
	require.NoError(t, e)
	bad := filepath.Join(t.TempDir(), "tampered.json")
	require.NoError(t, os.WriteFile(bad, tampered, 0600))
	_, e = OpenStore(bad, make([]byte, 32))
	require.Error(t, e)
}
func TestSSHKeyUncommittedCancellationAndPendingMutationGuards(t *testing.T) {
	service, store, asset, host, _ := keyRotationEnv(t)
	host.failVerify = true
	_, e := service.RotateSSHKey(context.Background(), asset.ID, "cancel-request-1", 1, "admin")
	require.ErrorIs(t, e, ErrSSHKeyRotationFailed)
	p, data, e := store.PendingSSHKeyChange(asset.ID)
	require.NoError(t, e)
	assert.Equal(t, "install", p.Phase)
	assert.True(t, host.allowed[data.NewFingerprint])
	_, e = service.Update(asset.ID, Input{Name: "edited", Host: asset.Host, Username: asset.Username, HostKeyFingerprint: asset.HostKeyFingerprint})
	assert.ErrorIs(t, e, ErrSSHKeyPending)
	assert.ErrorIs(t, store.Delete(asset.ID), ErrSSHKeyPending)
	_, e = store.CreateCredentialBackup(asset.ID, time.Now())
	assert.ErrorIs(t, e, ErrSSHKeyPending)
	_, e = service.RotateSSHKey(context.Background(), asset.ID, "competing-request-1", 1, "admin")
	assert.ErrorIs(t, e, ErrSSHKeyPending)
	host.failVerify = false
	_, e = service.CancelSSHKeyChange(context.Background(), asset.ID, "kr-00000000000000000000000000000000", "admin")
	assert.ErrorIs(t, e, ErrCredentialChanged)
	cancelled, e := service.CancelSSHKeyChange(context.Background(), asset.ID, p.OperationID, "admin")
	require.NoError(t, e)
	assert.Equal(t, CredentialPassword, cancelled.CredentialType)
	assert.EqualValues(t, 2, cancelled.CredentialRevision)
	assert.False(t, host.allowed[data.NewFingerprint])
	assert.False(t, store.HasPendingSSHKeyChange(asset.ID))
	_, e = service.RotateSSHKey(context.Background(), asset.ID, "cancel-request-1", 1, "admin")
	assert.ErrorIs(t, e, ErrSSHKeyCancelled)
}
func TestSSHKeyAmbiguousInstallationRecoversAndAutomaticPolicyIsOptIn(t *testing.T) {
	service, store, asset, host, _ := keyRotationEnv(t)
	host.installAmbiguous = true
	_, e := service.RotateSSHKey(context.Background(), asset.ID, "ambiguous-request-1", 1, "admin")
	require.ErrorIs(t, e, ErrSSHKeyRotationFailed)
	_, data, e := store.PendingSSHKeyChange(asset.ID)
	require.NoError(t, e)
	oldCount := host.installs
	host.installAmbiguous = false
	done, e := service.RotateSSHKey(context.Background(), asset.ID, "ambiguous-request-1", 1, "admin")
	require.NoError(t, e)
	assert.Equal(t, data.NewFingerprint, done.KeyFingerprint)
	assert.Greater(t, host.installs, oldCount)
	before := host.retires
	service.RotateDueSSHKeys(context.Background())
	assert.Equal(t, before, host.retires)
	record := store.assets[asset.ID]
	record.KeyRotationEnabled = true
	record.KeyRotatedAt = time.Now().Add(-8 * 24 * time.Hour)
	record.KeyLastAttemptAt = time.Now().Add(-2 * time.Hour)
	store.assets[asset.ID] = record
	service.RotateDueSSHKeys(context.Background())
	assert.Greater(t, host.retires, before)
	assert.NotEqual(t, data.NewFingerprint, store.assets[asset.ID].KeyFingerprint)
}
