package assets

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sharedKeyFixture struct {
	c        *PasswordCoordinator
	services []*Service
	assets   []Asset
	files    []string
	host     *fakeKeyHost
	oldFP    string
	old      sshclient.Credentials
}

func newSharedKeyFixture(t *testing.T) *sharedKeyFixture {
	t.Helper()
	s, st, a, host, file := keyRotationEnv(t)
	installed, e := s.RotateSSHKey(context.Background(), a.ID, "initial-key-install", 1, "fixture")
	require.NoError(t, e)
	_, _, old, e := st.connection(a.ID)
	require.NoError(t, e)
	otherKey := make([]byte, 32)
	otherKey[0] = 1
	otherFile := filepath.Join(t.TempDir(), "assets.json")
	peer, e := OpenStore(otherFile, otherKey)
	require.NoError(t, e)
	copy := installed.Asset
	copy.ID = "peer-shared-key"
	copy.Name = "Other organization key"
	copy, e = peer.CreateCredentials(copy, old)
	require.NoError(t, e)
	other := NewService(peer, nil)
	wireFakeKeys(other, host)
	c, e := OpenPasswordCoordinator(filepath.Join(t.TempDir(), "shared-passwords.json"), make([]byte, 32), nil)
	require.NoError(t, e)
	require.NoError(t, s.CoordinatePasswords(c, "source"))
	require.NoError(t, other.CoordinatePasswords(c, "peer"))
	return &sharedKeyFixture{c: c, services: []*Service{s, other}, assets: []Asset{installed.Asset, copy}, files: []string{file, otherFile}, host: host, oldFP: installed.KeyFingerprint, old: old}
}
func (f *sharedKeyFixture) rotate(t *testing.T) (ListItem, error) {
	t.Helper()
	return f.services[0].RotateSSHKey(context.Background(), f.assets[0].ID, "shared-rotate-request", f.assets[0].CredentialRevision, "rotating.user")
}

type keyRetirementCheck struct {
	KeyUpdater
	beforeRetire func()
	afterRelease func()
}

func (u *keyRetirementCheck) Retire(p sshclient.KeyPlan) error {
	if u.beforeRetire != nil {
		u.beforeRetire()
	}
	return u.KeyUpdater.Retire(p)
}
func (u *keyRetirementCheck) Release() error {
	if e := u.KeyUpdater.Release(); e != nil {
		return e
	}
	if u.afterRelease != nil {
		u.afterRelease()
	}
	return nil
}
func (f *sharedKeyFixture) checkRetirement(t *testing.T) {
	t.Helper()
	original := f.services[0].keyUpdater
	f.services[0].keyUpdater = func(ctx context.Context, target sshclient.Target, credentials sshclient.Credentials, id string) (KeyUpdater, error) {
		u, e := original(ctx, target, credentials, id)
		if e != nil {
			return nil, e
		}
		return &keyRetirementCheck{KeyUpdater: u, beforeRetire: func() {
			for i, s := range f.services {
				a, e := s.Get(f.assets[i].ID)
				require.NoError(t, e)
				assert.NotEqual(t, f.oldFP, a.KeyFingerprint)
				p, _, e := s.store.PendingSSHKeyChange(a.ID)
				require.NoError(t, e)
				assert.Equal(t, "cleanup", p.Phase)
			}
		}}, nil
	}
}
func (f *sharedKeyFixture) checkComplete(t *testing.T, next string) {
	t.Helper()
	for i, s := range f.services {
		a, e := s.Get(f.assets[i].ID)
		require.NoError(t, e)
		assert.Equal(t, next, a.KeyFingerprint)
		assert.False(t, s.store.HasPendingSSHKeyChange(a.ID))
		assert.True(t, s.keyListItemShared(a.ID))
	}
	assert.Empty(t, f.c.keys.ops)
}
func (s *Service) keyListItemShared(id string) bool {
	a, e := s.Get(id)
	if e != nil {
		return false
	}
	status := s.sshKeyRotationStatus(a)
	return status != nil && status.Shared
}

func TestSharedSSHKeyRetiresOnlyAfterAllIndependentVaultsCommit(t *testing.T) {
	f := newSharedKeyFixture(t)
	f.checkRetirement(t)
	before := f.host.retires
	item, e := f.rotate(t)
	require.NoError(t, e)
	assert.NotEqual(t, f.oldFP, item.KeyFingerprint)
	f.checkComplete(t, item.KeyFingerprint)
	assert.False(t, f.host.allowed[f.oldFP])
	assert.Equal(t, before+1, f.host.retires)
	for i, s := range f.services {
		backups, e := s.ListCredentialBackups(f.assets[i].ID)
		require.NoError(t, e)
		assert.NotEmpty(t, backups)
		raw, e := os.ReadFile(f.files[i])
		require.NoError(t, e)
		assert.NotContains(t, string(raw), "PRIVATE KEY")
	}
	raw, e := os.ReadFile(f.c.keyJournalPath())
	require.NoError(t, e)
	assert.NotContains(t, string(raw), f.assets[0].ID)
	assert.NotContains(t, string(raw), "PRIVATE KEY")
	_, e = OpenPasswordCoordinator(f.c.path, []byte("0123456789abcdef0123456789abcdef"), nil)
	require.Error(t, e)
}
func TestSharedSSHKeyPartialPromotionPreservesOldKeyAndResumesFromPeer(t *testing.T) {
	f := newSharedKeyFixture(t)
	source := f.services[0]
	path := source.store.path
	verify := source.verifyPassword
	source.verifyPassword = func(ctx context.Context, target sshclient.Target, key sshclient.Credentials, d time.Duration) error {
		e := verify(ctx, target, key, d)
		if e == nil && len(key.PrivateKey) > 0 {
			source.store.path = filepath.Dir(path)
		}
		return e
	}
	_, e := f.rotate(t)
	require.ErrorIs(t, e, ErrSSHKeyRotationFailed)
	assert.True(t, f.host.allowed[f.oldFP])
	require.Len(t, f.c.keys.ops, 1)
	peer, e := f.services[1].Get(f.assets[1].ID)
	require.NoError(t, e)
	assert.NotEqual(t, f.oldFP, peer.KeyFingerprint)
	assert.False(t, f.services[0].sshKeyRotationStatus(f.assets[0]).CanCancel)
	_, e = source.CancelSSHKeyChange(context.Background(), f.assets[0].ID, source.sshKeyRotationStatus(f.assets[0]).OperationID, "operator")
	require.ErrorIs(t, e, ErrSSHKeyCommitted)
	source.store.path = path
	source.verifyPassword = verify
	f.checkRetirement(t)
	p, _, e := f.services[1].store.PendingSSHKeyChange(f.assets[1].ID)
	require.NoError(t, e)
	item, e := f.services[1].RotateSSHKey(context.Background(), f.assets[1].ID, p.RequestID, p.ExpectedRevision, "peer.operator")
	require.NoError(t, e)
	f.checkComplete(t, item.KeyFingerprint)
	assert.False(t, f.host.allowed[f.oldFP])
}
func TestSharedSSHKeyCancelFromPeerRollsBackCandidateAndKeepsEveryOldKey(t *testing.T) {
	f := newSharedKeyFixture(t)
	f.host.installAmbiguous = true
	_, e := f.rotate(t)
	require.ErrorIs(t, e, ErrSSHKeyRotationFailed)
	require.Len(t, f.c.keys.ops, 1)
	p, d, e := f.services[1].store.PendingSSHKeyChange(f.assets[1].ID)
	require.NoError(t, e)
	assert.True(t, f.host.allowed[d.NewFingerprint])
	assert.True(t, f.services[1].sshKeyRotationStatus(f.assets[1]).CanCancel)
	_, e = f.services[1].CancelSSHKeyChange(context.Background(), f.assets[1].ID, p.OperationID, "peer.operator")
	require.NoError(t, e)
	f.checkComplete(t, f.oldFP)
	assert.True(t, f.host.allowed[f.oldFP])
	assert.False(t, f.host.allowed[d.NewFingerprint])
}
func TestSharedSSHKeyPartialFinishRecoversWithoutContactingRemote(t *testing.T) {
	f := newSharedKeyFixture(t)
	source := f.services[0]
	path := source.store.path
	original := source.keyUpdater
	source.keyUpdater = func(ctx context.Context, target sshclient.Target, key sshclient.Credentials, id string) (KeyUpdater, error) {
		u, e := original(ctx, target, key, id)
		if e != nil {
			return nil, e
		}
		return &keyRetirementCheck{KeyUpdater: u, afterRelease: func() { source.store.path = filepath.Dir(path) }}, nil
	}
	_, e := f.rotate(t)
	require.ErrorIs(t, e, ErrSSHKeyRotationFailed)
	require.Len(t, f.c.keys.ops, 1)
	assert.False(t, f.host.allowed[f.oldFP])
	source.store.path = path
	reopened, e := OpenPasswordCoordinator(f.c.path, make([]byte, 32), nil)
	require.NoError(t, e)
	for i, scope := range []string{"source", "peer"} {
		key := make([]byte, 32)
		key[0] = byte(i)
		st, e := OpenStore(f.files[i], key)
		require.NoError(t, e)
		s := NewService(st, nil)
		s.keyUpdater = func(context.Context, sshclient.Target, sshclient.Credentials, string) (KeyUpdater, error) {
			t.Error("finished rotation must not contact SSH")
			return nil, errors.New("unexpected SSH")
		}
		require.NoError(t, s.CoordinatePasswords(reopened, scope))
		f.services[i] = s
	}
	f.c = reopened
	f.services[0].RecoverPendingSSHKeyChanges(context.Background())
	a, e := f.services[0].Get(f.assets[0].ID)
	require.NoError(t, e)
	f.checkComplete(t, a.KeyFingerprint)
}
func TestSharedSSHKeyUnreachableReplicaPreventsRetirementAndFreezesCohort(t *testing.T) {
	f := newSharedKeyFixture(t)
	f.services[1].verifyPassword = func(context.Context, sshclient.Target, sshclient.Credentials, time.Duration) error {
		return errors.New("peer route offline")
	}
	before := f.host.retires
	_, e := f.rotate(t)
	require.ErrorIs(t, e, ErrSSHKeyRotationFailed)
	assert.Equal(t, before, f.host.retires)
	assert.True(t, f.host.allowed[f.oldFP])
	assert.Len(t, f.c.keys.ops, 1)
	require.Error(t, f.services[1].Delete(f.assets[1].ID))
	_, e = f.services[1].Create(Input{Name: "Late duplicate", Host: f.assets[1].Host, Port: f.assets[1].Port, Username: f.assets[1].Username, HostKeyFingerprint: f.assets[1].HostKeyFingerprint, CredentialType: CredentialSSHKey, PrivateKey: string(f.old.PrivateKey)})
	require.ErrorIs(t, e, ErrSSHKeyPending)
	wireFakeKeys(f.services[1], f.host)
	_, e = f.rotate(t)
	require.NoError(t, e)
}
func TestSharedSSHKeyRecoveryIncludesArchivedOrganizationStorage(t *testing.T) {
	f := newSharedKeyFixture(t)
	delete(f.c.services, "peer")
	f.services[0].verifyPassword = func(ctx context.Context, target sshclient.Target, key sshclient.Credentials, d time.Duration) error {
		return f.services[1].verifyPassword(ctx, target, key, d)
	}
	// The inactive store uses the live initiating service's verifier, but never
	// schedules its own work or opens its own remote key updater.
	item, e := f.rotate(t)
	require.NoError(t, e)
	f.checkComplete(t, item.KeyFingerprint)
}
func TestSharedSSHKeyJournalTamperingFailsClosed(t *testing.T) {
	f := newSharedKeyFixture(t)
	f.host.installAmbiguous = true
	_, e := f.rotate(t)
	require.Error(t, e)
	raw, e := os.ReadFile(f.c.keyJournalPath())
	require.NoError(t, e)
	var envelope encryptedSecret
	require.NoError(t, json.Unmarshal(raw, &envelope))
	envelope.Ciphertext[0] ^= 128
	raw, e = json.Marshal(envelope)
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(f.c.keyJournalPath(), raw, 0600))
	_, e = OpenPasswordCoordinator(f.c.path, make([]byte, 32), nil)
	require.Error(t, e)
}
func TestSharedSSHKeyCoordinatesCopiesWithinSameOrganization(t *testing.T) {
	f := newSharedKeyFixture(t)
	input := Input{Name: "Same organization copy", Host: f.assets[0].Host, Port: f.assets[0].Port, Username: f.assets[0].Username, HostKeyFingerprint: f.assets[0].HostKeyFingerprint, CredentialType: CredentialSSHKey, PrivateKey: string(f.old.PrivateKey)}
	copy, e := f.services[0].Create(input)
	require.NoError(t, e)
	item, e := f.rotate(t)
	require.NoError(t, e)
	current, e := f.services[0].Get(copy.ID)
	require.NoError(t, e)
	assert.Equal(t, item.KeyFingerprint, current.KeyFingerprint)
	assert.False(t, f.services[0].store.HasPendingSSHKeyChange(copy.ID))
	f.checkComplete(t, item.KeyFingerprint)
}
func TestSharedSSHKeyAdoptsSourceJournalBeforeCoordinatorWasPersisted(t *testing.T) {
	f := newSharedKeyFixture(t)
	next, fp, e := generateSSHKey()
	require.NoError(t, e)
	_, _, _, e = f.services[0].store.BeginSSHKeyChange(f.assets[0].ID, "interrupted-source", f.assets[0].CredentialRevision, "original.operator", next, fp)
	require.NoError(t, e)
	require.NoError(t, f.services[0].store.RecordSSHKeyAttempt(f.assets[0].ID, "", time.Now().Add(-2*time.Hour)))
	f.services[0].RecoverPendingSSHKeyChanges(context.Background())
	f.checkComplete(t, fp)
	assert.False(t, f.host.allowed[f.oldFP])
}
func TestSharedSSHKeyAutomaticSchedulesRotateCohortOnce(t *testing.T) {
	f := newSharedKeyFixture(t)
	old := time.Now().UTC().Add(-8 * 24 * time.Hour)
	for i, s := range f.services {
		s.store.mu.Lock()
		record := s.store.assets[f.assets[i].ID]
		record.KeyRotationEnabled = true
		record.KeyRotatedAt = old
		record.KeyLastAttemptAt = old
		s.store.assets[f.assets[i].ID] = record
		require.NoError(t, s.store.persistLocked())
		s.store.mu.Unlock()
	}
	before := f.host.installs
	var wg sync.WaitGroup
	for _, s := range f.services {
		wg.Add(1)
		go func(s *Service) { defer wg.Done(); s.RotateDueSSHKeys(context.Background()) }(s)
	}
	wg.Wait()
	assert.Equal(t, before+1, f.host.installs)
	a, e := f.services[0].Get(f.assets[0].ID)
	require.NoError(t, e)
	f.checkComplete(t, a.KeyFingerprint)
}
func TestSharedSSHKeyLeavesDifferentKeyForSameRemoteAccountUntouched(t *testing.T) {
	f := newSharedKeyFixture(t)
	other, fp, e := generateSSHKey()
	require.NoError(t, e)
	f.host.allowed[fp] = true
	a := f.assets[0]
	a.ID = "independent-key"
	a.Name = "Different authorized key"
	_, e = f.services[0].store.CreateCredentials(a, other)
	require.NoError(t, e)
	f.c.refreshSharedKeyCounts()
	_, e = f.rotate(t)
	require.NoError(t, e)
	current, e := f.services[0].Get(a.ID)
	require.NoError(t, e)
	assert.Equal(t, fp, current.KeyFingerprint)
	assert.True(t, f.host.allowed[fp])
	assert.False(t, f.services[0].keyListItemShared(a.ID))
}
func TestSharedSSHKeyCancelledPreparationAppliesCooldownToUnstagedReplica(t *testing.T) {
	f := newSharedKeyFixture(t)
	peer := f.services[1]
	path := peer.store.path
	peer.store.path = filepath.Dir(path)
	_, e := f.rotate(t)
	require.Error(t, e)
	require.Len(t, f.c.keys.ops, 1)
	assert.False(t, peer.store.HasPendingSSHKeyChange(f.assets[1].ID))
	assert.False(t, peer.sshKeyRotationStatus(f.assets[1]).CanCancel)
	peer.store.path = path
	p, _, e := f.services[0].store.PendingSSHKeyChange(f.assets[0].ID)
	require.NoError(t, e)
	_, e = f.services[0].CancelSSHKeyChange(context.Background(), f.assets[0].ID, p.OperationID, "cancelling.user")
	require.NoError(t, e)
	f.checkComplete(t, f.oldFP)
	assert.True(t, peer.keyChangeCoolingDown(f.assets[1].ID, time.Now().UTC()))
	assert.True(t, f.host.allowed[f.oldFP])
}
