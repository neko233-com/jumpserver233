package assets

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type coordinatedFixture struct {
	c        *PasswordCoordinator
	services []*Service
	assets   []Asset
	paths    []string
	remote   string
	changes  int
}

func sharedFixture(t *testing.T) *coordinatedFixture {
	t.Helper()
	c, e := OpenPasswordCoordinator(filepath.Join(t.TempDir(), "shared.json"), make([]byte, 32), nil)
	require.NoError(t, e)
	f := &coordinatedFixture{c: c, remote: "initial-credential"}
	for _, scope := range []string{"default", "other"} {
		st, path, a := createRotationStoreTest(t, time.Now().UTC().Add(-8*24*time.Hour))
		s := NewServiceWithPasswordRotation(st, nil, func(_ context.Context, _ sshclient.Target, current sshclient.Credentials, next string, _ time.Duration) error {
			if current.Password != f.remote {
				return errors.New("authentication failed")
			}
			for _, active := range f.services {
				assert.True(t, active.store.HasPendingPasswordRotation(a.ID))
				assert.Equal(t, "rotating", active.List()[0].PasswordRotation.State)
			}
			f.remote = next
			f.changes++
			return nil
		}, func(_ context.Context, _ sshclient.Target, c sshclient.Credentials, _ time.Duration) error {
			if c.Password != f.remote {
				return errors.New("authentication failed")
			}
			return nil
		})
		require.NoError(t, s.CoordinatePasswords(c, scope))
		f.services = append(f.services, s)
		f.assets = append(f.assets, a)
		f.paths = append(f.paths, path)
	}
	return f
}
func (f *coordinatedFixture) check(t *testing.T, expected string) {
	t.Helper()
	for i, s := range f.services {
		v, e := s.store.Password(f.assets[i].ID)
		require.NoError(t, e)
		assert.Equal(t, expected, v)
		assert.False(t, s.store.HasPendingPasswordRotation(f.assets[i].ID))
	}
}
func TestSharedPasswordRotationCommitsAllVaultsAndSchedulesOnce(t *testing.T) {
	f := sharedFixture(t)
	assert.True(t, f.services[0].List()[0].PasswordRotation.Shared)
	f.services[0].rotationStatus[f.assets[0].ID] = baseRotationStatus(f.assets[0], time.Now().UTC())
	var wg sync.WaitGroup
	for _, s := range f.services {
		wg.Add(1)
		go func(s *Service) { defer wg.Done(); s.RotateDuePasswords(context.Background()) }(s)
	}
	wg.Wait()
	require.Equal(t, 1, f.changes)
	f.check(t, f.remote)
	assert.Empty(t, f.c.ops)
	for i, s := range f.services {
		item := s.List()[0]
		assert.True(t, item.PasswordRotation.Shared)
		assert.Equal(t, "scheduled", item.PasswordRotation.State)
		assert.Equal(t, PasswordRotationInterval, item.PasswordRotation.NextRotationAt.Sub(item.PasswordRotation.LastRotatedAt))
		backups, e := s.ListCredentialBackups(f.assets[i].ID)
		require.NoError(t, e)
		require.Len(t, backups, 1)
		data, e := os.ReadFile(f.paths[i])
		require.NoError(t, e)
		assert.NotContains(t, string(data), f.remote)
		assert.NotContains(t, string(data), "initial-credential")
		audit, e := os.ReadFile(filepath.Join(filepath.Dir(f.paths[i]), "credential-rotations", "index.jsonl"))
		require.NoError(t, e)
		assert.Contains(t, string(audit), "shared_completed")
		assert.Contains(t, string(audit), `"operation_id"`)
		assert.NotContains(t, string(audit), f.remote)
	}
}
func TestSharedPasswordRestoreChangesRemoteOnceAndRetainsLocalHistory(t *testing.T) {
	f := sharedFixture(t)
	backup, e := f.services[0].CreateCredentialBackup(f.assets[0].ID, "operator")
	require.NoError(t, e)
	_, e = f.services[0].RotatePassword(context.Background(), f.assets[0].ID)
	require.NoError(t, e)
	_, e = f.services[0].RestoreCredentialBackup(context.Background(), f.assets[0].ID, backup.ID, "restoring.user")
	require.NoError(t, e)
	f.check(t, "initial-credential")
	assert.Equal(t, 2, f.changes)
	audit, e := os.ReadFile(filepath.Join(filepath.Dir(f.paths[0]), "credential-rotations", "index.jsonl"))
	require.NoError(t, e)
	assert.Contains(t, string(audit), `"actor":"restoring.user"`)
	assert.Contains(t, string(audit), backup.ID)
	other, e := os.ReadFile(filepath.Join(filepath.Dir(f.paths[1]), "credential-rotations", "index.jsonl"))
	require.NoError(t, e)
	assert.NotContains(t, string(other), backup.ID)
}
func TestSharedPasswordConflictsNeverChangeRemoteOrRevealOtherScope(t *testing.T) {
	f := sharedFixture(t)
	_, e := f.services[1].store.Update(f.assets[1], "conflicting-password")
	require.NoError(t, e)
	_, e = f.services[0].RotatePassword(context.Background(), f.assets[0].ID)
	require.ErrorIs(t, e, ErrSharedCredentialConflict)
	assert.Zero(t, f.changes)
	assert.Empty(t, f.c.ops)
	input := Input{Name: "Conflicting copy", Host: f.assets[0].Host, Port: f.assets[0].Port, Username: f.assets[0].Username, HostKeyFingerprint: f.assets[0].HostKeyFingerprint, Password: "unauthorized-password"}
	_, e = f.services[0].Create(input)
	require.ErrorIs(t, e, ErrSharedCredentialConflict)
	assert.NotContains(t, e.Error(), f.assets[1].Name)
}
func TestSharedPasswordRetainsUnresolvedJournalAndRecoversAfterRestart(t *testing.T) {
	f := sharedFixture(t)
	for _, s := range f.services {
		s.verifyPassword = func(context.Context, sshclient.Target, sshclient.Credentials, time.Duration) error {
			return errors.New("offline")
		}
	}
	_, e := f.services[0].RotatePassword(context.Background(), f.assets[0].ID)
	require.ErrorIs(t, e, ErrPasswordRotationFailed)
	require.Len(t, f.c.ops, 1)
	for _, s := range f.services {
		assert.Equal(t, "recovery_required", s.List()[0].PasswordRotation.State)
		require.ErrorIs(t, s.Delete(f.assets[0].ID), ErrRotationPending)
	}
	raw, e := os.ReadFile(f.c.path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), f.remote)
	assert.NotContains(t, string(raw), "initial-credential")
	_, e = OpenPasswordCoordinator(f.c.path, []byte("another-32-byte-key-01234567890123"), nil)
	require.Error(t, e)
	reopened, e := OpenPasswordCoordinator(f.c.path, make([]byte, 32), nil)
	require.NoError(t, e)
	for i, scope := range []string{"default", "other"} {
		st, e := OpenStore(f.paths[i], []byte("0123456789abcdef0123456789abcdef"))
		require.NoError(t, e)
		s := NewServiceWithPasswordRotation(st, nil, nil, func(_ context.Context, _ sshclient.Target, c sshclient.Credentials, _ time.Duration) error {
			if c.Password != f.remote {
				return errors.New("authentication failed")
			}
			return nil
		})
		require.NoError(t, s.CoordinatePasswords(reopened, scope))
		f.services[i] = s
	}
	reopened.Recover(context.Background())
	assert.Empty(t, reopened.ops)
	f.check(t, f.remote)
	assert.Equal(t, 1, f.changes)
}
func TestSharedPasswordCommitDecisionResumesPartialLocalCommitWithoutSSH(t *testing.T) {
	f := sharedFixture(t)
	broken := f.services[1].store
	path := broken.path
	for _, s := range f.services {
		s.verifyPassword = func(_ context.Context, _ sshclient.Target, c sshclient.Credentials, _ time.Duration) error {
			if c.Password != f.remote {
				return errors.New("authentication failed")
			}
			broken.path = filepath.Dir(path)
			return nil
		}
	}
	_, e := f.services[0].RotatePassword(context.Background(), f.assets[0].ID)
	require.ErrorIs(t, e, ErrPasswordRotationFailed)
	require.Len(t, f.c.ops, 1)
	assert.Equal(t, "commit", f.c.op.Phase)
	assert.False(t, f.services[0].store.HasPendingPasswordRotation(f.assets[0].ID))
	assert.True(t, broken.HasPendingPasswordRotation(f.assets[1].ID))
	broken.path = path
	for _, s := range f.services {
		s.verifyPassword = func(context.Context, sshclient.Target, sshclient.Credentials, time.Duration) error {
			t.Error("commit recovery must not contact SSH")
			return errors.New("unexpected SSH")
		}
	}
	f.c.Recover(context.Background())
	f.check(t, f.remote)
	assert.Empty(t, f.c.ops)
	assert.Equal(t, 1, f.changes)
}
func TestSharedPasswordPreparationFailureRollsBackEveryPendingCopy(t *testing.T) {
	f := sharedFixture(t)
	f.services[1].store.path = filepath.Dir(f.paths[1])
	_, e := f.services[0].RotatePassword(context.Background(), f.assets[0].ID)
	require.ErrorIs(t, e, ErrPasswordRotationFailed)
	assert.Zero(t, f.changes)
	f.services[1].store.path = f.paths[1]
	f.c.Recover(context.Background())
	f.check(t, "initial-credential")
	assert.Empty(t, f.c.ops)
}
func TestSharedPasswordRecoveryIncludesArchivedStoresWithoutSchedulers(t *testing.T) {
	f := sharedFixture(t)
	delete(f.c.services, "other") // Registered storage remains; its runtime is stopped.
	_, e := f.services[0].RotatePassword(context.Background(), f.assets[0].ID)
	require.NoError(t, e)
	f.check(t, f.remote)
}
func TestSharedPasswordPrepareRecoveryNeverChangesRemote(t *testing.T) {
	f := sharedFixture(t)
	o := &sharedPasswordOperation{ID: strings.Repeat("a", 32), Identity: passwordIdentity(f.assets[0]), Phase: "prepare", Participants: f.c.participants(passwordIdentity(f.assets[0])), StartedAt: time.Now().UTC(), Trigger: "automatic", Source: passwordParticipant{"default", f.assets[0].ID}}
	f.c.op = o
	f.c.ops[o.Identity] = o
	var e error
	o.Old, e = f.c.seal("initial-credential", "old")
	require.NoError(t, e)
	o.Next, e = f.c.seal("uncommitted-password", "next")
	require.NoError(t, e)
	require.NoError(t, f.c.persist())
	require.NoError(t, f.services[0].store.BeginPasswordRotation(f.assets[0].ID, "uncommitted-password", o.StartedAt))
	f.c.Recover(context.Background())
	f.check(t, "initial-credential")
	assert.Empty(t, f.c.ops)
	assert.Zero(t, f.changes)
}
func TestSharedPasswordIdentityAndJournalValidation(t *testing.T) {
	f := sharedFixture(t)
	a := f.assets[0]
	b := a
	b.Host = strings.ToUpper(a.Host) + "."
	assert.Equal(t, passwordIdentity(a), passwordIdentity(b))
	b = a
	b.Username += "x"
	assert.NotEqual(t, passwordIdentity(a), passwordIdentity(b))
	b = a
	b.HostKeyFingerprint += "x"
	assert.NotEqual(t, passwordIdentity(a), passwordIdentity(b))
	path := filepath.Join(t.TempDir(), "bad.json")
	for _, raw := range []string{`[]`, `{"broken":null}`, `{"broken":{"phase":"commit"}}`} {
		require.NoError(t, os.WriteFile(path, []byte(raw), 0600))
		_, e := OpenPasswordCoordinator(path, make([]byte, 32), nil)
		require.Error(t, e)
	}
}
func TestSharedPasswordPostgresJournalAndIndependentEncryptedOrganizationStores(t *testing.T) {
	url := os.Getenv("JMS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for shared password PostgreSQL integration")
	}
	namespace := "shared-password-" + strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "")
	docs, e := storage.OpenPostgres(context.Background(), url, namespace)
	require.NoError(t, e)
	defer docs.Close()
	c, e := OpenPasswordCoordinator(filepath.Join(t.TempDir(), "coordinator.json"), make([]byte, 32), docs)
	require.NoError(t, e)
	remote := "initial-credential"
	for i, scope := range []string{"first", "second"} {
		scoped, e := docs.Scoped(scope)
		require.NoError(t, e)
		st, e := OpenStoreWithDocuments(filepath.Join(t.TempDir(), "assets.json"), make([]byte, 32), scoped)
		require.NoError(t, e)
		a := Asset{ID: "shared-asset", Name: "Shared", Host: "host.invalid", Port: 22, Username: "ops", HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
		_, e = st.Create(a, remote)
		require.NoError(t, e)
		s := NewServiceWithPasswordRotation(st, nil, func(_ context.Context, _ sshclient.Target, _ sshclient.Credentials, p string, _ time.Duration) error {
			remote = p
			return nil
		}, func(context.Context, sshclient.Target, sshclient.Credentials, time.Duration) error {
			return errors.New("offline")
		})
		require.NoError(t, s.CoordinatePasswords(c, scope))
		if i == 1 {
			_, e = s.RotatePassword(context.Background(), a.ID)
			require.ErrorIs(t, e, ErrPasswordRotationFailed)
		}
	}
	raw, e := docs.Load("shared-passwords")
	require.NoError(t, e)
	assert.True(t, json.Valid(raw))
	assert.NotContains(t, string(raw), remote)
	reopened, e := OpenPasswordCoordinator(filepath.Join(t.TempDir(), "unused.json"), make([]byte, 32), docs)
	require.NoError(t, e)
	for _, scope := range []string{"first", "second"} {
		scoped, e := docs.Scoped(scope)
		require.NoError(t, e)
		st, e := OpenStoreWithDocuments(filepath.Join(t.TempDir(), "unused.json"), make([]byte, 32), scoped)
		require.NoError(t, e)
		s := NewServiceWithPasswordRotation(st, nil, nil, func(_ context.Context, _ sshclient.Target, creds sshclient.Credentials, _ time.Duration) error {
			if creds.Password != remote {
				return errors.New("authentication failed")
			}
			return nil
		})
		require.NoError(t, s.CoordinatePasswords(reopened, scope))
		defer scoped.Delete("assets")
	}
	reopened.Recover(context.Background())
	assert.Empty(t, reopened.ops)
	for _, st := range reopened.stores {
		p, e := st.Password("shared-asset")
		require.NoError(t, e)
		assert.Equal(t, remote, p)
	}
	require.NoError(t, docs.Delete("shared-passwords"))
}
