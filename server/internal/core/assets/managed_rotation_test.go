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
	"github.com/neko233-com/jumpserver233/server/internal/core/rotationplans"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func managedIntent(t *testing.T, s *Service, id, collector, request string) rotationplans.Intent {
	t.Helper()
	rows, e := s.PrepareManagedRotations(context.Background(), []rotationplans.Selection{{AccountID: id, CollectorID: collector}})
	require.NoError(t, e)
	require.Len(t, rows, 1)
	return rotationplans.Intent{RequestID: request, Actor: rotationplans.Actor{ID: "plan-owner", Name: "Plan owner"}, Target: rows[0]}
}
func TestManagedRotationInspectionDoesNotWaitForUnrelatedCoordinatorMutation(t *testing.T) {
	s, _, a, _ := newRotationServiceTest(t)
	c := attachManagedCoordinator(t, s)
	in := managedIntent(t, s, a.ID, "", "nonblocking-inspection")
	c.mu.Lock()
	done := make(chan error, 1)
	go func() {
		out, e := s.InspectManagedRotation(context.Background(), in)
		if e == nil && out.State != "not_started" {
			e = errors.New("unexpected inspection state")
		}
		done <- e
	}()
	select {
	case e := <-done:
		require.NoError(t, e)
	case <-time.After(time.Second):
		c.mu.Unlock()
		t.Fatal("metadata inspection waited for a remote mutation")
		return
	}
	c.mu.Unlock()
}
func TestManagedRotationTimeoutStopsWaitingForUnrelatedCredentialMutation(t *testing.T) {
	s, _, a, _ := newRotationServiceTest(t)
	c := attachManagedCoordinator(t, s)
	in := managedIntent(t, s, a.ID, "", "bounded-coordinator-wait")
	c.mu.Lock()
	defer c.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, e := s.ExecuteManagedRotation(ctx, in, func() error { return ctx.Err() }); done <- e }()
	select {
	case e := <-done:
		assert.ErrorIs(t, e, context.DeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("timed-out step retained its coordinator wait")
	}
	assert.False(t, s.store.HasPendingPasswordRotation(a.ID))
}
func TestManagedRotationFormatFourPreservesImportReceiptsAndRejectsDowngrade(t *testing.T) {
	s, st, a, path := newRotationServiceTest(t)
	ctx := context.Background()
	rows := []AccountImportRow{importRow(a.ID, "metadata-import-user", 2)}
	preview, e := s.PreviewAccountImport(ctx, rows, importActor(), "default", "coexisting-import")
	require.NoError(t, e)
	receipt, e := s.CommitAccountImport(ctx, rows, importActor(), "default", "coexisting-import", preview.Token)
	require.NoError(t, e)
	in := managedIntent(t, s, a.ID, "", "planned-format-four")
	st.mu.Lock()
	r := st.assets[a.ID]
	r.PlannedPasswordReceipt = &plannedPasswordReceipt{plannedPasswordIntent: plannedPasswordIntent{RequestID: in.RequestID, Revision: in.Target.Revision, Version: in.Target.Version, Actor: in.Actor}, State: "failed", AfterRevision: in.Target.Revision, At: time.Now().UTC()}
	st.assets[a.ID] = r
	e = st.persistLocked()
	st.mu.Unlock()
	require.NoError(t, e)
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.Contains(t, string(raw), `"format": 4`)
	reopened, e := OpenStore(path, []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, e)
	peer := NewService(reopened, nil)
	again, e := peer.CommitAccountImport(ctx, rows, importActor(), "default", "coexisting-import", preview.Token)
	require.NoError(t, e)
	assert.Equal(t, receipt, again)
	downgraded := strings.Replace(string(raw), `"format": 4`, `"format": 3`, 1)
	require.NoError(t, os.WriteFile(path, []byte(downgraded), 0600))
	_, e = OpenStore(path, []byte("0123456789abcdef0123456789abcdef"))
	assert.Error(t, e)
}
func attachManagedCoordinator(t *testing.T, s *Service) *PasswordCoordinator {
	t.Helper()
	c, e := OpenPasswordCoordinator(filepath.Join(t.TempDir(), "shared.json"), make([]byte, 32), nil)
	require.NoError(t, e)
	require.NoError(t, s.CoordinatePasswords(c, "default"))
	return c
}
func TestManagedPasswordReceiptSurvivesReloadAndDoesNotRepeatRemoteMutation(t *testing.T) {
	s, st, a, path := newRotationServiceTest(t)
	attachManagedCoordinator(t, s)
	remote := "initial-credential"
	changes := 0
	s.changePassword = func(_ context.Context, _ sshclient.Target, _ sshclient.Credentials, next string, _ time.Duration) error {
		changes++
		remote = next
		return nil
	}
	s.verifyPassword = func(_ context.Context, _ sshclient.Target, c sshclient.Credentials, _ time.Duration) error {
		if c.Password != remote {
			return errors.New("authentication failed")
		}
		return nil
	}
	op := managedIntent(t, s, a.ID, "", "planned-password-receipt")
	out, e := s.ExecuteManagedRotation(context.Background(), op, func() error { return nil })
	require.NoError(t, e)
	assert.Equal(t, "succeeded", out.State)
	assert.EqualValues(t, op.Target.Revision+1, out.Revision)
	assert.Equal(t, 1, changes)
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.Contains(t, string(raw), `"format": 4`)
	assert.NotContains(t, string(raw), remote)
	reopened, e := OpenStore(path, []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, e)
	peer := NewServiceWithPasswordRotation(reopened, nil, func(context.Context, sshclient.Target, sshclient.Credentials, string, time.Duration) error {
		t.Fatal("completed request re-executed")
		return nil
	}, nil)
	attachManagedCoordinator(t, peer)
	again, e := peer.ExecuteManagedRotation(context.Background(), op, func() error { return nil })
	require.NoError(t, e)
	assert.Equal(t, out, again)
	changed := op
	changed.Actor.ID = "different-owner"
	_, e = peer.ExecuteManagedRotation(context.Background(), changed, func() error { return nil })
	assert.ErrorIs(t, e, rotationplans.ErrConflict)
	assert.False(t, st.HasPendingPasswordRotation(a.ID))
}
func TestManagedPasswordSourceFenceAndPrivilegedCollector(t *testing.T) {
	s, st, a, _ := newRotationServiceTest(t)
	attachManagedCoordinator(t, s)
	collector := a
	collector.ID = "collector"
	collector.Username = "root"
	_, e := st.Create(collector, "synthetic-collector-password")
	require.NoError(t, e)
	op := managedIntent(t, s, a.ID, collector.ID, "planned-collector-password")
	remote := "initial-credential"
	changes := 0
	s.changePassword = func(context.Context, sshclient.Target, sshclient.Credentials, string, time.Duration) error {
		t.Fatal("target self rotation used instead of collector")
		return nil
	}
	s.changePasswordFor = func(_ context.Context, c sshclient.Target, credentials sshclient.Credentials, user, next string, _ time.Duration) error {
		assert.Equal(t, "root", c.Username)
		assert.Equal(t, "synthetic-collector-password", credentials.Password)
		assert.Equal(t, a.Username, user)
		remote = next
		changes++
		return nil
	}
	s.verifyPassword = func(_ context.Context, target sshclient.Target, c sshclient.Credentials, _ time.Duration) error {
		assert.Equal(t, a.Username, target.Username)
		if c.Password != remote {
			return errors.New("invalid target")
		}
		return nil
	}
	out, e := s.ExecuteManagedRotation(context.Background(), op, func() error { return nil })
	require.NoError(t, e)
	assert.Equal(t, "succeeded", out.State)
	assert.Equal(t, 1, changes)
	stale := managedIntent(t, s, a.ID, collector.ID, "stale-target")
	current, e := s.ManagedAccount(a.ID, a.ID)
	require.NoError(t, e)
	_, e = s.UpdateManagedAccount(a.ID, a.ID, AccountInput{Name: new("Concurrent metadata edit"), Version: current.Version}, importActor())
	require.NoError(t, e)
	out, e = s.ExecuteManagedRotation(context.Background(), stale, func() error { return nil })
	require.NoError(t, e)
	assert.Equal(t, "changed", out.State)
	assert.Equal(t, 1, changes)
	raw, e := json.Marshal(out)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "password")
}
func TestManagedPasswordVaultFailureRecoversReceiptWithoutAnotherChange(t *testing.T) {
	s, st, a, path := newRotationServiceTest(t)
	attachManagedCoordinator(t, s)
	remote := "initial-credential"
	changes := 0
	s.changePassword = func(_ context.Context, _ sshclient.Target, _ sshclient.Credentials, next string, _ time.Duration) error {
		changes++
		remote = next
		st.path = filepath.Join(path, "not-a-directory", "assets.json")
		return nil
	}
	s.verifyPassword = func(_ context.Context, _ sshclient.Target, c sshclient.Credentials, _ time.Duration) error {
		if c.Password == remote {
			return nil
		}
		return errors.New("invalid")
	}
	op := managedIntent(t, s, a.ID, "", "commit-failure")
	out, e := s.ExecuteManagedRotation(context.Background(), op, func() error { return nil })
	require.Error(t, e)
	assert.Equal(t, "recovery_required", out.State)
	assert.Equal(t, 1, changes)
	reopened, e := OpenStore(path, []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, e)
	peer := NewServiceWithPasswordRotation(reopened, nil, func(context.Context, sshclient.Target, sshclient.Credentials, string, time.Duration) error {
		t.Fatal("recovery changed remote password again")
		return nil
	}, s.verifyPassword)
	attachManagedCoordinator(t, peer)
	unrelated := op
	unrelated.RequestID = "unrelated-recovery-request"
	out, e = peer.RecoverManagedRotation(context.Background(), unrelated, rotationplans.Actor{ID: "recovery-admin", Name: "Recovery admin"}, func() error { return nil })
	require.NoError(t, e)
	assert.Equal(t, "recovery_required", out.State)
	_, e = peer.RecoverManagedRotation(context.Background(), op, rotationplans.Actor{ID: "recovery-admin", Name: "Recovery admin"}, func() error { return rotationplans.ErrDenied })
	assert.ErrorIs(t, e, rotationplans.ErrDenied)
	out, e = peer.RecoverManagedRotation(context.Background(), op, rotationplans.Actor{ID: "recovery-admin", Name: "Recovery admin"}, func() error { return nil })
	require.NoError(t, e)
	assert.Equal(t, "succeeded", out.State)
	assert.Equal(t, 1, changes)
}
func TestManagedSharedPasswordRequestCommitsEveryAliasAndReplaysSourceReceipt(t *testing.T) {
	f := sharedFixture(t)
	s := f.services[0]
	op := managedIntent(t, s, f.assets[0].ID, "", "shared-planned")
	result, e := s.ExecuteManagedRotation(context.Background(), op, func() error { return nil })
	require.NoError(t, e)
	assert.Equal(t, "succeeded", result.State)
	f.check(t, f.remote)
	assert.Equal(t, 1, f.changes)
	again, e := s.ExecuteManagedRotation(context.Background(), op, func() error { return nil })
	require.NoError(t, e)
	assert.Equal(t, result, again)
	assert.Equal(t, 1, f.changes)
	for _, path := range f.paths {
		peer, e := OpenStore(path, []byte("0123456789abcdef0123456789abcdef"))
		require.NoError(t, e)
		assert.NotNil(t, peer)
	}
}
func TestManagedKeyRotationFencesSourceAndReusesNativeKeyReceipt(t *testing.T) {
	s, _, a, host, _ := keyRotationEnv(t)
	attachManagedCoordinator(t, s)
	installed, e := s.RotateSSHKey(context.Background(), a.ID, "initial-key", a.CredentialRevision, "admin")
	require.NoError(t, e)
	op := managedIntent(t, s, installed.ID, "", "planned-key")
	before := host.installs
	out, e := s.ExecuteManagedRotation(context.Background(), op, func() error { return nil })
	require.NoError(t, e)
	assert.Equal(t, "succeeded", out.State)
	assert.Equal(t, before+1, host.installs)
	again, e := s.ExecuteManagedRotation(context.Background(), op, func() error { return nil })
	require.NoError(t, e)
	assert.Equal(t, out, again)
	assert.Equal(t, before+1, host.installs)
}
func TestManagedKeyExplicitRecoveryKeepsOriginalOperationAfterCredentialPromotion(t *testing.T) {
	s, _, a, host, _ := keyRotationEnv(t)
	attachManagedCoordinator(t, s)
	installed, e := s.RotateSSHKey(context.Background(), a.ID, "install-before-planned-recovery", a.CredentialRevision, "admin")
	require.NoError(t, e)
	in := managedIntent(t, s, installed.ID, "", "planned-key-explicit-recovery")
	host.failRetire = true
	out, e := s.ExecuteManagedRotation(context.Background(), in, func() error { return nil })
	require.Error(t, e)
	assert.Equal(t, "recovery_required", out.State)
	installs := host.installs
	host.failRetire = false
	out, e = s.RecoverManagedRotation(context.Background(), in, rotationplans.Actor{ID: "recovery-admin", Name: "Recovery admin"}, func() error { return nil })
	require.NoError(t, e)
	assert.Equal(t, "succeeded", out.State)
	assert.Equal(t, installs, host.installs)
	assert.Equal(t, in.Target.Revision+1, out.Revision)
}
