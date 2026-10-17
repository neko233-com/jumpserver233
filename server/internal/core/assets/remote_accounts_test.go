package assets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xssh "golang.org/x/crypto/ssh"
)

func prepareRemoteTest(t *testing.T, s *Service, parent Asset, request string) RemoteAccountTask {
	t.Helper()
	p, e := s.Get(parent.ID)
	require.NoError(t, e)
	v, e := s.PrepareRemoteAccount(parent.ID, RemoteAccountInput{Action: "create", Username: "remoteqa_user", Shell: "/bin/sh", Version: accountVersion(p), RequestID: request}, strings.Repeat("a", 64), strings.Repeat("b", 64), AccountActor{ID: "owner", Name: "Owner"}, accesspolicies.Origin{SourceIP: "192.0.2.3", Method: "exec"})
	require.NoError(t, e)
	return v
}
func remoteTestResult(op hostagent.AccountOperation, state string) hostagent.AccountAdminResult {
	uid := uint32(1001)
	if state == "cancelled" {
		uid = 0
	}
	return hostagent.AccountAdminResult{Format: hostagent.AccountAdminFormat, ID: op.Task.ID, Digest: op.Task.Digest(), Action: op.Task.Action, Username: op.Task.Username, UID: uid, GID: 1001, Home: "/home/" + op.Task.Username, Shell: "/bin/sh", State: state, Stage: "ready"}
}
func TestRemoteAccountReservesEncryptedKeyVerifiesThenAtomicallyPromotesAndReloads(t *testing.T) {
	s, st, parent, path := newRotationServiceTest(t)
	task := prepareRemoteTest(t, s, parent, "create-durable")
	a, e := s.AccountAsset(parent.ID, task.Operation.AccountID)
	require.NoError(t, e)
	assert.True(t, a.AccountDisabled)
	assert.Equal(t, "pending", a.RemoteAccount.State)
	assert.Equal(t, parent.Username, task.Operation.CollectorAccount)
	assert.NotEmpty(t, task.Operation.Task.PublicKey)
	duplicate := prepareRemoteTest(t, s, parent, "create-durable")
	assert.Equal(t, task.Operation.AccountID, duplicate.Operation.AccountID)
	assert.Equal(t, task.Operation.Task.PublicKey, duplicate.Operation.Task.PublicKey)
	_, e = s.UpdateManagedAccount(parent.ID, a.ID, AccountInput{Version: accountVersion(a)}, AccountActor{ID: "owner", Name: "Owner"})
	assert.ErrorIs(t, e, ErrRemoteAccountPending)
	_, e = s.Update(parent.ID, Input{Name: parent.Name, Host: parent.Host, Port: parent.Port, Username: parent.Username, HostKeyFingerprint: parent.HostKeyFingerprint})
	assert.ErrorIs(t, e, ErrRemoteAccountPending)
	assert.ErrorIs(t, s.DeleteManagedAccount(parent.ID, a.ID, accountVersion(a), AccountActor{ID: "owner", Name: "Owner"}), ErrRemoteAccountPending)
	verified := false
	s.verifyPassword = func(_ context.Context, target sshclient.Target, c sshclient.Credentials, _ time.Duration) error {
		assert.Equal(t, a.Username, target.Username)
		signer, e := xssh.ParsePrivateKey(c.PrivateKey)
		require.NoError(t, e)
		assert.Equal(t, task.Operation.Task.PublicKey, strings.TrimSpace(string(xssh.MarshalAuthorizedKey(signer.PublicKey()))))
		assert.Empty(t, c.Password)
		verified = true
		return nil
	}
	result, e := s.ExecuteRemoteAccount(context.Background(), task.Operation, "job-test", func(_ context.Context, collector, job, parentID string, op hostagent.AccountOperation, guard func() error) (hostagent.AccountAdminResult, error) {
		assert.Equal(t, parent.ID, collector)
		assert.Equal(t, parent.ID, parentID)
		return remoteTestResult(op, "applied"), guard()
	}, func() error { return nil })
	require.NoError(t, e)
	assert.True(t, verified)
	a, e = s.AccountAsset(parent.ID, a.ID)
	require.NoError(t, e)
	assert.True(t, a.AccountDisabled, "observing an effect does not activate the Vault endpoint")
	completed, e := s.CommitRemoteAccount(task.Operation, result)
	require.NoError(t, e)
	assert.Equal(t, "succeeded", completed.State)
	a, e = s.Get(a.ID)
	require.NoError(t, e)
	assert.False(t, a.AccountDisabled)
	assert.Equal(t, uint32(1001), a.RemoteAccount.UID)
	assert.True(t, a.KeyRotationEnabled)
	assert.Equal(t, SSHKeyRotationInterval, s.sshKeyRotationStatus(a).NextRotationAt.Sub(a.KeyRotatedAt))
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.Contains(t, string(raw), `"format": 2`)
	assert.NotContains(t, string(raw), "initial-credential")
	assert.NotContains(t, string(raw), "BEGIN OPENSSH PRIVATE KEY")
	var old []storedAsset
	assert.Error(t, json.Unmarshal(raw, &old), "old binaries refuse the versioned lifecycle document")
	reloaded, e := OpenStore(path, []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, e)
	restored, e := NewService(reloaded, nil).AccountAsset(parent.ID, a.ID)
	require.NoError(t, e)
	assert.Equal(t, a, restored)
	_, _, _, e = st.connection(a.ID)
	require.NoError(t, e)
	_, e = s.BindRemoteAccountSubmission(task.Operation, "job-test", "")
	require.NoError(t, e, "a fast completion remains a successful submission response")
}
func TestRemoteAccountUnknownEffectKeepsKeyAndExplicitInspectionReusesIt(t *testing.T) {
	s, _, parent, _ := newRotationServiceTest(t)
	task := prepareRemoteTest(t, s, parent, "create-unknown")
	s.verifyPassword = func(context.Context, sshclient.Target, sshclient.Credentials, time.Duration) error {
		return errors.New("synthetic verification failure")
	}
	executor := func(_ context.Context, _, _, _ string, op hostagent.AccountOperation, _ func() error) (hostagent.AccountAdminResult, error) {
		return remoteTestResult(op, "applied"), nil
	}
	_, e := s.ExecuteRemoteAccount(context.Background(), task.Operation, "job-first", executor, func() error { return nil })
	assert.ErrorIs(t, e, ErrRemoteAccountPending)
	unknown, e := s.RemoteAccountTask(parent.ID, task.Operation.Task.ID)
	require.NoError(t, e)
	assert.Equal(t, "needs_reconcile", unknown.State)
	next, e := s.ResumeRemoteAccount(parent.ID, task.Operation.Task.ID, unknown.Revision, "inspect", strings.Repeat("c", 64), AccountActor{ID: "new-owner", Name: "Recovery"}, unknown.Origin)
	require.NoError(t, e)
	assert.Equal(t, task.Creator, next.Creator)
	assert.Equal(t, "new-owner", next.OwnerID)
	assert.Equal(t, task.Operation.Task.PublicKey, next.Operation.Task.PublicKey)
	assert.EqualValues(t, 2, next.Operation.Attempt)
	assert.False(t, s.RemoteAccountOperationAllowed("owner", parent.ID, &task.Operation))
	s.verifyPassword = func(context.Context, sshclient.Target, sshclient.Credentials, time.Duration) error { return nil }
	r, e := s.ExecuteRemoteAccount(context.Background(), next.Operation, "job-reconcile", executor, func() error { return nil })
	require.NoError(t, e)
	_, e = s.CommitRemoteAccount(next.Operation, r)
	require.NoError(t, e)
	_, e = s.ResumeRemoteAccount(parent.ID, task.Operation.Task.ID, unknown.Revision, "apply", strings.Repeat("d", 64), task.Creator, unknown.Origin)
	assert.ErrorIs(t, e, ErrRemoteAccountConflict)
}
func TestRemoteAccountCancellationFencesCreateAndRestoresOnlyPreviousLocalState(t *testing.T) {
	s, _, parent, _ := newRotationServiceTest(t)
	task := prepareRemoteTest(t, s, parent, "cancel-create")
	task, e := s.ResumeRemoteAccount(parent.ID, task.Operation.Task.ID, task.Revision, "cancel", task.Operation.Binding, task.Creator, task.Origin)
	require.NoError(t, e)
	executor := func(_ context.Context, _, _, _ string, op hostagent.AccountOperation, _ func() error) (hostagent.AccountAdminResult, error) {
		return remoteTestResult(op, "cancelled"), nil
	}
	r, e := s.ExecuteRemoteAccount(context.Background(), task.Operation, "job-cancel", executor, func() error { return nil })
	require.NoError(t, e)
	_, e = s.CommitRemoteAccount(task.Operation, r)
	require.NoError(t, e)
	_, e = s.Get(task.Operation.AccountID)
	assert.ErrorIs(t, e, ErrNotFound)
	a := addManagedTestAccount(t, s, parent.ID)
	row, e := s.AccountAsset(parent.ID, a.ID)
	require.NoError(t, e)
	task, e = s.PrepareRemoteAccount(parent.ID, RemoteAccountInput{Action: "disable", Username: row.Username, AccountID: row.ID, UID: 1001, Version: accountVersion(row), RequestID: "cancel-disable"}, strings.Repeat("a", 64), strings.Repeat("b", 64), AccountActor{ID: "owner", Name: "Owner"}, accesspolicies.Origin{Method: "exec"})
	require.NoError(t, e)
	task, e = s.ResumeRemoteAccount(parent.ID, task.Operation.Task.ID, task.Revision, "cancel", task.Operation.Binding, task.Creator, task.Origin)
	require.NoError(t, e)
	r, e = s.ExecuteRemoteAccount(context.Background(), task.Operation, "job-cancel-disable", executor, func() error { return nil })
	require.NoError(t, e)
	_, e = s.CommitRemoteAccount(task.Operation, r)
	require.NoError(t, e)
	current, e := s.Get(row.ID)
	require.NoError(t, e)
	assert.Equal(t, row.AccountDisabled, current.AccountDisabled)
	assert.Nil(t, current.RemoteAccount)
	assert.Equal(t, row.CredentialRevision, current.CredentialRevision)
}
func TestRemoteAccountPreparationWriteFailureDoesNotReserveOrLoseAnEndpoint(t *testing.T) {
	s, st, parent, _ := newRotationServiceTest(t)
	before := len(st.List())
	blocked := filepath.Join(t.TempDir(), "blocked")
	require.NoError(t, os.WriteFile(blocked, []byte("owned failure"), 0600))
	st.path = filepath.Join(blocked, "assets.json")
	_, e := s.PrepareRemoteAccount(parent.ID, RemoteAccountInput{Action: "create", Username: "remoteqa_fault", Shell: "/bin/sh", Version: accountVersion(parent), RequestID: "prepare-failure"}, strings.Repeat("a", 64), strings.Repeat("b", 64), AccountActor{ID: "owner", Name: "Owner"}, accesspolicies.Origin{Method: "exec"})
	require.Error(t, e)
	assert.Equal(t, before, len(st.List()))
	tasks, e := s.RemoteAccountTasks(parent.ID)
	require.NoError(t, e)
	assert.Empty(t, tasks)
}

func TestRemoteAccountPendingCopiesBlockedAcrossOrganizationsAndCommitFailureRecovers(t *testing.T) {
	s, st, parent, path := newRotationServiceTest(t)
	coordinator, e := OpenPasswordCoordinator(filepath.Join(t.TempDir(), "coordinator.json"), make([]byte, 32), nil)
	require.NoError(t, e)
	require.NoError(t, s.CoordinatePasswords(coordinator, "default"))
	other, _, otherParent, _ := newRotationServiceTest(t)
	require.NoError(t, other.CoordinatePasswords(coordinator, "other"))
	task := prepareRemoteTest(t, s, parent, "copy-block-test")
	otherCurrent, e := other.ManagedAccount(otherParent.ID, otherParent.ID)
	require.NoError(t, e)
	_, e = other.CreateManagedAccount(otherParent.ID, AccountInput{Username: task.Operation.Task.Username, Password: "synthetic-other-password", Version: otherCurrent.Version}, task.Creator)
	assert.ErrorIs(t, e, ErrRemoteAccountPending)
	s.verifyPassword = func(context.Context, sshclient.Target, sshclient.Credentials, time.Duration) error { return nil }
	r, e := s.ExecuteRemoteAccount(context.Background(), task.Operation, "job-commit-fault", func(_ context.Context, _, _, _ string, op hostagent.AccountOperation, _ func() error) (hostagent.AccountAdminResult, error) {
		return remoteTestResult(op, "applied"), nil
	}, func() error { return nil })
	require.NoError(t, e)
	blocked := filepath.Join(t.TempDir(), "blocked")
	require.NoError(t, os.WriteFile(blocked, []byte("owned fault"), 0600))
	st.path = filepath.Join(blocked, "assets.json")
	_, e = s.CommitRemoteAccount(task.Operation, r)
	require.Error(t, e)
	a, e := s.AccountAsset(parent.ID, task.Operation.AccountID)
	require.NoError(t, e)
	assert.True(t, a.AccountDisabled)
	st.path = path
	loaded, e := OpenStore(path, []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, e)
	recovered := NewServiceWithPasswordRotation(loaded, nil, nil, s.verifyPassword)
	pending, e := recovered.RemoteAccountTask(parent.ID, task.Operation.Task.ID)
	require.NoError(t, e)
	assert.Equal(t, "needs_reconcile", pending.State)
	next, e := recovered.ResumeRemoteAccount(parent.ID, task.Operation.Task.ID, pending.Revision, "inspect", task.Operation.Binding, task.Creator, task.Origin)
	require.NoError(t, e)
	observed, e := recovered.ExecuteRemoteAccount(context.Background(), next.Operation, "job-reconcile-commit", func(_ context.Context, _, _, _ string, op hostagent.AccountOperation, _ func() error) (hostagent.AccountAdminResult, error) {
		assert.Equal(t, "inspect", op.Mode)
		return remoteTestResult(op, "applied"), nil
	}, func() error { return nil })
	require.NoError(t, e)
	_, e = recovered.CommitRemoteAccount(next.Operation, observed)
	require.NoError(t, e)
	a, e = recovered.Get(next.Operation.AccountID)
	require.NoError(t, e)
	assert.False(t, a.AccountDisabled)
}

func TestRemoteAccountPostgresTakeoverRetainsStagedKeyWithoutAutomaticReplay(t *testing.T) {
	dsn := os.Getenv("JMS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires PostgreSQL state fixture")
	}
	docs, e := storage.OpenPostgres(context.Background(), dsn, fmt.Sprintf("remote-account-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	t.Cleanup(func() { _ = docs.Delete("assets"); _ = docs.Close() })
	key := []byte("0123456789abcdef0123456789abcdef")
	st, e := OpenStoreWithDocuments(filepath.Join(t.TempDir(), "assets.json"), key, docs)
	require.NoError(t, e)
	parent, e := st.Create(Asset{ID: "asset-ha", Name: "HA", Host: "192.0.2.8", Port: 22, Username: "root", HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, "synthetic-root")
	require.NoError(t, e)
	s := NewService(st, nil)
	task := prepareRemoteTest(t, s, parent, "pg-takeover-remote")
	_, e = s.ExecuteRemoteAccount(context.Background(), task.Operation, "job-interrupted", func(context.Context, string, string, string, hostagent.AccountOperation, func() error) (hostagent.AccountAdminResult, error) {
		return hostagent.AccountAdminResult{}, context.Canceled
	}, func() error { return nil })
	require.Error(t, e)
	peer, e := OpenStoreWithDocuments(filepath.Join(t.TempDir(), "unused.json"), key, docs)
	require.NoError(t, e)
	nextService := NewServiceWithPasswordRotation(peer, nil, nil, func(context.Context, sshclient.Target, sshclient.Credentials, time.Duration) error { return nil })
	pending, e := nextService.RemoteAccountTask(parent.ID, task.Operation.Task.ID)
	require.NoError(t, e)
	assert.Equal(t, "needs_reconcile", pending.State)
	assert.Equal(t, task.Operation.Task.PublicKey, pending.Operation.Task.PublicKey)
	_, _, _, e = peer.connection(task.Operation.AccountID)
	assert.ErrorIs(t, e, ErrAccountDisabled)
	raw, e := docs.Load("assets")
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "PRIVATE KEY")
	assert.NotContains(t, string(raw), "synthetic-root")
	next, e := nextService.ResumeRemoteAccount(parent.ID, task.Operation.Task.ID, pending.Revision, "inspect", task.Operation.Binding, task.Creator, task.Origin)
	require.NoError(t, e)
	result, e := nextService.ExecuteRemoteAccount(context.Background(), next.Operation, "job-new-leader", func(_ context.Context, _, _, _ string, op hostagent.AccountOperation, _ func() error) (hostagent.AccountAdminResult, error) {
		assert.Equal(t, "inspect", op.Mode)
		return remoteTestResult(op, "applied"), nil
	}, func() error { return nil })
	require.NoError(t, e)
	_, e = nextService.CommitRemoteAccount(next.Operation, result)
	require.NoError(t, e)
	final, e := OpenStoreWithDocuments(filepath.Join(t.TempDir(), "unused.json"), key, docs)
	require.NoError(t, e)
	_, _, c, e := final.connection(task.Operation.AccountID)
	require.NoError(t, e)
	assert.NotEmpty(t, c.PrivateKey)
}
