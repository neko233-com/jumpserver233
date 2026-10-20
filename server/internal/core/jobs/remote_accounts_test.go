package jobs

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func remoteInput() Input {
	op := &hostagent.AccountOperation{CollectorAccount: "root", Task: hostagent.AccountAdminTask{ID: "ra-" + strings.Repeat("a", 32), Action: "disable", Username: "remoteqa_test", UID: 1001}, Mode: "apply", Attempt: 1, Binding: strings.Repeat("a", 64), Target: strings.Repeat("b", 64), ParentAssetID: "asset", AccountID: "account"}
	return Input{AssetID: "collector", RemoteAccount: op, Command: op.Command(), RequestID: "remote-operation", TimeoutSeconds: 10}
}
func TestRemoteAccountJobsUseVersion3TypedExecutorAndNeverFallBackToShell(t *testing.T) {
	file := filepath.Join(t.TempDir(), "jobs.json")
	key := make([]byte, 32)
	var shell, typed atomic.Int32
	s, e := Open(file, key, nil, func(context.Context, string, string) (sshclient.ExecResult, error) {
		shell.Add(1)
		return sshclient.ExecResult{}, nil
	})
	require.NoError(t, e)
	t.Cleanup(s.Close)
	in := remoteInput()
	j, e := s.Submit(in, "owner", "operator", "host", "root", "review", "command-review")
	require.NoError(t, e)
	in.RemoteAccount.Mode = "cancel"
	stored, e := s.Get(j.ID)
	require.NoError(t, e)
	assert.Equal(t, "apply", stored.RemoteAccount.Mode)
	untyped := remoteInput()
	untyped.RemoteAccount = nil
	_, _, e = s.FindRequest("owner", untyped)
	require.ErrorIs(t, e, ErrConflict)
	s.Close()
	raw, e := os.ReadFile(file)
	require.NoError(t, e)
	var box envelope
	require.NoError(t, json.Unmarshal(raw, &box))
	assert.Equal(t, 7, box.Version)
	assert.NotContains(t, string(raw), "remoteqa_test")
	box.Version = 2
	downgrade, _ := json.Marshal(box)
	require.NoError(t, os.WriteFile(file, downgrade, 0600))
	_, e = Open(file, key, nil, nil)
	require.Error(t, e, "version is authenticated with the ciphertext")
	require.NoError(t, os.WriteFile(file, raw, 0600))
	reloaded, e := Open(file, key, nil, func(context.Context, string, string) (sshclient.ExecResult, error) {
		shell.Add(1)
		return sshclient.ExecResult{}, nil
	})
	require.NoError(t, e)
	t.Cleanup(reloaded.Close)
	reloaded.SetExecutionGuard(func(Job) error { return nil })
	reloaded.SetRemoteAccountExecutor(func(_ context.Context, j Job) (sshclient.ExecResult, error) {
		typed.Add(1)
		assert.Equal(t, "apply", j.RemoteAccount.Mode)
		return sshclient.ExecResult{ExitCode: 0}, nil
	})
	_, e = reloaded.Review(j.ID, "reviewer", true)
	require.NoError(t, e)
	waitJob(t, reloaded, j.ID, "succeeded")
	assert.EqualValues(t, 1, typed.Load())
	assert.Zero(t, shell.Load())
}
func TestRemoteAccountJobsLeadershipLossLeavesExplicitReconciliation(t *testing.T) {
	file := filepath.Join(t.TempDir(), "jobs.json")
	key := make([]byte, 32)
	fallback := func(context.Context, string, string) (sshclient.ExecResult, error) {
		t.Error("typed account operation reached shell executor")
		return sshclient.ExecResult{}, nil
	}
	s, e := Open(file, key, nil, fallback)
	require.NoError(t, e)
	t.Cleanup(s.Close)
	entered := make(chan struct{})
	s.SetExecutionGuard(func(Job) error { return nil })
	s.SetRemoteAccountExecutor(func(ctx context.Context, _ Job) (sshclient.ExecResult, error) {
		close(entered)
		<-ctx.Done()
		return sshclient.ExecResult{}, ctx.Err()
	})
	j, e := s.Submit(remoteInput(), "owner", "operator", "host", "root", "allow", "")
	require.NoError(t, e)
	<-entered
	s.Abandon()
	next, e := Open(file, key, nil, fallback)
	require.NoError(t, e)
	t.Cleanup(next.Close)
	got, e := next.Get(j.ID)
	require.NoError(t, e)
	assert.Equal(t, "interrupted", got.State)
	assert.Equal(t, remoteInput().RemoteAccount, got.RemoteAccount)
}
