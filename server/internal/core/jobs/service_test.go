package jobs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func waitJob(t *testing.T, s *Service, id, state string) Job {
	t.Helper()
	var job Job
	require.Eventually(t, func() bool { var err error; job, err = s.Get(id); return err == nil && job.State == state }, 3*time.Second, 5*time.Millisecond)
	return job
}
func TestJobsEncryptedIdempotentAndReviewLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jobs.json")
	key := []byte(strings.Repeat("k", 32))
	var calls atomic.Int32
	executor := func(context.Context, string, string) (sshclient.ExecResult, error) {
		calls.Add(1)
		return sshclient.ExecResult{Stdout: "private-output", Stderr: "warning", ExitCode: 7}, nil
	}
	s, err := Open(path, key, nil, executor)
	require.NoError(t, err)
	defer s.Close()
	in := Input{AssetID: "asset", Command: "private-command", RequestID: "retry-one", TimeoutSeconds: 10}
	j, err := s.Submit(in, "owner", "operator", "host", "ops", "review", "review rule")
	require.NoError(t, err)
	assert.Zero(t, calls.Load())
	duplicate, err := s.Submit(in, "owner", "operator", "host", "ops", "review", "review rule")
	require.NoError(t, err)
	assert.Equal(t, j.ID, duplicate.ID)
	conflict := in
	conflict.Command = "different"
	_, err = s.Submit(conflict, "owner", "operator", "host", "ops", "allow", "")
	assert.ErrorIs(t, err, ErrConflict)
	_, err = s.Review(j.ID, "reviewer", true)
	require.NoError(t, err)
	completed := waitJob(t, s, j.ID, "failed")
	assert.Equal(t, 7, completed.ExitCode)
	assert.Equal(t, "reviewer", completed.ReviewedBy)
	assert.Equal(t, "remote_exit", completed.ErrorCode)
	assert.EqualValues(t, 1, calls.Load())
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "private-command")
	assert.NotContains(t, string(data), "private-output")
	reloaded, err := Open(path, key, nil, executor)
	require.NoError(t, err)
	defer reloaded.Close()
	again, err := reloaded.Get(j.ID)
	require.NoError(t, err)
	assert.Equal(t, completed, again)
	_, err = Open(path, []byte(strings.Repeat("x", 32)), nil, executor)
	require.Error(t, err)
	items, total, err := s.List("other", 0, 50)
	require.NoError(t, err)
	assert.Empty(t, items)
	assert.Zero(t, total)
	items, _, err = s.List("owner", 0, 50)
	require.NoError(t, err)
	assert.Empty(t, items[0].Stdout)
}
func TestJobsDenyCancelCapacityTimeoutAndBoundedOutput(t *testing.T) {
	var calls atomic.Int32
	s, err := Open(filepath.Join(t.TempDir(), "jobs.json"), make([]byte, 32), nil, func(ctx context.Context, _, command string) (sshclient.ExecResult, error) {
		calls.Add(1)
		if command == "large" {
			return sshclient.ExecResult{Stdout: strings.Repeat("x", sshclient.MaxExecOutput+100), ExitCode: 0}, nil
		}
		<-ctx.Done()
		return sshclient.ExecResult{ExitCode: -1}, ctx.Err()
	})
	require.NoError(t, err)
	defer s.Close()
	denied, err := s.Submit(Input{AssetID: "a", Command: "deny"}, "u", "u", "a", "ops", "deny", "block")
	require.NoError(t, err)
	assert.Equal(t, "denied", denied.State)
	assert.Zero(t, calls.Load())
	first, err := s.Submit(Input{AssetID: "a", Command: "wait"}, "u", "u", "a", "ops", "allow", "")
	require.NoError(t, err)
	_, err = s.Submit(Input{AssetID: "a", Command: "wait"}, "u", "u", "a", "ops", "allow", "")
	require.NoError(t, err)
	_, err = s.Submit(Input{AssetID: "a", Command: "wait"}, "u", "u", "a", "ops", "allow", "")
	assert.ErrorIs(t, err, ErrBusy)
	require.NoError(t, s.Cancel(first.ID))
	waitJob(t, s, first.ID, "cancelled")
	timed, err := s.Submit(Input{AssetID: "a", Command: "wait", TimeoutSeconds: 1}, "v", "v", "a", "ops", "allow", "")
	require.NoError(t, err)
	waitJob(t, s, timed.ID, "timed_out")
	large, err := s.Submit(Input{AssetID: "a", Command: "large"}, "v", "v", "a", "ops", "allow", "")
	require.NoError(t, err)
	finished := waitJob(t, s, large.ID, "succeeded")
	assert.Len(t, finished.Stdout, sshclient.MaxExecOutput)
	assert.True(t, finished.Truncated)
}
func TestJobsFailClosedAndRestartDoesNotReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jobs.json")
	key := make([]byte, 32)
	var calls atomic.Int32
	exec := func(context.Context, string, string) (sshclient.ExecResult, error) {
		calls.Add(1)
		return sshclient.ExecResult{}, nil
	}
	s, err := Open(path, key, nil, exec)
	require.NoError(t, err)
	j, err := s.Submit(Input{AssetID: "a", Command: "wait"}, "u", "u", "a", "ops", "review", "")
	require.NoError(t, err)
	s.mu.Lock()
	record := s.jobs[j.ID]
	record.State = "running"
	s.jobs[j.ID] = record
	require.NoError(t, s.persistLocked())
	s.mu.Unlock()
	s.Close()
	reloaded, err := Open(path, key, nil, exec)
	require.NoError(t, err)
	defer reloaded.Close()
	record, err = reloaded.Get(j.ID)
	require.NoError(t, err)
	assert.Equal(t, "interrupted", record.State)
	assert.Zero(t, calls.Load())
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blocked, []byte("x"), 0600))
	reloaded.path = filepath.Join(blocked, "jobs.json")
	_, err = reloaded.Submit(Input{AssetID: "a", Command: "new"}, "u", "u", "a", "ops", "allow", "")
	require.Error(t, err)
	assert.Zero(t, calls.Load())
}
func TestJobReviewExpiresBeforeApproval(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "jobs.json"), make([]byte, 32), nil, func(context.Context, string, string) (sshclient.ExecResult, error) {
		t.Error("expired command executed")
		return sshclient.ExecResult{}, nil
	})
	require.NoError(t, err)
	defer s.Close()
	j, err := s.Submit(Input{AssetID: "a", Command: "pending"}, "u", "u", "a", "ops", "review", "")
	require.NoError(t, err)
	s.mu.Lock()
	old := s.jobs[j.ID]
	old.CreatedAt = time.Now().Add(-6 * time.Minute)
	s.jobs[j.ID] = old
	s.mu.Unlock()
	_, err = s.Review(j.ID, "admin", true)
	assert.ErrorIs(t, err, ErrConflict)
	waitJob(t, s, j.ID, "timed_out")
}
func TestLostLeaderDoesNotWriteCompletionOrReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jobs.json")
	executor := func(ctx context.Context, _, _ string) (sshclient.ExecResult, error) {
		<-ctx.Done()
		return sshclient.ExecResult{ExitCode: -1}, ctx.Err()
	}
	s, err := Open(path, make([]byte, 32), nil, executor)
	require.NoError(t, err)
	j, err := s.Submit(Input{AssetID: "a", Command: "wait"}, "u", "u", "a", "ops", "allow", "")
	require.NoError(t, err)
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	s.Abandon()
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after))
	next, err := Open(path, make([]byte, 32), nil, executor)
	require.NoError(t, err)
	defer next.Close()
	record, err := next.Get(j.ID)
	require.NoError(t, err)
	assert.Equal(t, "interrupted", record.State)
}
func TestJobsPostgresPersistence(t *testing.T) {
	url := os.Getenv("JMS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for PostgreSQL job-store integration")
	}
	docs, err := storage.OpenPostgres(context.Background(), url, "jobs-test-"+time.Now().Format("150405.000000000"))
	require.NoError(t, err)
	defer docs.Close()
	defer docs.Delete("ssh-jobs")
	key := make([]byte, 32)
	executor := func(context.Context, string, string) (sshclient.ExecResult, error) {
		return sshclient.ExecResult{ExitCode: 0}, nil
	}
	s, err := Open(filepath.Join(t.TempDir(), "jobs.json"), key, docs, executor)
	require.NoError(t, err)
	j, err := s.Submit(Input{AssetID: "a", Command: "private-command"}, "u", "u", "a", "ops", "review", "")
	require.NoError(t, err)
	s.Close()
	data, err := docs.Load("ssh-jobs")
	require.NoError(t, err)
	assert.NotContains(t, string(data), "private-command")
	other, err := Open(filepath.Join(t.TempDir(), "jobs.json"), key, docs, executor)
	require.NoError(t, err)
	defer other.Close()
	record, err := other.Get(j.ID)
	require.NoError(t, err)
	assert.Equal(t, "pending_review", record.State)
}

func TestSubmitGateRunsAfterCapacityAndDeduplication(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "jobs.json"), make([]byte, 32), nil, func(ctx context.Context, _, _ string) (sshclient.ExecResult, error) {
		<-ctx.Done()
		return sshclient.ExecResult{}, ctx.Err()
	})
	require.NoError(t, err)
	defer s.Close()
	calls := 0
	gate := func() error { calls++; return nil }
	in := Input{AssetID: "a", Command: "wait", RequestID: "one"}
	first, err := s.SubmitWithGate(in, "u", "u", "a", "ops", "allow", "", gate)
	require.NoError(t, err)
	_, err = s.SubmitWithGate(in, "u", "u", "a", "ops", "allow", "", gate)
	require.NoError(t, err)
	assert.Equal(t, 1, calls)
	in.RequestID = "two"
	_, err = s.SubmitWithGate(in, "u", "u", "a", "ops", "allow", "", gate)
	require.NoError(t, err)
	in.RequestID = "three"
	_, err = s.SubmitWithGate(in, "u", "u", "a", "ops", "allow", "", gate)
	assert.ErrorIs(t, err, ErrBusy)
	assert.Equal(t, 2, calls)
	require.NoError(t, s.Cancel(first.ID))
	waitJob(t, s, first.ID, "cancelled")
	gateError := errors.New("permit denied")
	_, err = s.SubmitWithGate(in, "u", "u", "a", "ops", "allow", "", func() error { return gateError })
	assert.ErrorIs(t, err, gateError)
	_, found, err := s.FindRequest("u", in)
	require.NoError(t, err)
	assert.False(t, found)
}
