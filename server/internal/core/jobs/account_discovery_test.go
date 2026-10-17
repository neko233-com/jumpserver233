package jobs

import (
	"context"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accountdiscovery"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func discoveryInput() Input {
	o := &accountdiscovery.Operation{Binding: strings.Repeat("a", 64), Target: strings.Repeat("b", 64)}
	return Input{AssetID: "asset", Discovery: o, Command: o.Command(), RequestID: "inventory-request", TimeoutSeconds: 10}
}

func TestDiscoveryJobsCloneMetadataPersistReviewAndRejectUntypedReplay(t *testing.T) {
	file := filepath.Join(t.TempDir(), "jobs.json")
	key := make([]byte, 32)
	var fallback, calls atomic.Int32
	exec := func(context.Context, string, string) (sshclient.ExecResult, error) {
		fallback.Add(1)
		return sshclient.ExecResult{ExitCode: 0}, nil
	}
	s, err := Open(file, key, nil, exec)
	require.NoError(t, err)
	t.Cleanup(s.Close)
	in := discoveryInput()
	expected := *in.Discovery
	j, err := s.Submit(in, "owner", "operator", "host", "ops", "review", "inventory-review")
	require.NoError(t, err)
	in.Discovery.Binding = strings.Repeat("c", 64)
	j.Discovery.Target = strings.Repeat("d", 64)
	stored, err := s.Get(j.ID)
	require.NoError(t, err)
	assert.Equal(t, expected, *stored.Discovery)

	untyped := discoveryInput()
	untyped.Discovery = nil
	_, _, err = s.FindRequest("owner", untyped)
	assert.ErrorIs(t, err, ErrConflict)
	_, err = s.Submit(untyped, "owner", "operator", "host", "ops", "allow", "")
	assert.ErrorIs(t, err, ErrConflict)
	s.Close()

	reloaded, err := Open(file, key, nil, exec)
	require.NoError(t, err)
	t.Cleanup(reloaded.Close)
	again, err := reloaded.Get(j.ID)
	require.NoError(t, err)
	assert.Equal(t, "pending_review", again.State)
	assert.Equal(t, expected, *again.Discovery)
	reloaded.SetExecutionGuard(func(job Job) error {
		assert.Equal(t, expected, *job.Discovery)
		return nil
	})
	reloaded.SetDiscoveryExecutor(func(_ context.Context, job Job) (sshclient.ExecResult, error) {
		calls.Add(1)
		assert.Equal(t, expected, *job.Discovery)
		return sshclient.ExecResult{ExitCode: 0, Stdout: "inventory-summary"}, nil
	})
	_, err = reloaded.Review(j.ID, "reviewer", true)
	require.NoError(t, err)
	completed := waitJob(t, reloaded, j.ID, "succeeded")
	assert.Equal(t, "inventory-summary", completed.Stdout)
	assert.EqualValues(t, 1, calls.Load())
	assert.Zero(t, fallback.Load())
}

func TestDiscoveryJobsRequireTypedExecutorGuardAndCanonicalOperation(t *testing.T) {
	for _, missing := range []string{"executor", "guard"} {
		t.Run(missing, func(t *testing.T) {
			var calls atomic.Int32
			s, err := Open(filepath.Join(t.TempDir(), "jobs.json"), make([]byte, 32), nil, func(context.Context, string, string) (sshclient.ExecResult, error) {
				calls.Add(1)
				return sshclient.ExecResult{}, nil
			})
			require.NoError(t, err)
			t.Cleanup(s.Close)
			if missing != "guard" {
				s.SetExecutionGuard(func(Job) error { return nil })
			}
			if missing != "executor" {
				s.SetDiscoveryExecutor(func(context.Context, Job) (sshclient.ExecResult, error) {
					calls.Add(1)
					return sshclient.ExecResult{}, nil
				})
			}
			j, err := s.Submit(discoveryInput(), "owner", "operator", "host", "ops", "allow", "")
			require.NoError(t, err)
			assert.Equal(t, "access_policy_denied", waitJob(t, s, j.ID, "failed").ErrorCode)
			assert.Zero(t, calls.Load())
		})
	}
	in := discoveryInput()
	in.Command += " extra"
	_, err := Validate(in)
	assert.ErrorIs(t, err, ErrInvalid)
	in = discoveryInput()
	in.Plugin = &hostplugins.Operation{}
	_, err = Validate(in)
	assert.ErrorIs(t, err, ErrInvalid)
	in = discoveryInput()
	in.Discovery.Target = "invalid"
	_, err = Validate(in)
	assert.ErrorIs(t, err, ErrInvalid)
}

func TestDiscoveryJobsLeadershipLossInterruptsWithoutReplay(t *testing.T) {
	file := filepath.Join(t.TempDir(), "jobs.json")
	key := make([]byte, 32)
	var fallback atomic.Int32
	exec := func(context.Context, string, string) (sshclient.ExecResult, error) {
		fallback.Add(1)
		return sshclient.ExecResult{}, nil
	}
	s, err := Open(file, key, nil, exec)
	require.NoError(t, err)
	t.Cleanup(s.Close)
	entered := make(chan struct{})
	s.SetExecutionGuard(func(Job) error { return nil })
	s.SetDiscoveryExecutor(func(ctx context.Context, _ Job) (sshclient.ExecResult, error) {
		close(entered)
		<-ctx.Done()
		return sshclient.ExecResult{}, ctx.Err()
	})
	j, err := s.Submit(discoveryInput(), "owner", "operator", "host", "ops", "allow", "")
	require.NoError(t, err)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("native collector did not start")
	}
	s.Abandon()
	reloaded, err := Open(file, key, nil, exec)
	require.NoError(t, err)
	t.Cleanup(reloaded.Close)
	again, err := reloaded.Get(j.ID)
	require.NoError(t, err)
	assert.Equal(t, "interrupted", again.State)
	assert.Equal(t, "node_restarted", again.ErrorCode)
	assert.Equal(t, discoveryInput().Discovery, again.Discovery)
	assert.Zero(t, fallback.Load())
}
