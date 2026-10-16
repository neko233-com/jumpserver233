package jobs

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecutionGuardStopsSSHBeforeSideEffectsAndRetainsOrigin(t *testing.T) {
	var calls atomic.Int32
	s, e := Open(filepath.Join(t.TempDir(), "jobs.json"), make([]byte, 32), nil, func(context.Context, string, string) (sshclient.ExecResult, error) {
		calls.Add(1)
		return sshclient.ExecResult{}, nil
	})
	require.NoError(t, e)
	defer s.Close()
	origin := accesspolicies.Origin{SourceIP: "192.0.2.8", Method: "exec"}
	s.SetExecutionGuard(func(j Job) error { assert.Equal(t, origin, j.AccessOrigin); return ErrAccessDenied })
	j, e := s.Submit(Input{Origin: origin, AssetID: "host", Command: "whoami"}, "owner", "owner", "host", "ops", "allow", "")
	require.NoError(t, e)
	require.Eventually(t, func() bool { job, _ := s.Get(j.ID); return job.State == "failed" }, time.Second, time.Millisecond)
	job, e := s.Get(j.ID)
	require.NoError(t, e)
	assert.Equal(t, "access_policy_denied", job.ErrorCode)
	assert.Zero(t, calls.Load())
}
