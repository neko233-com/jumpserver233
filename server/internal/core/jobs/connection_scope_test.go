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
	"github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnectionScopeJobsPersistAndRequireContextAfterRestart(t *testing.T) {
	for _, mode := range []string{"bound", "missing-binder", "invalid-binder"} {
		t.Run(mode, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "jobs")
			key := make([]byte, 32)
			scope, err := accessreviews.ConnectionScope(strings.Repeat("a", 64), "/srv/approved", strings.Repeat("b", 64))
			require.NoError(t, err)
			type contextKey struct{}
			var calls atomic.Int32
			executor := func(ctx context.Context, _, _ string) (sshclient.ExecResult, error) {
				assert.Equal(t, scope, ctx.Value(contextKey{}))
				calls.Add(1)
				return sshclient.ExecResult{ExitCode: 0}, nil
			}
			s, err := Open(file, key, nil, executor)
			require.NoError(t, err)
			input := Input{AssetID: "host", Command: "pwd", RequestID: "connection-scope-001", ConnectionScope: scope}
			public, err := json.Marshal(input)
			require.NoError(t, err)
			assert.NotContains(t, string(public), "cx1-")
			job, err := s.Submit(input, "owner", "Owner", "Host", "ops", "review", "Review")
			require.NoError(t, err)
			s.Close()
			raw, err := os.ReadFile(file)
			require.NoError(t, err)
			var sealed envelope
			require.NoError(t, json.Unmarshal(raw, &sealed))
			assert.Equal(t, 5, sealed.Version)
			assert.NotContains(t, string(raw), scope)
			s, err = Open(file, key, nil, executor)
			require.NoError(t, err)
			defer s.Close()
			s.SetExecutionGuard(func(Job) error { return nil })
			if mode == "bound" {
				s.SetConnectionContext(func(ctx context.Context, j Job) (context.Context, error) {
					return context.WithValue(ctx, contextKey{}, j.ConnectionScope), nil
				})
			} else if mode == "invalid-binder" {
				s.SetConnectionContext(func(context.Context, Job) (context.Context, error) { return nil, ErrAccessDenied })
			}
			_, err = s.Review(job.ID, "Reviewer", true)
			require.NoError(t, err)
			state, count := "failed", int32(0)
			if mode == "bound" {
				state, count = "succeeded", 1
			}
			finished := waitJob(t, s, job.ID, state)
			assert.Equal(t, scope, finished.ConnectionScope)
			assert.Equal(t, count, calls.Load())
			again, err := s.Submit(input, "owner", "Owner", "Host", "ops", "allow", "")
			require.NoError(t, err)
			assert.Equal(t, job.ID, again.ID)
			assert.Equal(t, count, calls.Load())
		})
	}
}
