package jobs

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDrainPreservesAdmittedJobAndRejectsNewExecutorWithoutLeakingCounts(t *testing.T) {
	g := workgate.New()
	started, finish := make(chan struct{}), make(chan struct{})
	s, e := Open(filepath.Join(t.TempDir(), "jobs.json"), []byte(strings.Repeat("k", 32)), nil, func(ctx context.Context, _ string, _ string) (sshclient.ExecResult, error) {
		close(started)
		<-finish
		_, release, e := g.Enter(ctx, "verification")
		if e != nil {
			return sshclient.ExecResult{}, e
		}
		release()
		return sshclient.ExecResult{}, nil
	})
	require.NoError(t, e)
	defer func() {
		select {
		case <-finish:
		default:
			close(finish)
		}
		s.Close()
	}()
	s.SetAdmissionGate(g)
	first, e := s.Submit(Input{AssetID: "a", Command: "existing", RequestID: "old-job", TimeoutSeconds: 10}, "owner", "owner", "host", "ops", "allow", "")
	require.NoError(t, e)
	<-started
	g.SetClosed(true)
	assert.Equal(t, 1, s.ActiveCount())
	second, e := s.Submit(Input{AssetID: "a", Command: "new", RequestID: "new-job", TimeoutSeconds: 10}, "owner", "owner", "host", "ops", "allow", "")
	require.NoError(t, e)
	assert.Equal(t, "service_draining", waitJob(t, s, second.ID, "failed").ErrorCode)
	close(finish)
	waitJob(t, s, first.ID, "succeeded")
	require.Eventually(t, func() bool { return len(g.Snapshot()) == 0 && s.ActiveCount() == 0 }, time.Second, time.Millisecond)
}
