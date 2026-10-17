package jobs

import (
	"context"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
	"time"
)

func TestSecurityFeedReviewAndPolicyDenialMetadata(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "jobs"), make([]byte, 32), nil, func(context.Context, string, string) (sshclient.ExecResult, error) {
		return sshclient.ExecResult{Stdout: "synthetic-private-output"}, nil
	})
	require.NoError(t, e)
	defer s.Close()
	submit := func(id, decision string) Job {
		j, e := s.Submit(Input{AssetID: "asset", Command: "synthetic-private-command", TimeoutSeconds: 10, RequestID: id}, "owner", "Owner", "Synthetic host", "ops", decision, "Rule")
		require.NoError(t, e)
		return j
	}
	j := submit("pending", "review")
	batch, e := s.SecurityNotificationFeed(context.Background(), "", time.Time{}, 100)
	require.NoError(t, e)
	require.Len(t, batch.Events, 1)
	assert.Equal(t, "job_review_pending", batch.Events[0].State)
	_, e = s.Review(j.ID, "reviewer", false)
	require.NoError(t, e)
	submit("denied", "deny")
	expired := submit("expired", "review")
	s.mu.Lock()
	v := s.jobs[expired.ID]
	v.CreatedAt = time.Now().UTC().Add(-6 * time.Minute)
	s.jobs[expired.ID] = v
	s.mu.Unlock()
	batch, e = s.SecurityNotificationFeed(context.Background(), "", time.Time{}, 100)
	require.NoError(t, e)
	states := []string{}
	for _, v := range batch.Events {
		states = append(states, v.State)
	}
	assert.Contains(t, states, "job_review_denied")
	assert.Contains(t, states, "job_command_denied")
	assert.Contains(t, states, "job_review_expired")
	raw, _ := json.Marshal(batch)
	assert.NotContains(t, string(raw), "synthetic-private-command")
	assert.NotContains(t, string(raw), "synthetic-private-output")
	info, e := s.SecurityNotificationInfo(expired.ID)
	require.NoError(t, e)
	assert.Equal(t, "timed_out", info.State)
}
