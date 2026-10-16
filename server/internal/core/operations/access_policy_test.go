package operations

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlanSourceSurvivesReloadAndUsesScheduledChannel(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	js, e := jobs.Open(filepath.Join(dir, "jobs.json"), key, nil, func(context.Context, string, string) (sshclient.ExecResult, error) {
		return sshclient.ExecResult{}, nil
	})
	require.NoError(t, e)
	defer js.Close()
	s, e := Open(filepath.Join(dir, "ops.json"), key, nil, js)
	require.NoError(t, e)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	input := PlanInput{Name: "source plan", AssetIDs: []string{"host"}, Command: "whoami", Kind: "once", RunAt: now.Add(time.Hour), RequestID: "source-plan", Origin: accesspolicies.Origin{SourceIP: "2001:db8::8", Method: "scheduled_exec"}}
	prepared, revision, e := s.Prepare("owner", input)
	require.NoError(t, e)
	p, e := s.CreatePlan("owner", "owner", prepared, revision)
	require.NoError(t, e)
	s.Close()
	copy, e := Open(filepath.Join(dir, "ops.json"), key, nil, js)
	require.NoError(t, e)
	defer copy.Close()
	copy.now = func() time.Time { return now }
	again, e := copy.CreatePlan("owner", "owner", prepared, revision)
	require.NoError(t, e)
	assert.Equal(t, p.ID, again.ID)
	assert.Equal(t, input.Origin, again.AccessOrigin)
	now = now.Add(2 * time.Hour)
	copy.submit = func(owner string, in jobs.Input, review string) (Submission, error) {
		assert.Equal(t, input.Origin, in.Origin)
		return Submission{}, ErrDenied
	}
	copy.Tick()
	runs, _ := copy.Runs("owner", 0, 10)
	require.Len(t, runs, 1)
	assert.Equal(t, input.Origin, runs[0].AccessOrigin)
	assert.Equal(t, "denied", runs[0].Items[0].State)
}
