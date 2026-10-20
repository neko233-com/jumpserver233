package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/reporting"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func historyExecutor(context.Context, string, string) (sshclient.ExecResult, error) {
	return sshclient.ExecResult{ExitCode: 0}, nil
}

func TestJobHistoryEmptyOwnerPageRemainsJSONArray(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "jobs.json"), make([]byte, 32), nil, historyExecutor)
	require.NoError(t, err)
	defer s.Close()
	for _, offset := range []int{0, 100} {
		rows, total, err := s.List("new-operator", offset, 50)
		require.NoError(t, err)
		require.NotNil(t, rows)
		assert.Zero(t, total)
		raw, err := json.Marshal(rows)
		require.NoError(t, err)
		assert.JSONEq(t, "[]", string(raw))
	}
}

func TestJobHistorySurvivesHotWindowWithOutputsAndDurableRetry(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "jobs.json"), make([]byte, 32), nil, historyExecutor)
	require.NoError(t, err)
	defer s.Close()
	at := time.Now().UTC().Add(-time.Hour)
	for n := 0; n < 1700; n++ {
		owner := "a"
		if n%2 != 0 {
			owner = "b"
		}
		j := Job{ID: fmt.Sprintf("job-%04d", n), OperatorID: owner, AssetID: "host", Command: "pwd", RequestID: fmt.Sprintf("retry-%d", n), State: "succeeded", CreatedAt: at.Add(time.Duration(n) * time.Millisecond), FinishedAt: at.Add(time.Duration(n+1) * time.Millisecond), TimeoutSeconds: 60}
		j.Stdout = "private preserved stdout"
		s.jobs[j.ID] = j
		require.NoError(t, s.archiveHistoryLocked())
	}
	require.Less(t, len(s.jobs), 1000)
	rows, total, err := s.List("a", 800, 100)
	require.NoError(t, err)
	assert.Equal(t, 850, total)
	require.Len(t, rows, 50)
	assert.Equal(t, "job-0098", rows[0].ID)
	assert.Empty(t, rows[0].Stdout)
	first, err := s.Get("job-0000")
	require.NoError(t, err)
	assert.True(t, first.Archived)
	assert.Equal(t, "private preserved stdout", first.Stdout)
	in := Input{AssetID: "host", Command: "pwd", RequestID: "retry-0", TimeoutSeconds: 60}
	again, err := s.Submit(in, "a", "A", "Host", "ops", "allow", "")
	require.NoError(t, err)
	assert.Equal(t, first.ID, again.ID)
	in.Command = "changed"
	_, err = s.Submit(in, "a", "A", "Host", "ops", "allow", "")
	assert.ErrorIs(t, err, ErrConflict)
	count := 0
	require.NoError(t, s.ReportMetadata(context.Background(), "a", false, func(reporting.Entry) error { count++; return nil }))
	assert.Equal(t, 850, count)
	require.NoError(t, s.persistLocked())
	s.Close()
	peer, err := Open(s.path, make([]byte, 32), nil, historyExecutor)
	require.NoError(t, err)
	defer peer.Close()
	loaded, err := peer.Get(first.ID)
	require.NoError(t, err)
	assert.Equal(t, first, loaded)
	_, total, err = peer.List("foreign", 0, 100)
	require.NoError(t, err)
	assert.Zero(t, total)
}

func TestJobHistoryCrashDuplicateIsDeduplicatedAndHotSaveFailureRetainsEvidence(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "jobs"), make([]byte, 32), nil, historyExecutor)
	require.NoError(t, err)
	defer s.Close()
	at := time.Now().UTC()
	for n := 0; n < 800; n++ {
		j := Job{ID: fmt.Sprintf("job-%04d", n), OperatorID: "a", AssetID: "host", Command: "pwd", RequestID: fmt.Sprintf("req-%d", n), State: "succeeded", CreatedAt: at.Add(time.Duration(n) * time.Nanosecond)}
		s.jobs[j.ID] = j
	}
	s.path = filepath.Join(dir, "missing-parent", "jobs") // force the atomic rename target to be a directory
	require.NoError(t, os.MkdirAll(s.path, 0700))
	assert.Error(t, s.archiveHistoryLocked())
	assert.Len(t, s.jobs, 800)
	rows, total, err := s.List("a", 0, 100)
	require.NoError(t, err)
	assert.Equal(t, 800, total)
	assert.Len(t, rows, 100)
	s.path = filepath.Join(dir, "jobs")
	require.NoError(t, s.archiveHistoryLocked())
	assert.Len(t, s.jobs, 736)
}
