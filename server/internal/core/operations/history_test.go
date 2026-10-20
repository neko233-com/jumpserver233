package operations

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/playbooks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fillHistoryRuns(s *Service, count int, at time.Time) {
	for n := 0; n < count; n++ {
		owner := "owner"
		if n%2 != 0 {
			owner = "other"
		}
		r := Run{ID: fmt.Sprintf("run-%05d", n), PlanID: "old-plan", OwnerID: owner, State: "succeeded", Command: "pwd", TimeoutSeconds: 60, WorkingDirectory: "/srv/work", CreatedAt: at.Add(time.Duration(n) * time.Millisecond), Items: []Item{{AssetID: "a", State: "succeeded"}}, Trigger: "manual", TriggeredBy: ScheduleActor{ID: owner, Name: owner}, RequestID: fmt.Sprintf("request-%d", n), AccessOrigin: accesspolicies.Origin{Method: "exec"}}
		s.data.Runs[r.ID] = r
	}
}

func TestRunHistoryPaginationTriggerReplayAndSourceSurvivePruning(t *testing.T) {
	s, js, _ := setup(t, nil)
	at := time.Now().UTC().Add(-time.Hour)
	fillHistoryRuns(s, 1000, at)
	program, err := playbooks.Compile(playbooks.Workspace{Files: map[string]string{"main.yml": "- tasks: [{debug: {msg: original}}]"}})
	require.NoError(t, err)
	id := playbooks.WorkspaceID(program.Files)
	s.data.Programs[id] = program
	r := s.data.Runs["run-00000"]
	r.ProgramID = id
	r.PlaybookID = "playbook-deleted"
	r.PlaybookRevision = 7
	r.StepReservation = 1
	r.Variables = map[string]any{"private": "original"}
	r.Items[0].Steps = []StepResult{{ID: "step-one", State: "succeeded", Final: true, Local: &LocalEvidence{Result: playbooks.Result{Stdout: "preserved local output"}}}}
	s.data.Runs[r.ID] = r
	require.NoError(t, s.compactHistory())
	assert.NotContains(t, s.data.Programs, id, "archived original source is self contained")
	rows, total, err := s.ListRuns("owner", 480, 50)
	require.NoError(t, err)
	assert.Equal(t, 500, total)
	require.Len(t, rows, 20)
	assert.Equal(t, "run-00038", rows[0].ID)
	assert.True(t, rows[0].Archived)
	full, err := s.Run(r.ID)
	require.NoError(t, err)
	assert.True(t, full.Archived)
	assert.Equal(t, "preserved local output", full.Items[0].Steps[0].Local.Result.Stdout)
	loaded, err := s.RunProgram(r.ID, "owner", false)
	require.NoError(t, err)
	assert.Equal(t, program.Files, loaded.Files)
	_, err = s.RunProgram(r.ID, "foreign", false)
	assert.ErrorIs(t, err, ErrNotFound)
	replay, err := s.TriggerPlan("old-plan", r.RequestID, r.TriggeredBy, r.AccessOrigin)
	require.NoError(t, err)
	assert.Equal(t, r.ID, replay.ID, "deleted plan still returns original trigger receipt")
	_, err = s.TriggerPlan("another-plan", r.RequestID, r.TriggeredBy, r.AccessOrigin)
	assert.ErrorIs(t, err, ErrConflict)
	_, err = s.TriggerPlan("old-plan", r.RequestID, r.TriggeredBy, accesspolicies.Origin{Method: "exec", SourceIP: "changed"})
	assert.ErrorIs(t, err, ErrConflict)
	assert.ErrorIs(t, s.CancelRun(r.ID), ErrNotFound)
	s.Close()
	peer, err := Open(s.path, make([]byte, 32), nil, js)
	require.NoError(t, err)
	defer peer.Close()
	loaded, err = peer.RunProgram(r.ID, "owner", false)
	require.NoError(t, err)
	assert.Equal(t, program.Files, loaded.Files)
	_, total, err = peer.ListRuns("foreign", 0, 50)
	require.NoError(t, err)
	assert.Zero(t, total)
}

func TestRunArchiveHotSaveFailureAndDuplicateQueryAreSafe(t *testing.T) {
	s, _, _ := setup(t, nil)
	fillHistoryRuns(s, 800, time.Now().UTC().Add(-time.Hour))
	original := s.path
	s.path = filepath.Join(filepath.Dir(original), "is-directory")
	require.NoError(t, os.MkdirAll(s.path, 0700))
	assert.Error(t, s.compactHistory())
	assert.Len(t, s.data.Runs, 800)
	_, total, err := s.ListRuns("", 0, 100)
	require.NoError(t, err)
	assert.Equal(t, 800, total, "archive commit before failed hot save must not duplicate rows")
	s.path = original
	require.NoError(t, s.compactHistory())
	assert.Len(t, s.data.Runs, 736)
	_, total, err = s.ListRuns("", 0, 100)
	require.NoError(t, err)
	assert.Equal(t, 800, total)
}

func TestRunArchiveDoesNotCaptureInFlightCancellationOrCollector(t *testing.T) {
	s, _, _ := setup(t, nil)
	fillHistoryRuns(s, 800, time.Now().UTC().Add(-time.Hour))
	r := s.data.Runs["run-00000"]
	r.State = "cancelled"
	r.Cancelled = true
	r.Items[0].State = "dispatching"
	s.data.Runs[r.ID] = r
	second := s.data.Runs["run-00001"]
	second.State = "running"
	second.Items[0].State = "running"
	s.data.Runs[second.ID] = second
	require.NoError(t, s.compactHistory())
	assert.Contains(t, s.data.Runs, r.ID)
	assert.Contains(t, s.data.Runs, second.ID)
	assert.ErrorIs(t, s.CancelRun("run-00799"), ErrConflict, "terminal evidence cannot be edited")
}
