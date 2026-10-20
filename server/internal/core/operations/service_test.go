package operations

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
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setup(t *testing.T, executor jobs.Executor) (*Service, *jobs.Service, *time.Time) {
	t.Helper()
	if executor == nil {
		executor = func(context.Context, string, string) (sshclient.ExecResult, error) {
			return sshclient.ExecResult{ExitCode: 0}, nil
		}
	}
	dir := t.TempDir()
	js, err := jobs.Open(filepath.Join(dir, "jobs.json"), make([]byte, 32), nil, executor)
	require.NoError(t, err)
	s, err := Open(filepath.Join(dir, "operations.json"), make([]byte, 32), nil, js)
	require.NoError(t, err)
	t.Cleanup(func() { s.Close(); js.Close() })
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	s.submit = func(owner string, in jobs.Input, _ string) (Submission, error) {
		j, e := js.Submit(in, owner, owner, in.AssetID, "ops", "allow", "")
		return Submission{Job: j}, e
	}
	return s, js, &now
}
func plan(t *testing.T, s *Service, in PlanInput) Plan {
	t.Helper()
	if in.Name == "" {
		in.Name = "test plan"
	}
	if in.RequestID == "" {
		in.RequestID = in.Name
	}
	if len(in.AssetIDs) == 0 {
		in.AssetIDs = []string{"a"}
	}
	if in.Command == "" && in.TemplateID == "" {
		in.Command = "private-command"
	}
	if in.Kind == "" {
		in.Kind = "batch"
	}
	prepared, revision, err := s.Prepare("owner", in)
	require.NoError(t, err)
	p, err := s.CreatePlan("owner", "owner", prepared, revision)
	require.NoError(t, err)
	return p
}
func lastRun(t *testing.T, s *Service, p Plan) Run {
	t.Helper()
	current, err := s.Plan(p.ID)
	require.NoError(t, err)
	r, err := s.Run(current.LastRunID)
	require.NoError(t, err)
	return r
}
func TestTemplatesArePrivateRevisionedEncryptedSnapshots(t *testing.T) {
	s, _, _ := setup(t, nil)
	template, err := s.SaveTemplate("", "owner", "owner", TemplateInput{Name: "health", Command: "private-command", TimeoutSeconds: 15})
	require.NoError(t, err)
	assert.Equal(t, 1, template.Revision)
	assert.Empty(t, s.Templates("foreign"))
	_, err = s.SaveTemplate(template.ID, "foreign", "foreign", template.TemplateInput)
	assert.ErrorIs(t, err, ErrNotFound)
	p := plan(t, s, PlanInput{TemplateID: template.ID})
	_, _, err = s.Prepare("foreign", PlanInput{Name: "foreign", AssetIDs: []string{"a"}, Kind: "batch", TemplateID: template.ID, RequestID: "foreign"})
	assert.ErrorIs(t, err, ErrNotFound)
	changed := template.TemplateInput
	changed.Command = "changed-command"
	updated, err := s.SaveTemplate(template.ID, "owner", "owner", changed)
	require.NoError(t, err)
	assert.Equal(t, 2, updated.Revision)
	_, err = s.SaveTemplate(template.ID, "owner", "owner", changed)
	assert.ErrorIs(t, err, ErrConflict)
	assert.ErrorIs(t, s.DeleteTemplate(template.ID, "owner", 1), ErrConflict)
	require.NoError(t, s.DeleteTemplate(template.ID, "owner", 2))
	stored, err := s.Plan(p.ID)
	require.NoError(t, err)
	assert.Equal(t, "private-command", stored.Command)
	assert.Equal(t, 1, stored.TemplateRevision)
	bytes, err := os.ReadFile(s.path)
	require.NoError(t, err)
	assert.NotContains(t, string(bytes), "private-command")
	assert.NotContains(t, string(bytes), "health")
	restored, err := Open(s.path, make([]byte, 32), nil, s.jobs)
	require.NoError(t, err)
	defer restored.Close()
	loaded, err := restored.Plan(p.ID)
	require.NoError(t, err)
	assert.Equal(t, stored, loaded)
	_, err = Open(s.path, bytesKey(1), nil, s.jobs)
	require.Error(t, err)
}
func bytesKey(value byte) []byte { return []byte(strings.Repeat(string([]byte{value}), 32)) }
func TestBatchQueuesAtCapacityAndCancelsAllMembers(t *testing.T) {
	var started atomic.Int32
	s, js, now := setup(t, func(ctx context.Context, _, _ string) (sshclient.ExecResult, error) {
		started.Add(1)
		<-ctx.Done()
		return sshclient.ExecResult{ExitCode: -1}, ctx.Err()
	})
	p := plan(t, s, PlanInput{AssetIDs: []string{"c", "b", "a"}})
	s.Tick()
	run := lastRun(t, s, p)
	assert.Equal(t, []string{"a", "b", "c"}, []string{run.Items[0].AssetID, run.Items[1].AssetID, run.Items[2].AssetID})
	assert.Equal(t, "pending", run.Items[2].State)
	assert.Equal(t, "capacity", run.Items[2].ErrorCode)
	require.Eventually(t, func() bool { return started.Load() == 2 }, time.Second, time.Millisecond)
	require.NoError(t, js.Cancel(run.Items[0].JobID))
	require.Eventually(t, func() bool { j, _ := js.Get(run.Items[0].JobID); return j.State == "cancelled" }, time.Second, time.Millisecond)
	*now = now.Add(2 * time.Second)
	s.Tick()
	run = lastRun(t, s, p)
	assert.NotEmpty(t, run.Items[2].JobID)
	require.NoError(t, s.CancelRun(run.ID))
	s.Tick()
	run = lastRun(t, s, p)
	assert.Equal(t, "cancelled", run.State)
	for _, item := range run.Items {
		if item.JobID != "" {
			require.Eventually(t, func() bool { j, _ := js.Get(item.JobID); return j.State == "cancelled" }, time.Second, time.Millisecond)
		}
	}
	totalRuns, total := s.Runs("foreign", 0, 50)
	assert.Empty(t, totalRuns)
	assert.Zero(t, total)
}
func TestOnceAndIntervalCoalesceWithoutOverlapAndCanPause(t *testing.T) {
	s, _, now := setup(t, func(ctx context.Context, _, _ string) (sshclient.ExecResult, error) {
		<-ctx.Done()
		return sshclient.ExecResult{}, ctx.Err()
	})
	once := plan(t, s, PlanInput{Name: "once", Kind: "once", RunAt: now.Add(time.Minute)})
	interval := plan(t, s, PlanInput{Name: "interval", Kind: "interval", IntervalSeconds: 60})
	s.Tick()
	_, count := s.Runs("", 0, 100)
	assert.Zero(t, count)
	*now = now.Add(10 * time.Minute)
	s.Tick()
	_, count = s.Runs("", 0, 100)
	assert.Equal(t, 2, count)
	original := lastRun(t, s, interval)
	s.Tick()
	_, count = s.Runs("", 0, 100)
	assert.Equal(t, 2, count)
	assert.ErrorIs(t, s.SetEnabled(once.ID, true), ErrConflict)
	*now = now.Add(time.Minute)
	s.Tick()
	current, err := s.Plan(interval.ID)
	require.NoError(t, err)
	assert.Equal(t, "previous_run_active", current.ErrorCode)
	assert.Equal(t, original.ID, current.LastRunID)
	require.NoError(t, s.SetEnabled(interval.ID, false))
	*now = now.Add(time.Hour)
	s.Tick()
	_, count = s.Runs("", 0, 100)
	assert.Equal(t, 2, count)
	require.NoError(t, s.SetEnabled(interval.ID, true))
	current, err = s.Plan(interval.ID)
	require.NoError(t, err)
	assert.Equal(t, now.Add(time.Minute), current.NextRun)
	require.NoError(t, s.CancelRun(original.ID))
	*now = now.Add(time.Minute)
	s.Tick()
	newRun := lastRun(t, s, interval)
	assert.NotEqual(t, original.ID, newRun.ID)
}
func TestDurableClaimRecoveryLinksExistingJobButNeverReplaysUnknownDispatch(t *testing.T) {
	s, js, _ := setup(t, nil)
	p := plan(t, s, PlanInput{AssetIDs: []string{"a", "b"}})
	s.submit = nil
	s.Tick()
	run := lastRun(t, s, p)
	j, err := js.Submit(jobInput(run, "a"), "owner", "owner", "a", "ops", "review", "")
	require.NoError(t, err)
	require.NoError(t, s.mutate(func(next *state) error {
		r := next.Runs[run.ID]
		for i := range r.Items {
			r.Items[i].State = "dispatching"
		}
		next.Runs[r.ID] = r
		return nil
	}))
	s.Close()
	restored, err := Open(s.path, make([]byte, 32), nil, js)
	require.NoError(t, err)
	defer restored.Close()
	recovered, err := restored.Run(run.ID)
	require.NoError(t, err)
	assert.Equal(t, j.ID, recovered.Items[0].JobID)
	assert.Equal(t, "pending_review", recovered.Items[0].State)
	assert.Equal(t, "interrupted", recovered.Items[1].State)
	var calls int
	restored.submit = func(string, jobs.Input, string) (Submission, error) { calls++; return Submission{}, nil }
	restored.Tick()
	assert.Zero(t, calls)
	input := jobInput(run, strings.Repeat("a", 128))
	_, err = jobs.Validate(input)
	require.NoError(t, err)
}
func TestWaitingReviewDenialFailureAndPartialResults(t *testing.T) {
	s, js, now := setup(t, nil)
	p := plan(t, s, PlanInput{AssetIDs: []string{"a", "b", "c", "d"}})
	s.submit = func(owner string, in jobs.Input, review string) (Submission, error) {
		switch in.AssetID {
		case "b":
			if review == "" {
				return Submission{ReviewID: "login-review"}, nil
			}
			assert.Equal(t, "login-review", review)
			return Submission{}, ErrDenied
		case "c":
			return Submission{}, errors.New("audit unavailable")
		case "d":
			j, e := js.Submit(in, owner, owner, "d", "ops", "review", "")
			return Submission{Job: j}, e
		default:
			j, e := js.Submit(in, owner, owner, "a", "ops", "allow", "")
			return Submission{Job: j}, e
		}
	}
	s.Tick()
	r := lastRun(t, s, p)
	assert.Equal(t, "waiting_review", r.Items[1].State)
	assert.Equal(t, "failed", r.Items[2].State)
	assert.Equal(t, "pending_review", r.Items[3].State)
	require.Eventually(t, func() bool { j, _ := js.Get(r.Items[0].JobID); return j.State == "succeeded" }, time.Second, time.Millisecond)
	*now = now.Add(2 * time.Second)
	s.Tick()
	r = lastRun(t, s, p)
	assert.Equal(t, "denied", r.Items[1].State)
	assert.Equal(t, "waiting_review", r.State)
	_, err := js.Review(r.Items[3].JobID, "admin", false)
	require.NoError(t, err)
	s.Tick()
	assert.Equal(t, "partial", lastRun(t, s, p).State)
}
func TestFailClosedBeforeDispatchAndOldLeaderStopsWriting(t *testing.T) {
	s, _, _ := setup(t, nil)
	p := plan(t, s, PlanInput{})
	s.submit = nil
	s.Tick()
	r := lastRun(t, s, p)
	originalPath := s.path
	blocked := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocked, []byte("x"), 0600))
	s.path = filepath.Join(blocked, "operations.json")
	calls := 0
	s.submit = func(string, jobs.Input, string) (Submission, error) { calls++; return Submission{}, nil }
	s.Tick()
	assert.Zero(t, calls)
	s.path = originalPath
	s.Abandon()
	before, err := os.ReadFile(s.path)
	require.NoError(t, err)
	s.Tick()
	assert.ErrorIs(t, s.CancelRun(r.ID), ErrBusy)
	after, err := os.ReadFile(s.path)
	require.NoError(t, err)
	assert.Equal(t, before, after)
}
func TestValidationAndHistoryCapacity(t *testing.T) {
	s, _, now := setup(t, nil)
	base := PlanInput{Name: "name", AssetIDs: []string{"a"}, Command: "whoami", Kind: "batch", RequestID: "request"}
	tests := []PlanInput{func() PlanInput { x := base; x.AssetIDs = []string{"a", "a"}; return x }(), func() PlanInput { x := base; x.Kind = "once"; x.RunAt = *now; return x }(), func() PlanInput { x := base; x.Kind = "interval"; x.IntervalSeconds = 59; return x }(), func() PlanInput { x := base; x.Kind = "cron"; return x }(), func() PlanInput { x := base; x.RequestID = ""; return x }()}
	for _, in := range tests {
		_, _, err := s.Prepare("owner", in)
		assert.ErrorIs(t, err, ErrInvalid)
	}
	p := plan(t, s, base)
	same := plan(t, s, base)
	assert.Equal(t, p.ID, same.ID)
	changed := base
	changed.Command = "other"
	prepared, rev, err := s.Prepare("owner", changed)
	require.NoError(t, err)
	_, err = s.CreatePlan("owner", "owner", prepared, rev)
	assert.ErrorIs(t, err, ErrConflict)
	require.NoError(t, s.mutate(func(next *state) error {
		for i := range 1000 {
			id := time.Unix(int64(i), 0).String()
			next.Runs[id] = Run{ID: id, OwnerID: "history", State: "failed", Items: []Item{{AssetID: "a", State: "failed"}}}
		}
		return nil
	}))
	s.Tick()
	paused, err := s.Plan(p.ID)
	require.NoError(t, err)
	assert.False(t, paused.Enabled)
	assert.Equal(t, "history_full", paused.ErrorCode)
}
func TestOperationsPostgresPersistence(t *testing.T) {
	url := os.Getenv("JMS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for operations PostgreSQL integration")
	}
	docs, err := storage.OpenPostgres(context.Background(), url, "operations-test-"+time.Now().Format("150405.000000000"))
	require.NoError(t, err)
	defer docs.Close()
	defer docs.Delete("operations")
	_, js, _ := setup(t, nil)
	s, err := Open(filepath.Join(t.TempDir(), "operations.json"), make([]byte, 32), docs, js)
	require.NoError(t, err)
	p := plan(t, s, PlanInput{WorkingDirectory: "/srv/work/deploy"})
	s.submit = nil
	s.Tick()
	s.Close()
	data, err := docs.Load("operations")
	require.NoError(t, err)
	assert.NotContains(t, string(data), "private-command")
	next, err := Open(filepath.Join(t.TempDir(), "operations.json"), make([]byte, 32), docs, js)
	require.NoError(t, err)
	defer next.Close()
	assert.Equal(t, "pending", lastRun(t, next, p).Items[0].State)
	assert.Equal(t, p.WorkingDirectory, lastRun(t, next, p).WorkingDirectory)
	loaded, err := next.Plan(p.ID)
	require.NoError(t, err)
	assert.Equal(t, p.WorkingDirectory, loaded.WorkingDirectory)
}
