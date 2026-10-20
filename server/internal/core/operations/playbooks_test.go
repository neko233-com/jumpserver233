package operations

import (
	"context"
	"errors"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/playbooks"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func nativePlan(t *testing.T, s *Service, source string, kind string) (PlaybookDetail, Plan) {
	t.Helper()
	book, e := s.SavePlaybook("", "owner", "owner", PlaybookInput{Name: "native workspace", Files: map[string]string{"main.yml": source}}, false)
	require.NoError(t, e)
	in := PlanInput{Name: "native plan", AssetIDs: []string{"a"}, PlaybookID: book.ID, Kind: kind, RequestID: "native-request", IntervalSeconds: 60, Origin: accesspolicies.Origin{Method: "exec", SourceIP: "127.0.0.1"}}
	if kind != "interval" {
		in.IntervalSeconds = 0
	}
	prepared, revision, e := s.Prepare("owner", in)
	require.NoError(t, e)
	p, e := s.CreatePlan("owner", "owner", prepared, revision)
	require.NoError(t, e)
	return book, p
}
func nativeSetup(t *testing.T, exec jobs.Executor) (*Service, *jobs.Service, *time.Time) {
	t.Helper()
	s, js, now := setup(t, exec)
	js.SetExecutionGuard(func(jobs.Job) error { return nil })
	s.SetPlaybookAuthorizer(func(string, string, accesspolicies.Origin) error { return nil })
	return s, js, now
}
func finishNative(t *testing.T, s *Service, now *time.Time, p Plan) Run {
	t.Helper()
	var r Run
	require.Eventually(t, func() bool {
		*now = now.Add(time.Second)
		s.Tick()
		current, _ := s.Plan(p.ID)
		r, _ = s.Run(current.LastRunID)
		return r.ID != "" && terminalRun(r.State)
	}, 5*time.Second, 2*time.Millisecond)
	return r
}
func TestNativePlaybookCatalogSnapshotsAndEncryptedCurrentVersion(t *testing.T) {
	s, _, _ := nativeSetup(t, nil)
	source := "- tasks: [{debug: {msg: original}}]"
	book, p := nativePlan(t, s, source, "interval")
	_, e := s.Playbook(book.ID, "foreign")
	assert.ErrorIs(t, e, ErrNotFound)
	_, e = s.SavePlaybook(book.ID, "foreign", "foreign", PlaybookInput{Name: "theft", Revision: 1, Visibility: "private", Files: book.Files}, true)
	assert.ErrorIs(t, e, ErrNotFound)
	input := PlaybookInput{Name: "shared", Revision: 1, Visibility: "organization", Files: map[string]string{"main.yml": "- tasks: [{debug: {msg: changed}}]"}}
	_, e = s.SavePlaybook(book.ID, "owner", "owner", input, false)
	assert.ErrorIs(t, e, ErrDenied)
	updated, e := s.SavePlaybook(book.ID, "owner", "owner", input, true)
	require.NoError(t, e)
	assert.Equal(t, 2, updated.Revision)
	_, e = s.SavePlaybook(book.ID, "owner", "owner", input, true)
	assert.ErrorIs(t, e, ErrConflict)
	_, e = s.Playbook(book.ID, "foreign")
	require.NoError(t, e)
	events, n, e := s.PlaybookEvents(book.ID, "owner", 0, 25)
	require.NoError(t, e)
	assert.Equal(t, 2, n)
	assert.Equal(t, "updated", events[0].Action)
	require.NoError(t, s.DeletePlaybook(book.ID, "owner", 2))
	saved, e := s.Plan(p.ID)
	require.NoError(t, e)
	assert.Equal(t, book.ProgramID, saved.ProgramID)
	assert.Equal(t, 1, saved.PlaybookRevision)
	r, e := s.TriggerPlan(p.ID, "manual-one", ScheduleActor{"owner", "owner"}, p.AccessOrigin)
	require.NoError(t, e)
	program, e := s.RunProgram(r.ID, "owner", false)
	require.NoError(t, e)
	assert.Equal(t, source, program.Files["main.yml"])
	_, e = s.RunProgram(r.ID, "foreign", false)
	assert.ErrorIs(t, e, ErrNotFound)
	raw, e := os.ReadFile(s.path)
	require.NoError(t, e)
	assert.Contains(t, string(raw), `"version":6`)
	assert.NotContains(t, string(raw), "original")
	restored, e := Open(s.path, make([]byte, 32), nil, s.jobs)
	require.NoError(t, e)
	defer restored.Close()
	loaded, e := restored.Run(r.ID)
	require.NoError(t, e)
	assert.Equal(t, r.ProgramID, loaded.ProgramID)
}
func TestNativePlaybookLoopsFactsConditionsHandlersAndPrivacy(t *testing.T) {
	var calls atomic.Int32
	s, _, now := nativeSetup(t, func(context.Context, string, string) (sshclient.ExecResult, error) {
		calls.Add(1)
		return sshclient.ExecResult{ExitCode: 0, Stdout: "ready\nJMS233_NATIVE_STATUS=changed\n"}, nil
	})
	_, p := nativePlan(t, s, `- hosts: all
  vars: {message: ready}
  tasks:
    - set_fact: {desired: ready}
    - command: {argv: [printf, '%s', '{{ item }}']}
      loop: [one, two]
      register: results
      notify: refreshed
    - assert: {that: 'results.results[0].rc == 0 and desired == message'}
    - fail: {msg: ignored}
      ignore_errors: true
    - fail: {msg: never}
      when: false
    - debug: {msg: never}
      loop: []
  handlers:
    - name: refreshed
      debug: {msg: handled}
    - name: untouched
      fail: {msg: never}
`, "batch")
	r := finishNative(t, s, now, p)
	require.Equal(t, "succeeded", r.State, r.Items)
	assert.Equal(t, int32(2), calls.Load())
	require.Len(t, r.Items[0].Steps, 9)
	assert.True(t, r.Items[0].Steps[4].Ignored)
	assert.Equal(t, "skipped", r.Items[0].Steps[8].State)
	for _, step := range r.Items[0].Steps {
		assert.True(t, step.Final)
		assert.Empty(t, step.Command)
	}
	out, e := s.StepOutput(r.ID, "a", r.Items[0].Steps[0].ID)
	require.NoError(t, e)
	assert.Equal(t, "ready", out.Extra["facts"].(map[string]any)["desired"])
	public := PublicRun(r)
	assert.Nil(t, public.Items[0].Steps[0].Local)
	public.Items[0].Steps[0].Name = "mutated"
	stored, _ := s.Run(r.ID)
	assert.NotEqual(t, "mutated", stored.Items[0].Steps[0].Name)
}
func TestNativePlaybookKnownRetriesAndTransportNeverIgnored(t *testing.T) {
	var calls atomic.Int32
	s, _, now := nativeSetup(t, func(context.Context, string, string) (sshclient.ExecResult, error) {
		if calls.Add(1) == 1 {
			return sshclient.ExecResult{ExitCode: 1}, nil
		}
		return sshclient.ExecResult{ExitCode: 0, Stdout: "\nJMS233_NATIVE_STATUS=ok\n"}, nil
	})
	_, p := nativePlan(t, s, "- tasks:\n    - command: {argv: [true]}\n      register: check\n      until: check.rc == 0\n      retries: 2\n      delay: 1\n", "batch")
	r := finishNative(t, s, now, p)
	require.Equal(t, "succeeded", r.State, r.Items)
	require.Len(t, r.Items[0].Steps, 2)
	assert.Equal(t, "retried", r.Items[0].Steps[0].State)
	assert.Equal(t, 1, r.Items[0].Steps[1].Attempt)
	s2, _, now2 := nativeSetup(t, func(context.Context, string, string) (sshclient.ExecResult, error) {
		return sshclient.ExecResult{ExitCode: -1}, errors.New("transport lost")
	})
	_, p2 := nativePlan(t, s2, "- tasks:\n    - command: {argv: [id]}\n      ignore_errors: true\n      until: result.rc == 0\n      retries: 2\n", "batch")
	r = finishNative(t, s2, now2, p2)
	assert.Equal(t, "failed", r.State)
	require.Len(t, r.Items[0].Steps, 1)
	assert.False(t, r.Items[0].Steps[0].Ignored)
}
func TestNativePlaybookRevocationDeadlineCancelAndManualDeduplication(t *testing.T) {
	s, _, now := nativeSetup(t, nil)
	_, p := nativePlan(t, s, "- tasks: [{pause: {seconds: 60}}, {debug: {msg: never}}]", "interval")
	before := p.NextRun
	r, e := s.TriggerPlan(p.ID, "manual", ScheduleActor{"actor", "Actor"}, p.AccessOrigin)
	require.NoError(t, e)
	again, e := s.TriggerPlan(p.ID, "manual", ScheduleActor{"actor", "Actor"}, p.AccessOrigin)
	require.NoError(t, e)
	assert.Equal(t, r.ID, again.ID)
	stored, _ := s.Plan(p.ID)
	assert.Equal(t, before, stored.NextRun)
	_, e = s.TriggerPlan(p.ID, "overlap", ScheduleActor{"actor", "Actor"}, p.AccessOrigin)
	assert.ErrorIs(t, e, ErrConflict)
	s.Tick()
	r, _ = s.Run(r.ID)
	require.Len(t, r.Items[0].Steps, 1)
	assert.Equal(t, "waiting", r.Items[0].Steps[0].State)
	s.SetPlaybookAuthorizer(func(string, string, accesspolicies.Origin) error { return ErrDenied })
	s.Tick()
	r, _ = s.Run(r.ID)
	assert.Equal(t, "failed", r.State)
	assert.Equal(t, "access_denied", r.Items[0].ErrorCode)
	s.SetPlaybookAuthorizer(func(string, string, accesspolicies.Origin) error { return nil })
	r, e = s.TriggerPlan(p.ID, "deadline", ScheduleActor{"actor", "Actor"}, p.AccessOrigin)
	require.NoError(t, e)
	*now = r.Deadline.Add(time.Second)
	s.Tick()
	r, _ = s.Run(r.ID)
	assert.Equal(t, "deadline_exceeded", r.ErrorCode)
	r, e = s.TriggerPlan(p.ID, "cancel", ScheduleActor{"actor", "Actor"}, p.AccessOrigin)
	require.NoError(t, e)
	s.Tick()
	require.NoError(t, s.CancelRun(r.ID))
	r, _ = s.Run(r.ID)
	assert.Equal(t, "cancelled", r.State)
	if len(r.Items[0].Steps) > 0 {
		assert.True(t, r.Items[0].Steps[0].Final)
	}
}
func TestNativePlaybookRecoveryNeverReplaysAmbiguousClaim(t *testing.T) {
	s, js, _ := nativeSetup(t, nil)
	_, p := nativePlan(t, s, "- tasks: [{command: {argv: [id]}}]", "batch")
	s.submit = nil
	s.Tick()
	r := lastRun(t, s, p)
	require.Len(t, r.Items[0].Steps, 1)
	step := r.Items[0].Steps[0]
	meta := playbooks.Execution{RunID: r.ID, StepID: step.ID, ProgramID: r.ProgramID, TaskIndex: 0}
	assert.True(t, s.WorkflowJobAllowed("owner", "a", meta, step.Command, ""))
	assert.False(t, s.WorkflowJobAllowed("foreign", "a", meta, step.Command, ""))
	assert.False(t, s.WorkflowJobAllowed("owner", "a", meta, "forged", ""))
	require.NoError(t, s.mutateStep(r.ID, 0, step.ID, func(c *StepResult, _ *Item, _ *Run) error { c.State = "dispatching"; return nil }))
	restored, e := Open(s.path, make([]byte, 32), nil, js)
	require.NoError(t, e)
	defer restored.Close()
	loaded, e := restored.Run(r.ID)
	require.NoError(t, e)
	assert.Equal(t, "interrupted", loaded.Items[0].State)
	assert.Equal(t, "dispatch_interrupted", loaded.Items[0].ErrorCode)
	assert.False(t, strings.Contains(loaded.Items[0].ErrorCode, "id"))
}
func TestNativePlaybookPostgresScopeTakeover(t *testing.T) {
	dsn := os.Getenv("JMS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for native Playbook takeover")
	}
	docs, e := storage.OpenPostgres(context.Background(), dsn, fmt.Sprintf("playbook-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	defer docs.Close()
	a, e := docs.Scoped("a")
	require.NoError(t, e)
	b, e := docs.Scoped("b")
	require.NoError(t, e)
	_, js, _ := nativeSetup(t, nil)
	first, e := Open(filepath.Join(t.TempDir(), "ops.json"), make([]byte, 32), a, js)
	require.NoError(t, e)
	book, p := nativePlan(t, first, "- tasks: [{debug: {msg: takeover}}]", "interval")
	first.Close()
	second, e := Open(filepath.Join(t.TempDir(), "ops.json"), make([]byte, 32), a, js)
	require.NoError(t, e)
	defer second.Close()
	recovered, e := second.Plan(p.ID)
	require.NoError(t, e)
	assert.Equal(t, p.ProgramID, recovered.ProgramID)
	source, e := second.Playbook(book.ID, "owner")
	require.NoError(t, e)
	assert.Equal(t, book.Files, source.Files)
	other, e := Open(filepath.Join(t.TempDir(), "ops.json"), make([]byte, 32), b, js)
	require.NoError(t, e)
	defer other.Close()
	_, e = other.Playbook(book.ID, "owner")
	assert.ErrorIs(t, e, ErrNotFound)
}
func TestNativePlaybookRejectsCorruptProgramAndReservationOverflow(t *testing.T) {
	s, _, _ := nativeSetup(t, nil)
	_, p := nativePlan(t, s, "- tasks: [{debug: {msg: safe}}]", "interval")
	st := clone(s.data)
	require.NoError(t, validatePrograms(&st, 4))
	program := playbooks.CloneProgram(st.Programs[p.ProgramID])
	program.Tasks[0].Name = "tampered"
	st.Programs[p.ProgramID] = program
	assert.Error(t, validatePrograms(&st, 4))
	st = clone(s.data)
	assert.Error(t, validatePrograms(&st, 3))
	st.Runs["capacity"] = Run{StepReservation: 20000}
	assert.False(t, canReservePlaybook(&st, p))
	assert.False(t, programCapacity(&state{Programs: map[string]playbooks.Program{"large": {Files: map[string]string{"large": strings.Repeat("x", 8<<20)}}}}))
}
