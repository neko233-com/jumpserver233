package releasebundle

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/servicemaintenance"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
	"github.com/stretchr/testify/require"
)

func scheduleFixture(t *testing.T) (InstallOptions, ScheduleInput) {
	t.Helper()
	opt := installFixture(t)
	_, e := install(context.Background(), opt, successfulChecker)
	require.NoError(t, e)
	acceptInstallFixture(t, opt)
	archive, sha := fixture(t, "install-v1.2.4")
	_, e = Stage(context.Background(), archive, sha, runtime.GOOS, runtime.GOARCH, opt.Root)
	require.NoError(t, e)
	return opt, ScheduleInput{Revision: 1, InstallationRevision: 1, RequestID: "schedule-request-001", ArchiveSHA256: sha, NotBefore: time.Now().UTC(), DrainTimeoutSeconds: 5}
}
func TestNativeScheduleIdempotenceRevisionsActorAndCancellation(t *testing.T) {
	ctx := context.Background()
	opt, in := scheduleFixture(t)
	v, e := SaveSchedule(ctx, opt.Root, in, "admin", "Admin")
	require.NoError(t, e)
	require.Equal(t, 2, v.Revision)
	require.Equal(t, "scheduled", v.Plan.Phase)
	again, e := SaveSchedule(ctx, opt.Root, in, "admin", "Admin")
	require.NoError(t, e)
	require.Equal(t, v.Plan.ID, again.Plan.ID)
	require.Len(t, again.Events, 1)
	_, e = SaveSchedule(ctx, opt.Root, in, "other", "Other")
	require.ErrorIs(t, e, ErrInstallConflict)
	changed := in
	changed.DrainTimeoutSeconds = 6
	_, e = SaveSchedule(ctx, opt.Root, changed, "admin", "Admin")
	require.ErrorIs(t, e, ErrInstallConflict)
	cancel := CancelScheduleInput{Revision: 2, RequestID: "schedule-cancel-001", PlanID: v.Plan.ID}
	v, e = CancelSchedule(ctx, opt.Root, cancel, "admin", "Admin")
	require.NoError(t, e)
	require.Equal(t, "cancelled", v.Plan.Phase)
	v, e = SaveSchedule(ctx, opt.Root, in, "admin", "Admin")
	require.NoError(t, e)
	require.Equal(t, "cancelled", v.Plan.Phase)
	_, e = CancelSchedule(ctx, opt.Root, cancel, "other", "Other")
	require.ErrorIs(t, e, ErrInstallConflict)
	v, e = CancelSchedule(ctx, opt.Root, cancel, "admin", "Admin")
	require.NoError(t, e)
	require.Len(t, v.Events, 2)
	in.RequestID = "schedule-request-002"
	_, e = SaveSchedule(ctx, opt.Root, in, "admin", "Admin")
	require.ErrorIs(t, e, ErrInstallConflict)
	in.Revision = v.Revision
	v, e = SaveSchedule(ctx, opt.Root, in, "admin", "Admin")
	require.NoError(t, e)
	worker := strings.Repeat("a", 32)
	v, e = transitionSchedule(ctx, opt.Root, v.Plan.ID, worker, "scheduled", "draining", "")
	require.NoError(t, e)
	v, e = transitionSchedule(ctx, opt.Root, v.Plan.ID, worker, "draining", "stopping", "")
	require.NoError(t, e)
	_, e = CancelSchedule(ctx, opt.Root, CancelScheduleInput{Revision: v.Revision, RequestID: "schedule-cancel-002", PlanID: v.Plan.ID}, "admin", "Admin")
	require.ErrorIs(t, e, ErrInstallConflict)
}
func TestNativeScheduleRejectsStaleSelectionChangedBytesAndWrongTime(t *testing.T) {
	for _, kind := range []string{"revision", "same-version", "changed-bytes", "future", "past", "bad-timeout", "invalid-digest"} {
		t.Run(kind, func(t *testing.T) {
			opt, in := scheduleFixture(t)
			switch kind {
			case "revision":
				in.InstallationRevision = 2
			case "same-version":
				in.ArchiveSHA256 = opt.ArchiveSHA256
			case "changed-bytes":
				require.NoError(t, os.WriteFile(filepath.Join(opt.Root, "releases", in.ArchiveSHA256, "web", "index.html"), []byte("changed"), 0600))
			case "future":
				in.NotBefore = time.Now().Add(367 * 24 * time.Hour)
			case "past":
				in.NotBefore = time.Now().Add(-time.Hour)
			case "bad-timeout":
				in.DrainTimeoutSeconds = 0
			case "invalid-digest":
				in.ArchiveSHA256 = "none"
			}
			_, e := SaveSchedule(context.Background(), opt.Root, in, "admin", "admin")
			require.Error(t, e)
			v, e := ScheduleState(context.Background(), opt.Root)
			require.NoError(t, e)
			require.Nil(t, v.Plan)
		})
	}
}
func TestNativeScheduleConcurrentStartAndCancelOwnOneReceipt(t *testing.T) {
	opt, in := scheduleFixture(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ids := map[string]bool{}
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := SaveSchedule(context.Background(), opt.Root, in, "admin", "admin")
			if e == nil {
				mu.Lock()
				ids[v.Plan.ID] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	require.Len(t, ids, 1)
	v, e := ScheduleState(context.Background(), opt.Root)
	require.NoError(t, e)
	require.Len(t, v.Receipts, 1)
	require.Len(t, v.Events, 1)
	candidates, e := StagedCandidates(context.Background(), opt.Root)
	require.NoError(t, e)
	require.Len(t, candidates, 1)
	require.Equal(t, in.ArchiveSHA256, candidates[0].ArchiveSHA256)
}

type maintenanceFixture struct {
	c          *servicemaintenance.Controller
	afterStart func()
	stops      int
}

func (m *maintenanceFixture) MaintenanceStatus(context.Context) (servicemaintenance.Status, error) {
	return m.c.Snapshot(), nil
}
func (m *maintenanceFixture) SetMaintenance(_ context.Context, in servicemaintenance.Input) (servicemaintenance.Status, error) {
	v, e := m.c.Change(in, "supervisor", "Supervisor")
	if in.Draining && m.afterStart != nil {
		m.afterStart()
	}
	return v, e
}
func (m *maintenanceFixture) StopMaintenance(_ context.Context, in servicemaintenance.Input) (servicemaintenance.Status, error) {
	v, fn, e := m.c.Stop(in, "supervisor", "Supervisor")
	if e == nil {
		m.stops++
		fn()
	}
	return v, e
}
func TestSupervisorScheduleCancelAndTimeoutReopenWithoutStopping(t *testing.T) {
	for _, kind := range []string{"cancel", "timeout", "wrong-process", "changed-maintenance", "preflight-rollback"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			opt, in := scheduleFixture(t)
			state, e := SaveSchedule(ctx, opt.Root, in, "admin", "Admin")
			require.NoError(t, e)
			plan := *state.Plan
			g := workgate.New()
			c, e := servicemaintenance.New(g, true, func(servicemaintenance.Event) error { return nil })
			require.NoError(t, e)
			done := make(chan error, 1)
			c.SetStop(func() { done <- nil })
			m := &maintenanceFixture{c: c}
			pid := os.Getpid()
			if kind == "wrong-process" {
				pid++
			}
			if kind == "cancel" || kind == "timeout" || kind == "changed-maintenance" {
				release, e := g.Acquire("ssh_routes")
				require.NoError(t, e)
				defer release()
			}
			if kind == "cancel" {
				m.afterStart = func() {
					s, e := ScheduleState(ctx, opt.Root)
					require.NoError(t, e)
					_, e = CancelSchedule(ctx, opt.Root, CancelScheduleInput{Revision: s.Revision, RequestID: "supervisor-cancel-01", PlanID: plan.ID}, "admin", "Admin")
					require.NoError(t, e)
				}
			}
			if kind == "changed-maintenance" {
				m.afterStart = func() {
					s := c.Snapshot()
					_, e = c.Change(servicemaintenance.Input{Instance: s.Instance, Revision: s.Revision, RequestID: "operator-change-01", Draining: false}, "admin", "Admin")
					require.NoError(t, e)
				}
			}
			installed, e := InstallationStatus(ctx, opt.Root)
			require.NoError(t, e)
			stopped, e := performScheduledInstall(ctx, SupervisorOptions{Root: opt.Root, Client: m, ReadPassphrase: func() ([]byte, error) { return append([]byte(nil), opt.Passphrase...), nil }}, strings.Repeat("b", 32), observedChild{pid, installed.Current}, plan, done)
			require.NoError(t, e)
			if kind == "preflight-rollback" {
				require.True(t, stopped)
				require.Equal(t, 1, m.stops)
			} else {
				require.False(t, stopped)
				require.Zero(t, m.stops)
				require.False(t, c.Snapshot().Draining)
			}
			state, e = ScheduleState(ctx, opt.Root)
			require.NoError(t, e)
			if kind == "cancel" {
				require.Equal(t, "cancelled", state.Plan.Phase)
			} else {
				require.Equal(t, "failed", state.Plan.Phase)
			}
			installed, e = InstallationStatus(ctx, opt.Root)
			require.NoError(t, e)
			require.Equal(t, opt.ArchiveSHA256, installed.Current.ArchiveSHA256)
		})
	}
}
