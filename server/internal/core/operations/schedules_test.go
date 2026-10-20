package operations

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func instant(v string) time.Time {
	t, e := time.Parse(time.RFC3339, v)
	if e != nil {
		panic(e)
	}
	return t
}
func calendarInput(expression, zone string) Schedule {
	return Schedule{Kind: "cron", CronExpression: expression, Timezone: zone}
}
func TestCalendarPreviewSyntaxZonesUTCAndCivilTime(t *testing.T) {
	now := instant("2026-10-18T00:00:00Z")
	for _, tt := range []struct{ expr, zone, after, want string }{
		{"0 2 * * *", "Asia/Shanghai", "2026-10-18T00:00:00Z", "2026-10-18T18:00:00Z"},
		{"0 2 * * *", "Asia/Shanghai", "2026-10-18T18:00:00Z", "2026-10-19T18:00:00Z"},
		{"*/15 9-17 * JAN,MAR MON-FRI", "UTC", "2026-01-01T09:01:00Z", "2026-01-01T09:15:00Z"},
		{"0 0 13 * FRI", "UTC", "2026-02-05T01:00:00Z", "2026-02-06T00:00:00Z"},
		{"0 0 13 * FRI", "UTC", "2026-04-12T01:00:00Z", "2026-04-13T00:00:00Z"},
		{"0 0 29 FEB *", "UTC", "2096-03-01T00:00:00Z", "2104-02-29T00:00:00Z"},
	} {
		t.Run(tt.expr+tt.after, func(t *testing.T) {
			p, e := PreviewSchedule(PreviewInput{Schedule: calendarInput(tt.expr, tt.zone), After: instant(tt.after), Limit: 1}, now)
			require.NoError(t, e)
			require.Len(t, p.Occurrences, 1)
			assert.Equal(t, instant(tt.want), p.Occurrences[0].At)
			assert.NotEmpty(t, p.Occurrences[0].Local)
			assert.Equal(t, "coalesce", p.MisfirePolicy)
			assert.Equal(t, "once", p.FoldPolicy)
			assert.Equal(t, 60, p.GraceSeconds)
		})
	}
}
func TestCalendarRejectsMalformedOrEmptySchedules(t *testing.T) {
	now := instant("2026-10-18T00:00:00Z")
	cases := []Schedule{
		calendarInput("* * * * * *", "UTC"), calendarInput("@daily", "UTC"), calendarInput("*/0 * * * *", "UTC"),
		calendarInput("0 0 31 FEB *", "UTC"), calendarInput("0 0 * * 7", "UTC"), calendarInput("0 0 * * *", "Local"),
		calendarInput("CRON_TZ=UTC * * * * *", "UTC"), calendarInput("* * * * *", "../../etc/passwd"),
		calendarInput("* * * * *", "UTC\n"), calendarInput(strings.Repeat("*", 129), "UTC"),
	}
	c := calendarInput("* * * * *", "UTC")
	c.GraceSeconds = 3601
	cases = append(cases, c)
	c = calendarInput("* * * * *", "UTC")
	c.MisfirePolicy = "execute_every_missed"
	cases = append(cases, c)
	c = calendarInput("* * * * *", "UTC")
	c.FoldPolicy = "unknown"
	cases = append(cases, c)
	c = calendarInput("0 0 1 JAN *", "UTC")
	c.EndAt = now.Add(time.Hour)
	cases = append(cases, c)
	for i, c := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			_, e := PreviewSchedule(PreviewInput{Schedule: c, After: now}, now)
			assert.ErrorIs(t, e, ErrInvalid)
		})
	}
	_, e := PreviewSchedule(PreviewInput{Schedule: calendarInput("* * * * *", "UTC"), Limit: 11}, now)
	assert.ErrorIs(t, e, ErrInvalid)
	_, e = normalizeSchedule(Schedule{Kind: "interval", IntervalSeconds: 60, Timezone: "UTC"}, now, false)
	assert.ErrorIs(t, e, ErrInvalid)
	_, e = normalizeSchedule(Schedule{Kind: "cron", CronExpression: "* * * * *", Timezone: "UTC", RunAt: now}, now, false)
	assert.ErrorIs(t, e, ErrInvalid)
}
func TestCalendarDSTGapFoldWatermarkAndHalfHourTransition(t *testing.T) {
	c := calendarInput("30 2 * * *", "America/New_York")
	p, e := PreviewSchedule(PreviewInput{Schedule: c, After: instant("2026-03-07T08:00:00Z"), Limit: 1}, time.Now())
	require.NoError(t, e)
	assert.Equal(t, instant("2026-03-09T06:30:00Z"), p.Occurrences[0].At)
	for _, fold := range []string{"once", "both"} {
		c = calendarInput("30 1 * * *", "America/New_York")
		c.FoldPolicy = fold
		p, e = PreviewSchedule(PreviewInput{Schedule: c, After: instant("2026-11-01T04:00:00Z"), Limit: 3}, time.Now())
		require.NoError(t, e)
		assert.Equal(t, instant("2026-11-01T05:30:00Z"), p.Occurrences[0].At)
		want := "2026-11-02T06:30:00Z"
		if fold == "both" {
			want = "2026-11-01T06:30:00Z"
		}
		assert.Equal(t, instant(want), p.Occurrences[1].At)
	}
	c = calendarInput("* * * * *", "America/New_York")
	c.FoldPolicy = "once"
	next, e := nextCalendar(c, instant("2026-11-01T05:59:00Z"), "2026-11-01T01:59")
	require.NoError(t, e)
	assert.Equal(t, instant("2026-11-01T07:00:00Z"), next)
	c = calendarInput("45 1 * * *", "Australia/Lord_Howe")
	c.FoldPolicy = "both"
	p, e = PreviewSchedule(PreviewInput{Schedule: c, After: instant("2026-04-04T14:00:00Z"), Limit: 2}, time.Now())
	require.NoError(t, e)
	assert.Equal(t, 30*time.Minute, p.Occurrences[1].At.Sub(p.Occurrences[0].At))
	assert.Equal(t, p.Occurrences[0].Local[:16], p.Occurrences[1].Local[:16])
}
func cronPlan(t *testing.T, s *Service, policy string) Plan {
	t.Helper()
	return plan(t, s, PlanInput{Kind: "cron", CronExpression: "* * * * *", Timezone: "UTC", MisfirePolicy: policy, GraceSeconds: 60})
}
func TestCalendarMissedRunPoliciesAndNoCatchupStorm(t *testing.T) {
	for _, policy := range []string{"coalesce", "skip"} {
		t.Run(policy, func(t *testing.T) {
			s, _, now := setup(t, nil)
			*now = instant("2026-10-18T00:00:30Z")
			p := cronPlan(t, s, policy)
			assert.Equal(t, instant("2026-10-18T00:01:00Z"), p.NextRun)
			*now = instant("2026-10-18T00:10:15Z")
			s.Tick()
			current, e := s.Plan(p.ID)
			require.NoError(t, e)
			assert.Equal(t, instant("2026-10-18T00:11:00Z"), current.NextRun)
			rows, n := s.Runs("owner", 0, 100)
			if policy == "coalesce" {
				require.Equal(t, 1, n)
				assert.Equal(t, p.NextRun, rows[0].ScheduledFor)
				assert.Equal(t, int64(555), rows[0].LatenessSeconds)
				assert.True(t, rows[0].Coalesced)
				assert.Equal(t, 1, rows[0].PlanRevision)
			} else {
				assert.Zero(t, n)
				assert.Equal(t, uint64(1), current.SkippedTriggers)
				assert.Equal(t, "missed_skipped", current.ErrorCode)
			}
			s.Tick()
			_, again := s.Runs("owner", 0, 100)
			assert.Equal(t, n, again)
		})
	}
}
func TestCalendarSkipsActiveRunAndResumesWithoutReplayingMissedTimes(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	s, _, now := setup(t, func(ctx context.Context, _ string, _ string) (sshclient.ExecResult, error) {
		calls.Add(1)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return sshclient.ExecResult{}, nil
	})
	defer close(release)
	*now = instant("2026-10-18T00:00:30Z")
	p := cronPlan(t, s, "coalesce")
	*now = p.NextRun
	s.Tick()
	require.Eventually(t, func() bool { return calls.Load() == 1 }, time.Second, time.Millisecond)
	*now = now.Add(time.Minute)
	s.Tick()
	current, e := s.Plan(p.ID)
	require.NoError(t, e)
	assert.Equal(t, uint64(1), current.SkippedTriggers)
	_, n := s.Runs("owner", 0, 100)
	assert.Equal(t, 1, n)
	_, e = s.SetEnabledRevision(p.ID, false, 1, ScheduleActor{"owner", "owner"})
	require.NoError(t, e)
	*now = now.Add(5 * time.Hour)
	current, e = s.SetEnabledRevision(p.ID, true, 2, ScheduleActor{"owner", "owner"})
	require.NoError(t, e)
	assert.True(t, current.NextRun.After(*now))
	assert.Equal(t, 3, current.ConfigRevision)
	s.Tick()
	assert.Equal(t, int32(1), calls.Load())
}
func TestCalendarBoundsAndConcurrentTickClaims(t *testing.T) {
	var calls atomic.Int32
	s, _, now := setup(t, func(context.Context, string, string) (sshclient.ExecResult, error) {
		calls.Add(1)
		return sshclient.ExecResult{}, nil
	})
	*now = instant("2026-10-18T00:00:30Z")
	p := plan(t, s, PlanInput{Kind: "cron", CronExpression: "* * * * *", Timezone: "UTC", RunAt: now.Add(90 * time.Second), EndAt: now.Add(3 * time.Minute)})
	assert.Equal(t, instant("2026-10-18T00:02:00Z"), p.NextRun)
	*now = p.NextRun
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() { defer wg.Done(); s.Tick() }()
	}
	wg.Wait()
	require.Eventually(t, func() bool { return calls.Load() == 1 }, time.Second, time.Millisecond)
	_, n := s.Runs("owner", 0, 100)
	assert.Equal(t, 1, n)
	*now = p.EndAt.Add(time.Second)
	s.Tick()
	current, e := s.Plan(p.ID)
	require.NoError(t, e)
	assert.False(t, current.Enabled)
	assert.Equal(t, int32(1), calls.Load())
}
func TestCalendarEditsAuditRevisionCreationIdempotencyAndClockRollback(t *testing.T) {
	s, _, now := setup(t, nil)
	*now = instant("2026-10-18T00:00:30Z")
	raw := PlanInput{Name: "calendar", AssetIDs: []string{"a"}, Command: "private-command", Kind: "cron", CronExpression: "* * * * *", Timezone: "UTC", RunAt: now.Add(30 * time.Second), RequestID: "stable-create", Origin: accesspolicies.Origin{SourceIP: "192.0.2.9", Method: "scheduled_exec"}}
	prepared, rev, e := s.Prepare("owner", raw)
	require.NoError(t, e)
	p, e := s.CreatePlan("owner", "owner", prepared, rev)
	require.NoError(t, e)
	_, e = s.SetEnabledRevision(p.ID, false, 0, ScheduleActor{})
	assert.ErrorIs(t, e, ErrConflict)
	update := ScheduleUpdate{Revision: 1, Schedule: Schedule{Kind: "interval", IntervalSeconds: 3600}}
	edited, e := s.UpdateSchedule(p.ID, update, ScheduleActor{"manager", "manager"})
	require.NoError(t, e)
	assert.Equal(t, 2, edited.ConfigRevision)
	assert.Equal(t, p.CreationHash, edited.CreationHash)
	assert.Equal(t, p.Command, edited.Command)
	assert.Equal(t, p.AssetIDs, edited.AssetIDs)
	_, e = s.UpdateSchedule(p.ID, update, ScheduleActor{"manager", "manager"})
	assert.ErrorIs(t, e, ErrConflict)
	*now = now.Add(2 * time.Hour)
	again, found, e := s.ReplayPlan("owner", raw)
	require.NoError(t, e)
	assert.True(t, found)
	assert.Equal(t, p.ID, again.ID)
	assert.Equal(t, 2, again.ConfigRevision)
	raw.Origin.SourceIP = "192.0.2.10"
	_, _, e = s.ReplayPlan("owner", raw)
	assert.ErrorIs(t, e, ErrConflict)
	rows, n, e := s.ScheduleEvents(p.ID, 0, 20)
	require.NoError(t, e)
	assert.Equal(t, 2, n)
	assert.Equal(t, "updated", rows[0].Action)
	assert.Equal(t, "manager", rows[0].Actor.ID)
	assert.Equal(t, "cron", rows[0].Before.Kind)
	assert.Equal(t, "interval", rows[0].After.Kind)
	mutated := rows[0]
	mutated.After.Timezone = "not-stored"
	rows[0] = mutated
	rows, _, e = s.ScheduleEvents(p.ID, 0, 20)
	require.NoError(t, e)
	assert.Empty(t, rows[0].After.Timezone)
	current, _ := s.Plan(p.ID)
	current.LastScheduledAt = now.Add(time.Hour)
	s.mu.Lock()
	s.data.Plans[p.ID] = current
	s.mu.Unlock()
	current, e = s.SetEnabledRevision(p.ID, false, 2, ScheduleActor{"owner", "owner"})
	require.NoError(t, e)
	current, e = s.SetEnabledRevision(p.ID, true, 3, ScheduleActor{"owner", "owner"})
	require.NoError(t, e)
	assert.True(t, current.NextRun.After(current.LastScheduledAt))
}
func TestCalendarFailureDoesNotCommitSettingsOrAuditAndTemplateReplaySurvivesDeletion(t *testing.T) {
	s, _, now := setup(t, nil)
	tpl, e := s.SaveTemplate("", "owner", "owner", TemplateInput{Name: "snapshot", Command: "private-template", TimeoutSeconds: 12})
	require.NoError(t, e)
	raw := PlanInput{Name: "templated calendar", AssetIDs: []string{"a"}, TemplateID: tpl.ID, Kind: "cron", CronExpression: "* * * * *", Timezone: "UTC", RequestID: "template-calendar"}
	in, rev, e := s.Prepare("owner", raw)
	require.NoError(t, e)
	p, e := s.CreatePlan("owner", "owner", in, rev)
	require.NoError(t, e)
	require.NoError(t, s.DeleteTemplate(tpl.ID, "owner", tpl.Revision))
	_, found, e := s.ReplayPlan("owner", raw)
	require.NoError(t, e)
	assert.True(t, found)
	parent := filepath.Join(t.TempDir(), "not-directory")
	require.NoError(t, os.WriteFile(parent, []byte("owned fixture"), 0600))
	s.path = filepath.Join(parent, "operations.json")
	_, e = s.UpdateSchedule(p.ID, ScheduleUpdate{Revision: 1, Schedule: calendarInput("0 * * * *", "UTC")}, ScheduleActor{"owner", "owner"})
	require.Error(t, e)
	current, _ := s.Plan(p.ID)
	assert.Equal(t, p.NextRun, current.NextRun)
	assert.Equal(t, 1, current.ConfigRevision)
	_, n, e := s.ScheduleEvents(p.ID, 0, 20)
	require.NoError(t, e)
	assert.Equal(t, 1, n)
	_ = now
}
func TestCalendarEncryptedV2MigrationAndRestartRetainsFoldWatermark(t *testing.T) {
	s, js, now := setup(t, nil)
	*now = instant("2026-11-01T04:00:00Z")
	p := plan(t, s, PlanInput{Kind: "cron", CronExpression: "30 1 * * *", Timezone: "America/New_York"})
	*now = p.NextRun
	s.Tick()
	p, e := s.Plan(p.ID)
	require.NoError(t, e)
	s.Close()
	peer, e := Open(s.path, make([]byte, 32), nil, js)
	require.NoError(t, e)
	defer peer.Close()
	current, _ := peer.Plan(p.ID)
	assert.Equal(t, "2026-11-01T01:30", current.CalendarWatermark)
	assert.Equal(t, instant("2026-11-02T06:30:00Z"), current.NextRun)
	raw, e := os.ReadFile(s.path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "private-command")
	var box envelope
	require.NoError(t, json.Unmarshal(raw, &box))
	assert.Equal(t, 6, box.Version)
	peer.Close()
	// Legacy ordinary plans gain revision and immutable-create identity on open.
	legacy := clone(s.data)
	legacy.ScheduleEvents = nil
	for id, v := range legacy.Plans {
		v.Kind = "interval"
		v.IntervalSeconds = 60
		v.CronExpression = ""
		v.Timezone = ""
		v.MisfirePolicy = ""
		v.GraceSeconds = 0
		v.FoldPolicy = ""
		v.ConfigRevision = 0
		v.CreationHash = ""
		legacy.Plans[id] = v
	}
	plain, e := json.Marshal(legacy)
	require.NoError(t, e)
	box.Version = 2
	box.Ciphertext = s.aead.Seal(nil, box.Nonce, plain, []byte("jms233/operations/v2"))
	raw, e = json.Marshal(box)
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(s.path, raw, 0600))
	migrated, e := Open(s.path, make([]byte, 32), nil, js)
	require.NoError(t, e)
	defer migrated.Close()
	current, _ = migrated.Plan(p.ID)
	assert.Equal(t, 1, current.ConfigRevision)
	assert.Len(t, current.CreationHash, 64)
	raw, e = os.ReadFile(s.path)
	require.NoError(t, e)
	require.NoError(t, json.Unmarshal(raw, &box))
	assert.Equal(t, 6, box.Version)
}
func TestCalendarPostgresScopedTakeover(t *testing.T) {
	dsn := os.Getenv("JMS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for calendar takeover")
	}
	docs, e := storage.OpenPostgres(context.Background(), dsn, fmt.Sprintf("calendar-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	defer docs.Close()
	a, e := docs.Scoped("a")
	require.NoError(t, e)
	b, e := docs.Scoped("b")
	require.NoError(t, e)
	_, js, _ := setup(t, nil)
	first, e := Open(filepath.Join(t.TempDir(), "ops.json"), make([]byte, 32), a, js)
	require.NoError(t, e)
	p := plan(t, first, PlanInput{Kind: "cron", CronExpression: "0 2 * * *", Timezone: "Asia/Shanghai"})
	first.Close()
	second, e := Open(filepath.Join(t.TempDir(), "ops.json"), make([]byte, 32), a, js)
	require.NoError(t, e)
	defer second.Close()
	recovered, e := second.Plan(p.ID)
	require.NoError(t, e)
	assert.Equal(t, p.NextRun, recovered.NextRun)
	_, n, e := second.ScheduleEvents(p.ID, 0, 20)
	require.NoError(t, e)
	assert.Equal(t, 1, n)
	other, e := Open(filepath.Join(t.TempDir(), "ops.json"), make([]byte, 32), b, js)
	require.NoError(t, e)
	defer other.Close()
	assert.Empty(t, other.Plans("owner"))
}
func BenchmarkCalendarNext(b *testing.B) {
	c := calendarInput("*/5 8-18 * * MON-FRI", "America/New_York")
	after := instant("2026-10-18T00:00:00Z")
	b.ReportAllocs()
	for range b.N {
		if _, e := nextCalendar(c, after, ""); e != nil {
			b.Fatal(e)
		}
	}
}

func TestCalendarExpiredSchedulesReopenAndReplayWithoutNewWork(t *testing.T) {
	s, js, now := setup(t, nil)
	*now = instant("2020-01-01T00:00:30Z")
	raw := PlanInput{Name: "expired", AssetIDs: []string{"a"}, Command: "whoami", Kind: "cron", CronExpression: "* * * * *", Timezone: "UTC", EndAt: now.Add(2 * time.Minute), RequestID: "expired-calendar"}
	in, rev, e := s.Prepare("owner", raw)
	require.NoError(t, e)
	p, e := s.CreatePlan("owner", "owner", in, rev)
	require.NoError(t, e)
	*now = raw.EndAt
	s.Tick()
	p, e = s.Plan(p.ID)
	require.NoError(t, e)
	assert.False(t, p.Enabled)
	events, n, e := s.ScheduleEvents(p.ID, 0, 10)
	require.NoError(t, e)
	require.Equal(t, 2, n)
	assert.Equal(t, "ended", events[0].Action)
	assert.Equal(t, 2, p.ConfigRevision)
	s.Close()
	reopened, e := Open(s.path, make([]byte, 32), nil, js)
	require.NoError(t, e)
	defer reopened.Close()
	_, found, e := reopened.ReplayPlan("owner", raw)
	require.NoError(t, e)
	assert.True(t, found)
	_, count := reopened.Runs("owner", 0, 100)
	assert.Zero(t, count)
}

func TestCalendarEditRetainsPastRecurringStartAndAuditRetentionIsBounded(t *testing.T) {
	s, _, now := setup(t, nil)
	*now = instant("2026-10-18T00:00:30Z")
	p := plan(t, s, PlanInput{Kind: "cron", CronExpression: "* * * * *", Timezone: "UTC", RunAt: now.Add(30 * time.Second)})
	*now = now.Add(2 * time.Hour)
	update := scheduleOf(p.PlanInput)
	update.CronExpression = "0 3 * * *"
	edited, e := s.UpdateSchedule(p.ID, ScheduleUpdate{Revision: 1, Schedule: update}, ScheduleActor{"owner", "owner"})
	require.NoError(t, e)
	assert.Equal(t, p.RunAt, edited.RunAt)
	assert.True(t, edited.NextRun.After(*now))
	update.RunAt = now.Add(-time.Minute)
	_, e = s.UpdateSchedule(p.ID, ScheduleUpdate{Revision: 2, Schedule: update}, ScheduleActor{})
	assert.ErrorIs(t, e, ErrInvalid)
	s.mu.Lock()
	s.data.ScheduleEvents = make([]ScheduleEvent, 4000)
	for i := range s.data.ScheduleEvents {
		s.data.ScheduleEvents[i] = ScheduleEvent{ID: fmt.Sprint(i), PlanID: p.ID, At: *now, Action: "created", Revision: 1}
	}
	s.data.ScheduleEvents[0].At = now.AddDate(-2, 0, 0)
	s.mu.Unlock()
	_, e = s.SetEnabledRevision(p.ID, false, 2, ScheduleActor{"owner", "owner"})
	require.NoError(t, e)
	rows, n, e := s.ScheduleEvents(p.ID, 0, 100)
	require.NoError(t, e)
	assert.Equal(t, 4000, n)
	assert.Equal(t, "paused", rows[0].Action)
	_, e = s.SetEnabledRevision(p.ID, true, 3, ScheduleActor{"owner", "owner"})
	require.NoError(t, e)
	_, n, e = s.ScheduleEvents(p.ID, 4000, 100)
	require.NoError(t, e)
	assert.Equal(t, 4000, n)
	_, _, e = s.ScheduleEvents(p.ID, 0, 101)
	assert.ErrorIs(t, e, ErrInvalid)
}
