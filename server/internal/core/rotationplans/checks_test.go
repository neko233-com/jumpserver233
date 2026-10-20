package rotationplans

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/reporting"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func checkFixture(t *testing.T) (*Service, *rotationFixture, string, *atomic.Int32, *atomic.Bool) {
	t.Helper()
	s, f, path := newFixture(t)
	calls := &atomic.Int32{}
	allowed := &atomic.Bool{}
	allowed.Store(true)
	r := f.runner()
	r.AuthorizeCheck = func(Actor) error {
		if !allowed.Load() {
			return ErrDenied
		}
		return nil
	}
	r.Check = func(ctx context.Context, in Intent, guard func() error) (Outcome, error) {
		if e := guard(); e != nil {
			return Outcome{State: "denied", Code: "denied"}, e
		}
		assert.Empty(t, in.FixedPassword)
		assert.Empty(t, in.FixedSecretID)
		assert.True(t, in.PasswordPolicy.IsZero())
		calls.Add(1)
		return Outcome{State: "succeeded", CheckDurationMS: 3}, nil
	}
	s.SetRunner(r)
	return s, f, path, calls, allowed
}

func TestAccountCheckDoesNotRotateOrCopyFixedCandidatesAndChecksEachAlias(t *testing.T) {
	s, f, _, calls, allowed := checkFixture(t)
	v := f.targets["account-alias"]
	v.Group = f.targets["account-a"].Group
	f.targets["account-alias"] = v
	r := s.runnerSnapshot()
	r.AuthorizeFixed = func(Actor) error { return nil }
	s.SetRunner(r)
	in := fixedInput("check-fixed-plan")
	in.Targets = []Selection{{AccountID: "account-a"}, {AccountID: "account-alias"}}
	p, e := s.SaveRequest(context.Background(), testActor(), "", in, false, true)
	require.NoError(t, e)
	r.AuthorizeFixed = func(Actor) error { return ErrDenied }
	s.SetRunner(r)
	f.allowed.Store(false)
	check, e := s.Check(context.Background(), testActor(), p.ID, "check-fixed-run", false)
	require.NoError(t, e)
	check = drive(t, s, check.ID)
	assert.Equal(t, "check", check.Operation)
	assert.Equal(t, "succeeded", check.State)
	assert.EqualValues(t, 2, calls.Load())
	assert.Zero(t, f.calls)
	assert.Empty(t, check.PasswordMode)
	assert.True(t, check.PasswordPolicy.IsZero())
	assert.Empty(t, s.data.Runs[check.ID].FixedPassword)
	assert.Empty(t, s.data.Runs[check.ID].FixedSecretID)
	for _, item := range check.Items {
		assert.Empty(t, item.LinkedTo)
		assert.Zero(t, item.AfterRevision)
		assert.EqualValues(t, 3, item.CheckDurationMS)
	}
	again, e := s.Check(context.Background(), testActor(), p.ID, check.RequestID, false)
	require.NoError(t, e)
	assert.Equal(t, check, again)
	assert.EqualValues(t, 2, calls.Load())
	current, e := s.Plan(p.ID)
	require.NoError(t, e)
	assert.Empty(t, current.LastRunID)
	assert.Equal(t, check.ID, current.LastCheckRunID)
	feed, e := s.NotificationFeed(context.Background(), "", time.Time{}, 50)
	require.NoError(t, e)
	assert.Empty(t, feed.Events)
	feed, e = s.CheckNotificationFeed(context.Background(), "", time.Time{}, 50)
	require.NoError(t, e)
	assert.Empty(t, feed.Events)
	allowed.Store(false)
	_, e = s.Check(context.Background(), testActor(), p.ID, check.RequestID, false)
	assert.ErrorIs(t, e, ErrDenied)
	f.allowed.Store(true)
	r.AuthorizeFixed = func(Actor) error { return nil }
	s.SetRunner(r)
	_, e = s.Submit(context.Background(), testActor(), p.ID, check.RequestID, false)
	assert.ErrorIs(t, e, ErrConflict)
}

func TestAccountCheckSharedIdentityCannotHideDeniedAliasAndRetryIsSelective(t *testing.T) {
	s, f, _, _, _ := checkFixture(t)
	v := f.targets["account-alias"]
	v.Group = f.targets["account-a"].Group
	f.targets["account-alias"] = v
	p := saveManual(t, s, "account-a", "account-alias")
	r := s.runnerSnapshot()
	var checked []string
	r.Check = func(_ context.Context, in Intent, guard func() error) (Outcome, error) {
		if e := guard(); e != nil {
			return Outcome{}, e
		}
		checked = append(checked, in.Target.AccountID)
		if in.Target.AccountID == "account-alias" {
			return Outcome{}, ErrDenied
		}
		return Outcome{State: "succeeded", CheckDurationMS: 1}, nil
	}
	s.SetRunner(r)
	run, e := s.Check(context.Background(), testActor(), p.ID, "check-every-route", false)
	require.NoError(t, e)
	run = drive(t, s, run.ID)
	assert.Equal(t, "partial", run.State)
	assert.Equal(t, "denied", run.Items[1].State)
	assert.Equal(t, []string{"account-a", "account-alias"}, checked)
	r.Check = func(_ context.Context, in Intent, guard func() error) (Outcome, error) {
		checked = append(checked, in.Target.AccountID)
		return Outcome{State: "succeeded", CheckDurationMS: 1}, guard()
	}
	s.SetRunner(r)
	child, e := s.Retry(context.Background(), testActor(), run.ID, RetryInput{RequestID: "check-repaired-route", PlanRevision: p.Revision}, false)
	require.NoError(t, e)
	child = drive(t, s, child.ID)
	assert.Equal(t, "succeeded", child.State)
	require.Len(t, child.Items, 1)
	assert.Equal(t, "account-alias", child.Items[0].AccountID)
	assert.Equal(t, []string{"account-a", "account-alias", "account-alias"}, checked)
}

func TestAccountCheckScheduleIsIndependentAndPausesOnlyChecksOnRevocation(t *testing.T) {
	s, _, _, calls, allowed := checkFixture(t)
	p, e := s.Save(context.Background(), testActor(), "", PlanInput{Name: "Independent schedules", Kind: "interval", Enabled: true, IntervalHours: 168, CheckEnabled: true, CheckIntervalHours: 1, Targets: []Selection{{AccountID: "account-a"}}}, false)
	require.NoError(t, e)
	future := time.Now().UTC().Add(7 * 24 * time.Hour)
	require.NoError(t, s.mutate(func(d *state) error { v := d.Plans[p.ID]; v.NextRun = future; d.Plans[p.ID] = v; return nil }))
	s.Tick()
	waitIdle(t, s)
	current, e := s.Plan(p.ID)
	require.NoError(t, e)
	require.NotEmpty(t, current.LastCheckRunID)
	result, e := s.Run(current.LastCheckRunID)
	require.NoError(t, e)
	assert.Equal(t, "succeeded", result.State)
	assert.True(t, result.Scheduled)
	assert.Equal(t, "check", result.Operation)
	assert.True(t, current.Enabled)
	assert.Equal(t, future, current.NextRun)
	assert.EqualValues(t, 1, calls.Load())
	rotations := 0
	require.NoError(t, s.ReportMetadata(context.Background(), func(reporting.Entry) error { rotations++; return nil }))
	assert.Zero(t, rotations)
	later := time.Now().UTC().Add(2 * time.Hour)
	s.now = func() time.Time { return later }
	allowed.Store(false)
	s.Tick()
	waitIdle(t, s)
	current, e = s.Plan(p.ID)
	require.NoError(t, e)
	assert.False(t, current.CheckEnabled)
	assert.Equal(t, "denied", current.CheckErrorCode)
	assert.True(t, current.Enabled)
	assert.Equal(t, future, current.NextRun)
	assert.True(t, current.NextCheck.IsZero())
	assert.EqualValues(t, 1, calls.Load())
}

func TestAccountCheckResultWriteFailureAndRestartNeverAuthenticateTwice(t *testing.T) {
	s, f, path, calls, _ := checkFixture(t)
	p := saveManual(t, s, "account-a")
	check, e := s.Check(context.Background(), testActor(), p.ID, "check-write-failure", false)
	require.NoError(t, e)
	writes := 0
	s.saveHook = func([]byte) error {
		writes++
		if writes >= 2 {
			return errors.New("owned check result sink failure")
		}
		return nil
	}
	s.Tick()
	waitIdle(t, s)
	assert.EqualValues(t, 1, calls.Load())
	s.Tick()
	waitIdle(t, s)
	assert.EqualValues(t, 1, calls.Load())
	runner := s.runnerSnapshot()
	s.Close()
	peer, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	defer peer.Close()
	peer.SetRunner(runner)
	interrupted, e := peer.Run(check.ID)
	require.NoError(t, e)
	assert.Equal(t, "failed", interrupted.State)
	assert.Equal(t, "interrupted", interrupted.Items[0].State)
	assert.Equal(t, "check_interrupted", interrupted.Items[0].ErrorCode)
	peer.Tick()
	waitIdle(t, peer)
	assert.EqualValues(t, 1, calls.Load())
	again, e := peer.Check(context.Background(), testActor(), p.ID, check.RequestID, false)
	require.NoError(t, e)
	assert.Equal(t, interrupted, again)
	f.mu.Lock()
	v := f.targets["account-a"]
	v.Revision++
	v.Version = strings.Repeat("f", 64)
	f.targets["account-a"] = v
	f.mu.Unlock()
	retry, e := peer.Retry(context.Background(), testActor(), check.ID, RetryInput{RequestID: "check-explicit-retry", PlanRevision: p.Revision}, false)
	require.NoError(t, e)
	retry = drive(t, peer, retry.ID)
	assert.Equal(t, "check", retry.Operation)
	assert.Equal(t, "succeeded", retry.State)
	assert.EqualValues(t, 2, calls.Load())
	assert.EqualValues(t, 2, retry.Items[0].BeforeRevision)
	assert.Zero(t, retry.Items[0].AfterRevision)
}

func TestAccountCheckCancelledQueuedAndRevokedChecksPerformNoAuthentication(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{true: "cancelled", false: "revoked"}[cancelled], func(t *testing.T) {
			s, _, _, calls, allowed := checkFixture(t)
			p := saveManual(t, s, "account-a")
			r, e := s.Check(context.Background(), testActor(), p.ID, "check-never-started", false)
			require.NoError(t, e)
			if cancelled {
				require.NoError(t, s.Cancel(r.ID, testActor(), false))
			} else {
				allowed.Store(false)
			}
			s.Tick()
			waitIdle(t, s)
			assert.Zero(t, calls.Load())
			out, e := s.Run(r.ID)
			require.NoError(t, e)
			if cancelled {
				assert.Equal(t, "cancelled", out.State)
			} else {
				assert.Equal(t, "denied", out.Items[0].State)
			}
		})
	}
}

func TestAccountCheckAuthenticatedStateValidationAndFailureNotifications(t *testing.T) {
	s, _, _, _, _ := checkFixture(t)
	p := saveManual(t, s, "account-a")
	r := s.runnerSnapshot()
	r.Check = func(context.Context, Intent, func() error) (Outcome, error) {
		return Outcome{State: "failed", Code: "authentication_failed", CheckDurationMS: 2}, nil
	}
	s.SetRunner(r)
	check, e := s.Check(context.Background(), testActor(), p.ID, "check-negative-result", false)
	require.NoError(t, e)
	check = drive(t, s, check.ID)
	feed, e := s.CheckNotificationFeed(context.Background(), "", time.Time{}, 50)
	require.NoError(t, e)
	require.Len(t, feed.Events, 1)
	assert.Equal(t, check.ID, feed.Events[0].ResourceID)
	for _, mutate := range []func(*runRecord){func(r *runRecord) { r.PasswordMode = "fixed" }, func(r *runRecord) { r.Items[0].AfterRevision = 2 }, func(r *runRecord) { r.Items[0].CheckDurationMS = -1 }, func(r *runRecord) { r.Operation = "unknown" }, func(r *runRecord) { r.FixedPassword = "unexpected-private-candidate" }} {
		d := cloneState(s.data)
		v := d.Runs[check.ID]
		mutate(&v)
		d.Runs[check.ID] = v
		assert.ErrorIs(t, validateState(d), ErrInvalid)
	}
	for _, hours := range []int{-1, 0, 721} {
		in := p.PlanInput
		in.CheckEnabled = true
		in.CheckIntervalHours = hours
		_, e = s.Save(context.Background(), testActor(), p.ID, in, false)
		assert.ErrorIs(t, e, ErrInvalid)
	}
}
