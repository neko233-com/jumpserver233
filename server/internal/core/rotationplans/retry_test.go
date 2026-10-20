package rotationplans

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func failedRetrySource(t *testing.T, aliases bool) (*Service, *rotationFixture, Plan, Run, string) {
	t.Helper()
	s, f, path := newFixture(t)
	if aliases {
		v := f.targets["account-alias"]
		v.Group = f.targets["account-b"].Group
		f.targets["account-alias"] = v
	}
	targets := []string{"account-a", "account-b"}
	if aliases {
		targets = append(targets, "account-alias")
	}
	p := saveManual(t, s, targets...)
	runner := f.runner()
	execute := runner.Execute
	runner.Execute = func(ctx context.Context, in Intent, guard func() error) (Outcome, error) {
		if in.Target.AccountID == "account-b" {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.calls++
			out := Outcome{State: "failed", Code: "rotation_failed"}
			f.receipts[in.RequestID] = out
			return out, nil
		}
		return execute(ctx, in, guard)
	}
	s.SetRunner(runner)
	r, e := s.Submit(context.Background(), testActor(), p.ID, "retry-source", false)
	require.NoError(t, e)
	r = drive(t, s, r.ID)
	require.Equal(t, "partial", r.State)
	s.SetRunner(f.runner())
	return s, f, p, r, path
}

func TestRotationPlanRetrySelectedAliasSkipsSuccessAndKeepsDurableLineage(t *testing.T) {
	s, f, p, parent, path := failedRetrySource(t, true)
	in := RetryInput{RequestID: "retry-alias", PlanRevision: p.Revision, ItemIDs: []string{parent.Items[2].ID}}
	origin := accesspolicies.Origin{SourceIP: "198.51.100.7", Method: "credential_rotation"}
	child, e := s.Retry(context.Background(), testActor(), parent.ID, in, false, origin)
	require.NoError(t, e)
	assert.Len(t, child.Items, 2)
	assert.Equal(t, parent.ID, child.ParentRunID)
	assert.Equal(t, origin, child.AccessOrigin)
	assert.False(t, child.RetryAll)
	assert.Equal(t, child.Items[0].ID, child.Items[1].LinkedTo)
	for _, item := range child.Items {
		assert.NotEqual(t, "account-a", item.AccountID)
	}
	child = drive(t, s, child.ID)
	assert.Equal(t, "succeeded", child.State)
	assert.Equal(t, 3, f.calls)
	old, e := s.Run(parent.ID)
	require.NoError(t, e)
	assert.Empty(t, old.Items[0].RetryRunID)
	assert.Equal(t, child.ID, old.Items[1].RetryRunID)
	assert.Equal(t, child.ID, old.Items[2].RetryRunID)
	again, e := s.Retry(context.Background(), testActor(), parent.ID, in, false)
	require.NoError(t, e)
	assert.Equal(t, child, again)
	_, e = s.Submit(context.Background(), testActor(), p.ID, in.RequestID, false)
	assert.ErrorIs(t, e, ErrConflict)
	_, e = s.Retry(context.Background(), testActor(), parent.ID, RetryInput{RequestID: "different-retry", PlanRevision: p.Revision}, false)
	assert.ErrorIs(t, e, ErrConflict)
	changed := in
	changed.ItemIDs = []string{parent.Items[1].ID}
	_, e = s.Retry(context.Background(), testActor(), parent.ID, changed, false)
	assert.ErrorIs(t, e, ErrConflict)
	s.Close()
	peer, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	defer peer.Close()
	peer.SetRunner(f.runner())
	again, e = peer.Retry(context.Background(), testActor(), parent.ID, in, false)
	require.NoError(t, e)
	assert.Equal(t, child, again)
	f.allowed.Store(false)
	_, e = peer.Retry(context.Background(), testActor(), parent.ID, in, false)
	assert.ErrorIs(t, e, ErrDenied)
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), parent.ID)
}

func TestRotationPlanRetryConcurrentRequestsClaimOneAttempt(t *testing.T) {
	s, _, p, parent, _ := failedRetrySource(t, false)
	in := RetryInput{RequestID: "retry-concurrent", PlanRevision: p.Revision}
	var wg sync.WaitGroup
	ids := make(chan string, 20)
	for range 20 {
		wg.Go(func() {
			r, e := s.Retry(context.Background(), testActor(), parent.ID, in, false)
			assert.NoError(t, e)
			ids <- r.ID
		})
	}
	wg.Wait()
	close(ids)
	first := ""
	for id := range ids {
		if first == "" {
			first = id
		}
		assert.Equal(t, first, id)
	}
	rows, total, e := s.Runs(p.ID, 0, 100)
	require.NoError(t, e)
	assert.Equal(t, 2, total)
	assert.Len(t, rows, 2)
	_, e = s.Retry(context.Background(), testActor(), parent.ID, RetryInput{RequestID: "competing-retry", PlanRevision: p.Revision}, false)
	assert.Error(t, e)
	audit, _, e := s.Audit(0, 100)
	require.NoError(t, e)
	count := 0
	for _, a := range audit {
		if a.Action == "retried" {
			count++
			assert.Equal(t, parent.ID, a.ParentRunID)
		}
	}
	assert.Equal(t, 1, count)
}

func TestRotationPlanRetryCurrentRevisionAndFixedSnapshot(t *testing.T) {
	s, f, _ := newFixture(t)
	runner := f.runner()
	runner.AuthorizeFixed = func(Actor) error { return nil }
	var fail atomic.Bool
	fail.Store(true)
	execute := runner.Execute
	secretSeen := ""
	runner.Execute = func(ctx context.Context, in Intent, guard func() error) (Outcome, error) {
		if fail.Load() {
			return Outcome{State: "failed"}, nil
		}
		secretSeen = in.FixedPassword
		return execute(ctx, in, guard)
	}
	s.SetRunner(runner)
	input := fixedInput("retry-fixed-save")
	p, e := s.SaveRequest(context.Background(), testActor(), "", input, false, true)
	require.NoError(t, e)
	r, e := s.Submit(context.Background(), testActor(), p.ID, "retry-fixed-source", false)
	require.NoError(t, e)
	parent := drive(t, s, r.ID)
	require.Equal(t, "failed", parent.State)
	assert.Empty(t, s.data.Runs[parent.ID].FixedPassword)
	input.Revision = p.Revision
	input.RequestID = "retry-fixed-edit"
	input.FixedPassword = "Cd3#Cd3#Cd3#Cd3#Cd3#Cd3#Cd3#Cd3#Cd3#Cd3#Cd3#Cd3#Cd3#Cd3#Cd3#Cd3#"
	p, e = s.SaveRequest(context.Background(), testActor(), p.ID, input, false, true)
	require.NoError(t, e)
	_, e = s.Retry(context.Background(), testActor(), parent.ID, RetryInput{RequestID: "retry-stale", PlanRevision: p.Revision - 1}, false)
	assert.ErrorIs(t, e, ErrConflict)
	fail.Store(false)
	in := RetryInput{RequestID: "retry-fixed-child", PlanRevision: p.Revision}
	child, e := s.Retry(context.Background(), testActor(), parent.ID, in, false)
	require.NoError(t, e)
	input.Revision = p.Revision
	input.RequestID = "retry-fixed-edit-again"
	input.FixedPassword = fixedInput("").FixedPassword
	_, e = s.SaveRequest(context.Background(), testActor(), p.ID, input, false, true)
	require.NoError(t, e)
	child = drive(t, s, child.ID)
	assert.Equal(t, "succeeded", child.State)
	assert.True(t, secretSeen != "" && secretSeen != input.FixedPassword)
	assert.Empty(t, s.data.Runs[child.ID].FixedPassword)
	public, e := json.Marshal(child)
	require.NoError(t, e)
	assert.NotContains(t, string(public), secretSeen)
	assert.NotContains(t, string(public), "fixed_secret_id")
	again, e := s.Retry(context.Background(), testActor(), parent.ID, in, false)
	require.NoError(t, e)
	assert.Equal(t, child, again)
	runner.AuthorizeFixed = func(Actor) error { return ErrDenied }
	s.SetRunner(runner)
	_, e = s.Retry(context.Background(), testActor(), parent.ID, in, false)
	assert.ErrorIs(t, e, ErrDenied)
}

func TestRotationPlanRetryRefusesUncertainSuccessInvalidAndForeignInput(t *testing.T) {
	for _, state := range []string{"succeeded", "changed", "recovery_required", "recovering", "running", "queued", ""} {
		t.Run("inspect-"+state, func(t *testing.T) {
			s, f, p, parent, _ := failedRetrySource(t, false)
			r := f.runner()
			r.Inspect = func(context.Context, Intent) (Outcome, error) { return Outcome{State: state}, nil }
			s.SetRunner(r)
			_, e := s.Retry(context.Background(), testActor(), parent.ID, RetryInput{RequestID: "retry-inspect", PlanRevision: p.Revision}, false)
			require.Error(t, e)
			old, _ := s.Run(parent.ID)
			assert.Empty(t, old.Items[1].RetryRunID)
		})
	}
	s, f, p, parent, _ := failedRetrySource(t, false)
	for _, in := range []RetryInput{{RequestID: "", PlanRevision: 1}, {RequestID: "retry", PlanRevision: 0}, {RequestID: "retry", PlanRevision: 1, ItemIDs: []string{"bad/id"}}, {RequestID: "retry", PlanRevision: 1, ItemIDs: []string{parent.Items[1].ID, parent.Items[1].ID}}} {
		_, e := s.Retry(context.Background(), testActor(), parent.ID, in, false)
		assert.ErrorIs(t, e, ErrInvalid)
	}
	for _, ids := range [][]string{{"unknown-item"}, {parent.Items[0].ID}} {
		_, e := s.Retry(context.Background(), testActor(), parent.ID, RetryInput{RequestID: "retry-invalid-selection", PlanRevision: p.Revision, ItemIDs: ids}, false)
		assert.ErrorIs(t, e, ErrConflict)
	}
	_, e := s.Retry(context.Background(), Actor{ID: "other", Name: "Other"}, parent.ID, RetryInput{RequestID: "retry-foreign", PlanRevision: p.Revision}, false)
	assert.ErrorIs(t, e, ErrNotFound)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = s.Retry(ctx, testActor(), parent.ID, RetryInput{RequestID: "retry-cancelled", PlanRevision: p.Revision}, false)
	assert.ErrorIs(t, e, context.Canceled)
	runner := f.runner()
	runner.Inspect = func(context.Context, Intent) (Outcome, error) {
		return Outcome{}, errors.New("owned inspection failure")
	}
	s.SetRunner(runner)
	_, e = s.Retry(context.Background(), testActor(), parent.ID, RetryInput{RequestID: "retry-inspection-error", PlanRevision: p.Revision}, false)
	assert.ErrorContains(t, e, "inspection failure")
}

func TestRotationPlanRetryCASRetentionAndAuthenticatedGraphValidation(t *testing.T) {
	s, f, p, parent, _ := failedRetrySource(t, false)
	runner := f.runner()
	prepare := runner.Prepare
	var change atomic.Bool
	change.Store(true)
	runner.Prepare = func(ctx context.Context, a Actor, in []Selection) ([]Prepared, error) {
		if change.Swap(false) {
			require.NoError(t, s.mutate(func(d *state) error { v := d.Plans[p.ID]; v.Revision++; d.Plans[p.ID] = v; return nil }))
		}
		return prepare(ctx, a, in)
	}
	s.SetRunner(runner)
	_, e := s.Retry(context.Background(), testActor(), parent.ID, RetryInput{RequestID: "retry-cas", PlanRevision: p.Revision}, false)
	assert.ErrorIs(t, e, ErrConflict)
	s.SetRunner(f.runner())
	p, e = s.Plan(p.ID)
	require.NoError(t, e)
	child, e := s.Retry(context.Background(), testActor(), parent.ID, RetryInput{RequestID: "retry-retention", PlanRevision: p.Revision}, false)
	require.NoError(t, e)
	child = drive(t, s, child.ID)
	for _, mutate := range []func(*state){
		func(d *state) { v := d.Runs[child.ID]; v.ParentRunID = "unknown-run"; d.Runs[child.ID] = v },
		func(d *state) { v := d.Runs[parent.ID]; v.Items[1].RetryRunID = "unknown-run"; d.Runs[parent.ID] = v },
		func(d *state) {
			v := d.Runs[child.ID]
			v.Items[0].SourceItemID = parent.Items[0].ID
			d.Runs[child.ID] = v
		},
		func(d *state) {
			v := d.Runs[child.ID]
			v.RetryItemIDs = append(v.RetryItemIDs, v.RetryItemIDs[0])
			d.Runs[child.ID] = v
		},
	} {
		d := cloneState(s.data)
		mutate(&d)
		assert.ErrorIs(t, validateState(d), ErrInvalid)
	}
	now := time.Now().UTC()
	d := cloneState(s.data)
	old := d.Runs[parent.ID]
	old.FinishedAt = now.Add(-91 * 24 * time.Hour)
	d.Runs[parent.ID] = old
	pruneRetryRuns(&d, now)
	assert.Contains(t, d.Runs, parent.ID)
	assert.Contains(t, d.Runs, child.ID)
	recent := d.Runs[child.ID]
	recent.FinishedAt = now.Add(-91 * 24 * time.Hour)
	d.Runs[child.ID] = recent
	pruneRetryRuns(&d, now)
	assert.Empty(t, d.Runs)
	public, _ := s.Run(child.ID)
	public.RetryItemIDs[0] = "changed-copy"
	again, _ := s.Run(child.ID)
	assert.False(t, slices.Contains(again.RetryItemIDs, "changed-copy"))
}

func TestRotationPlanRetryFailedChildContinuesLineageWithoutMovingSchedule(t *testing.T) {
	s, f, p, parent, _ := failedRetrySource(t, false)
	future := time.Now().UTC().Add(24 * time.Hour)
	require.NoError(t, s.mutate(func(d *state) error {
		v := d.Plans[p.ID]
		v.Kind = "interval"
		v.Enabled = true
		v.IntervalHours = 168
		v.NextRun = future
		d.Plans[p.ID] = v
		return nil
	}))
	runner := f.runner()
	runner.Execute = func(context.Context, Intent, func() error) (Outcome, error) { return Outcome{State: "failed"}, nil }
	s.SetRunner(runner)
	first, e := s.Retry(context.Background(), testActor(), parent.ID, RetryInput{RequestID: "retry-chain-first", PlanRevision: p.Revision}, false)
	require.NoError(t, e)
	first = drive(t, s, first.ID)
	require.Equal(t, "failed", first.State)
	s.SetRunner(f.runner())
	second, e := s.Retry(context.Background(), testActor(), first.ID, RetryInput{RequestID: "retry-chain-second", PlanRevision: p.Revision}, false)
	require.NoError(t, e)
	second = drive(t, s, second.ID)
	require.Equal(t, "succeeded", second.State)
	assert.Equal(t, first.ID, second.ParentRunID)
	current, e := s.Plan(p.ID)
	require.NoError(t, e)
	assert.True(t, current.Enabled)
	assert.Equal(t, future, current.NextRun)
	require.NoError(t, validateState(s.data))
}

func TestRotationPlanRetryRejectsChangedCredentialAndRevokedSelectedAuthority(t *testing.T) {
	s, f, p, parent, _ := failedRetrySource(t, false)
	f.mu.Lock()
	v := f.targets["account-b"]
	v.Revision++
	f.targets["account-b"] = v
	f.mu.Unlock()
	_, e := s.Retry(context.Background(), testActor(), parent.ID, RetryInput{RequestID: "retry-stale-credential", PlanRevision: p.Revision}, false)
	assert.ErrorIs(t, e, ErrConflict)
	f.mu.Lock()
	v.Revision--
	f.targets["account-b"] = v
	f.mu.Unlock()
	runner := f.runner()
	var permitted atomic.Bool
	permitted.Store(true)
	runner.AuthorizeTargets = func(_ Actor, targets []Selection) error {
		require.Len(t, targets, 1)
		assert.Equal(t, "account-b", targets[0].AccountID)
		if !permitted.Load() {
			return ErrDenied
		}
		return nil
	}
	s.SetRunner(runner)
	in := RetryInput{RequestID: "retry-target-authority", PlanRevision: p.Revision}
	child, e := s.Retry(context.Background(), testActor(), parent.ID, in, false)
	require.NoError(t, e)
	permitted.Store(false)
	_, e = s.Retry(context.Background(), testActor(), parent.ID, in, false)
	assert.ErrorIs(t, e, ErrDenied)
	assert.NotEmpty(t, child.ID)
}

func TestRotationPlanRetryCancelledRunStartsFreshIntentsAfterInspection(t *testing.T) {
	s, f, _ := newFixture(t)
	p := saveManual(t, s, "account-a", "account-b")
	parent, e := s.Submit(context.Background(), testActor(), p.ID, "retry-cancel-source", false)
	require.NoError(t, e)
	require.NoError(t, s.Cancel(parent.ID, testActor(), false))
	child, e := s.Retry(context.Background(), testActor(), parent.ID, RetryInput{RequestID: "retry-cancel-child", PlanRevision: p.Revision}, false)
	require.NoError(t, e)
	child = drive(t, s, child.ID)
	assert.Equal(t, "succeeded", child.State)
	assert.Len(t, child.Items, 2)
	assert.Equal(t, 2, f.calls)
}
