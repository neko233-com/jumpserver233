package rotationplans

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
	"time"
)

func TestRotationPlanExplicitRecoveryUsesCurrentActorSourceWithoutRepeatingChange(t *testing.T) {
	s, f, _ := newFixture(t)
	p := saveManual(t, s, "account-a")
	runner := f.runner()
	runner.Execute = func(_ context.Context, in Intent, _ func() error) (Outcome, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		f.receipts[in.RequestID] = Outcome{State: "recovery_required"}
		return f.receipts[in.RequestID], nil
	}
	other := Actor{ID: "recovery-admin", Name: "Recovery admin"}
	source := accesspolicies.Origin{SourceIP: "198.51.100.8", Method: "credential_rotation"}
	recoveries := 0
	recoveryAllowed := false
	runner.Recover = func(_ context.Context, in Intent, as Actor, guard func() error) (Outcome, error) {
		if e := guard(); e != nil {
			return Outcome{}, e
		}
		if !recoveryAllowed {
			return Outcome{State: "denied", Code: "denied"}, ErrDenied
		}
		assert.Equal(t, other, as)
		assert.Equal(t, source, in.Origin)
		assert.Equal(t, testActor(), in.Actor)
		f.mu.Lock()
		defer f.mu.Unlock()
		recoveries++
		f.receipts[in.RequestID] = Outcome{State: "succeeded", Revision: 2}
		return f.receipts[in.RequestID], nil
	}
	s.SetRunner(runner)
	run, e := s.Submit(context.Background(), testActor(), p.ID, "recover-current-authority", false)
	require.NoError(t, e)
	s.Tick()
	waitIdle(t, s)
	require.ErrorIs(t, s.Recover(run.ID, other, false, source), ErrNotFound)
	require.NoError(t, s.Recover(run.ID, other, true, source))
	s.Tick()
	waitIdle(t, s)
	denied, e := s.Run(run.ID)
	require.NoError(t, e)
	assert.Equal(t, "recovery_required", denied.State)
	assert.Equal(t, "denied", denied.Items[0].ErrorCode)
	recoveryAllowed = true
	require.NoError(t, s.Recover(run.ID, other, true, source))
	current := drive(t, s, run.ID)
	assert.Equal(t, "succeeded", current.State)
	assert.Equal(t, 1, recoveries)
	assert.Equal(t, 1, f.calls)
}
func TestRotationPlanConcurrentIdempotentSubmissionCreatesOneRun(t *testing.T) {
	s, _, _ := newFixture(t)
	p := saveManual(t, s, "account-a")
	var wg sync.WaitGroup
	ids := make(chan string, 24)
	for range 24 {
		wg.Go(func() {
			r, e := s.Submit(context.Background(), testActor(), p.ID, "same-concurrent-request", false)
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
	page, total, e := s.Runs("", 0, 100)
	require.NoError(t, e)
	assert.Len(t, page, 1)
	assert.Equal(t, 1, total)
}
func TestRotationPlanValidationAndOptimisticEdits(t *testing.T) {
	s, _, path := newFixture(t)
	p := saveManual(t, s, "account-a")
	bad := p.PlanInput
	bad.Revision = 1
	bad.Targets = append(bad.Targets, bad.Targets[0])
	_, e := s.Save(context.Background(), testActor(), p.ID, bad, false)
	assert.ErrorIs(t, e, ErrInvalid)
	changed := p.PlanInput
	changed.Name = "new metadata"
	updated, e := s.Save(context.Background(), testActor(), p.ID, changed, false)
	require.NoError(t, e)
	assert.Equal(t, 2, updated.Revision)
	_, e = s.Save(context.Background(), testActor(), p.ID, changed, false)
	assert.ErrorIs(t, e, ErrConflict)
	once := PlanInput{Name: "past one-time", Kind: "once", Enabled: true, RunAt: time.Now().Add(-time.Hour), Targets: []Selection{{AccountID: "account-a"}}}
	_, e = s.Save(context.Background(), testActor(), "", once, false)
	assert.ErrorIs(t, e, ErrInvalid)
	_, e = Open(path, []byte("different-encryption-key-32-bytes!"), nil)
	assert.Error(t, e)
	data := cloneState(s.data)
	for id, r := range data.Plans {
		r.TargetCount = 0
		data.Plans[id] = r
	}
	assert.ErrorIs(t, validateState(data), ErrInvalid)
}
