package rotationplans

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

type rotationFixture struct {
	mu       sync.Mutex
	allowed  atomic.Bool
	calls    int
	receipts map[string]Outcome
	targets  map[string]Prepared
}

func newFixture(t *testing.T) (*Service, *rotationFixture, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plans.json")
	s, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	t.Cleanup(s.Close)
	f := &rotationFixture{receipts: map[string]Outcome{}, targets: map[string]Prepared{}}
	f.allowed.Store(true)
	for _, id := range []string{"account-a", "account-b", "account-alias"} {
		sum := sha256.Sum256([]byte(id))
		hash := hex.EncodeToString(sum[:])
		f.targets[id] = Prepared{Ref: Ref{AssetID: "asset-" + id, AccountID: id, AssetName: "Synthetic rotation metadata", Username: "synthetic-user-" + id, CredentialType: "password"}, Version: hash, Revision: 1, Binding: hash, Group: hash, RotatedAt: time.Now().UTC().Add(-8 * 24 * time.Hour)}
	}
	s.SetRunner(f.runner())
	return s, f, path
}
func (f *rotationFixture) runner() Runner {
	return Runner{
		Authorize: func(Actor) error {
			if !f.allowed.Load() {
				return ErrDenied
			}
			return nil
		},
		Prepare: func(_ context.Context, _ Actor, ids []Selection) ([]Prepared, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			out := []Prepared{}
			for _, id := range ids {
				v, ok := f.targets[id.AccountID]
				if !ok {
					return nil, ErrNotFound
				}
				out = append(out, v)
			}
			return out, nil
		},
		Execute: func(ctx context.Context, in Intent, guard func() error) (Outcome, error) {
			if e := guard(); e != nil {
				return Outcome{}, e
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if v, ok := f.receipts[in.RequestID]; ok {
				return v, nil
			}
			f.calls++
			out := Outcome{State: "succeeded", Revision: in.Target.Revision + 1, At: time.Now().UTC()}
			f.receipts[in.RequestID] = out
			return out, nil
		},
		Inspect: func(_ context.Context, in Intent) (Outcome, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if v, ok := f.receipts[in.RequestID]; ok {
				return v, nil
			}
			return Outcome{State: "not_started"}, nil
		},
	}
}
func testActor() Actor { return Actor{ID: "rotation-owner", Name: "Rotation owner"} }
func saveManual(t *testing.T, s *Service, targets ...string) Plan {
	t.Helper()
	in := PlanInput{Name: "Synthetic rotation plan", Kind: "manual"}
	for _, id := range targets {
		in.Targets = append(in.Targets, Selection{AccountID: id})
	}
	p, e := s.Save(context.Background(), testActor(), "", in, false)
	require.NoError(t, e)
	return p
}
func waitIdle(t *testing.T, s *Service) {
	t.Helper()
	require.Eventually(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return !s.working }, 3*time.Second, 5*time.Millisecond)
}
func drive(t *testing.T, s *Service, id string) Run {
	t.Helper()
	var out Run
	require.Eventually(t, func() bool {
		s.Tick()
		var e error
		out, e = s.Run(id)
		return e == nil && terminal(out.State)
	}, 3*time.Second, 5*time.Millisecond)
	waitIdle(t, s)
	return out
}
func TestRotationPlanBatchDeduplicationEncryptedReloadAndCurrentAuthority(t *testing.T) {
	s, f, path := newFixture(t)
	alias := f.targets["account-alias"]
	alias.Group = f.targets["account-a"].Group
	f.targets["account-alias"] = alias
	p := saveManual(t, s, "account-a", "account-alias", "account-b")
	run, e := s.Submit(context.Background(), testActor(), p.ID, "batch-request", false)
	require.NoError(t, e)
	result := drive(t, s, run.ID)
	assert.Equal(t, "succeeded", result.State)
	assert.Equal(t, 2, f.calls)
	require.NotEmpty(t, result.Items[1].LinkedTo)
	assert.Equal(t, result.Items[0].ID, result.Items[1].LinkedTo)
	raw, e := json.Marshal(result)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "Binding")
	assert.NotContains(t, string(raw), "Group")
	disk, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.NotContains(t, string(disk), "Synthetic rotation metadata")
	peer, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	defer peer.Close()
	peer.SetRunner(f.runner())
	again, e := peer.Submit(context.Background(), testActor(), p.ID, "batch-request", false)
	require.NoError(t, e)
	assert.Equal(t, result, again)
	f.allowed.Store(false)
	_, e = peer.Submit(context.Background(), testActor(), p.ID, "batch-request", false)
	assert.ErrorIs(t, e, ErrDenied)
}
func TestRotationPlanResultWriteFailureUsesVaultReceiptWithoutReexecution(t *testing.T) {
	s, f, path := newFixture(t)
	p := saveManual(t, s, "account-a")
	run, e := s.Submit(context.Background(), testActor(), p.ID, "durable-request", false)
	require.NoError(t, e)
	writes := 0
	s.saveHook = func([]byte) error {
		writes++
		if writes >= 2 {
			return errors.New("owned receipt sink failure")
		}
		return nil
	}
	s.Tick()
	waitIdle(t, s)
	require.Equal(t, 1, f.calls)
	live, e := s.Run(run.ID)
	require.NoError(t, e)
	assert.Equal(t, "running", live.Items[0].State)
	s.Close()
	peer, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	defer peer.Close()
	peer.SetRunner(f.runner())
	recovered := drive(t, peer, run.ID)
	assert.Equal(t, "succeeded", recovered.State)
	assert.Equal(t, 1, f.calls)
}
func TestRotationPlanSourceChangesStayLocalAndCancellationStopsQueuedTargets(t *testing.T) {
	s, f, _ := newFixture(t)
	p := saveManual(t, s, "account-a", "account-b")
	b := f.targets["account-b"]
	b.Binding = strings.Repeat("e", 64)
	f.targets["account-b"] = b
	run, e := s.Submit(context.Background(), testActor(), p.ID, "changed-binding", false)
	require.NoError(t, e)
	result := drive(t, s, run.ID)
	assert.Equal(t, "partial", result.State)
	assert.Equal(t, 1, f.calls)
	assert.Equal(t, "changed", result.Items[1].State)
	next, e := s.Submit(context.Background(), testActor(), p.ID, "cancel-before-start", false)
	require.NoError(t, e)
	require.NoError(t, s.Cancel(next.ID, testActor(), false))
	result, e = s.Run(next.ID)
	require.NoError(t, e)
	assert.Equal(t, "cancelled", result.State)
	s.Tick()
	waitIdle(t, s)
	assert.Equal(t, 1, f.calls)
}
func TestRotationPlanSchedulesOnlyDueGroupsAndPausesRevokedOwner(t *testing.T) {
	s, f, _ := newFixture(t)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	p, e := s.Save(context.Background(), testActor(), "", PlanInput{Name: "Seven-day schedule", Kind: "interval", Enabled: true, OnlyDue: true, IntervalHours: 168, Targets: []Selection{{AccountID: "account-a"}}}, false)
	require.NoError(t, e)
	s.Tick()
	waitIdle(t, s)
	plans, _, e := s.Plans(0, 10)
	require.NoError(t, e)
	require.Len(t, plans, 1)
	first := plans[0].LastRunID
	require.NotEmpty(t, first)
	result := drive(t, s, first)
	assert.Equal(t, "succeeded", result.State)
	assert.Equal(t, 1, f.calls)
	// The route is stable but a separate seven-day scheduler just rotated it.
	a := f.targets["account-a"]
	a.RotatedAt = now.Add(168 * time.Hour)
	f.targets["account-a"] = a
	now = now.Add(168 * time.Hour)
	s.Tick()
	waitIdle(t, s)
	current, e := s.Plan(p.ID)
	require.NoError(t, e)
	require.NotEqual(t, first, current.LastRunID)
	result, e = s.Run(current.LastRunID)
	require.NoError(t, e)
	assert.Equal(t, "not_due", result.Items[0].State)
	assert.Equal(t, 1, f.calls)
	f.allowed.Store(false)
	now = now.Add(168 * time.Hour)
	s.Tick()
	waitIdle(t, s)
	current, e = s.Plan(p.ID)
	require.NoError(t, e)
	assert.False(t, current.Enabled)
	assert.Equal(t, "denied", current.ErrorCode)
}
func TestRotationPlanRecoveryDoesNotReplayUnresolvedRemoteOperation(t *testing.T) {
	s, f, _ := newFixture(t)
	p := saveManual(t, s, "account-a")
	r := f.runner()
	r.Execute = func(_ context.Context, in Intent, _ func() error) (Outcome, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		f.receipts[in.RequestID] = Outcome{State: "recovery_required", Code: "credential_pending"}
		return f.receipts[in.RequestID], errors.New("ambiguous remote result")
	}
	s.SetRunner(r)
	run, e := s.Submit(context.Background(), testActor(), p.ID, "uncertain", false)
	require.NoError(t, e)
	s.Tick()
	waitIdle(t, s)
	current, e := s.Run(run.ID)
	require.NoError(t, e)
	assert.Equal(t, "recovery_required", current.State)
	assert.Equal(t, 1, f.calls)
	f.mu.Lock()
	f.receipts[current.Items[0].ID] = Outcome{State: "succeeded", Revision: 2, At: time.Now().UTC()}
	f.mu.Unlock()
	s.mu.Lock()
	delete(s.inspectAfter, run.ID)
	s.mu.Unlock()
	current = drive(t, s, run.ID)
	assert.Equal(t, "succeeded", current.State)
	assert.Equal(t, 1, f.calls)
}
