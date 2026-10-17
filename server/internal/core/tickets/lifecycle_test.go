package tickets

import (
	"context"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestTicketConcurrentDecisionsCASAndRetry(t *testing.T) {
	s, f, _ := setup(t)
	p := publish(t, s, 1)
	v := apply(t, s, p, "concurrent-submit")
	in := Decision{Revision: v.Revision, RequestID: "same-decision", Action: "approve"}
	var wg sync.WaitGroup
	results := make(chan error, 12)
	for range 12 {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := s.Decide(context.Background(), "reviewer-a", v.ID, in); results <- e }()
	}
	wg.Wait()
	close(results)
	for e := range results {
		require.NoError(t, e)
	}
	require.Len(t, f.grantStore.List(), 1)
	out, e := s.Get(context.Background(), "requester", v.ID)
	require.NoError(t, e)
	assert.Equal(t, "approved", out.State)
	require.Len(t, out.Approvals, 1)
	in.Comment = "changed"
	_, e = s.Decide(context.Background(), "reviewer-a", v.ID, in)
	assert.ErrorIs(t, e, ErrConflict)
}
func TestTicketRejectCancelExpiryAndParticipantVisibility(t *testing.T) {
	s, f, _ := setup(t)
	p := publish(t, s, 1)
	p.AllMembers = false
	p.Requesters = []Subject{{Kind: "group", ID: "allowed"}}
	p.CC = []Subject{{Kind: "user", ID: "stranger"}}
	f.mu.Lock()
	peer := f.peers["requester"]
	peer.Subjects = []Subject{{Kind: "group", ID: "allowed"}}
	f.peers["requester"] = peer
	f.mu.Unlock()
	p, e := s.SavePolicy(context.Background(), "publisher", p.ID, p.PolicyInput)
	require.NoError(t, e)
	v := apply(t, s, p, "participants")
	_, e = s.Get(context.Background(), "stranger", v.ID)
	require.NoError(t, e)
	page, e := s.List(context.Background(), "stranger", Query{View: "cc", Limit: 20})
	require.NoError(t, e)
	require.Len(t, page.Results, 1)
	v, e = s.Comment(context.Background(), "stranger", v.ID, "Synthetic copied participant")
	require.NoError(t, e)
	require.Len(t, v.Comments, 1)
	_, e = s.Decide(context.Background(), "stranger", v.ID, Decision{Revision: v.Revision, RequestID: "cc-denied", Action: "approve"})
	assert.ErrorIs(t, e, ErrDenied)
	v, e = s.Decide(context.Background(), "reviewer-a", v.ID, Decision{Revision: v.Revision, RequestID: "reject", Action: "reject", Comment: "Synthetic rejection"})
	require.NoError(t, e)
	assert.Equal(t, "rejected", v.State)
	assert.Empty(t, f.grantStore.List())
	cancelled := apply(t, s, p, "cancel-before-review")
	cancelled, e = s.Cancel(context.Background(), "requester", cancelled.ID, cancelled.Revision)
	require.NoError(t, e)
	assert.Equal(t, "cancelled", cancelled.State)
	expiry := apply(t, s, p, "approval-expiry")
	now := expiry.ApprovalExpiresAt.Add(time.Second)
	s.now = func() time.Time { return now }
	s.Tick()
	expiry, e = s.Get(context.Background(), "requester", expiry.ID)
	require.NoError(t, e)
	assert.Equal(t, "expired", expiry.State)
	s.now = time.Now
	active := approve(t, s, apply(t, s, p, "grant-expiry"), "reviewer-a", "grant-approved")
	now = active.EndsAt.Add(time.Second)
	s.now = func() time.Time { return now }
	assert.False(t, f.grantStore.Allows("requester", "asset-a", "managed", "connect", now))
	s.Tick()
	active, e = s.Get(context.Background(), "requester", active.ID)
	require.NoError(t, e)
	assert.Equal(t, "expired", active.State)
	assert.Empty(t, f.grantStore.List())
	history, e := s.Audit(context.Background(), "requester", 0, 100)
	require.NoError(t, e)
	assert.GreaterOrEqual(t, history.Total, 8)
}
func TestTicketPermissionChangesDisableDeleteAndUnavailableReviewers(t *testing.T) {
	s, f, _ := setup(t)
	p := publish(t, s, 2)
	// A single member cannot satisfy two stages, even through a shared role.
	for i := range p.Stages {
		p.Stages[i].Subjects = []Subject{{Kind: "role", ID: "shared-reviewer"}}
	}
	f.mu.Lock()
	a := f.peers["reviewer-a"]
	a.Subjects = []Subject{{Kind: "role", ID: "shared-reviewer"}}
	f.peers["reviewer-a"] = a
	f.mu.Unlock()
	_, e := s.SavePolicy(context.Background(), "publisher", p.ID, p.PolicyInput)
	assert.ErrorIs(t, e, ErrReviewers)
	original, e := s.Policy(context.Background(), "publisher", p.ID)
	require.NoError(t, e)
	v := apply(t, s, original, "role-change")
	v = approve(t, s, v, "reviewer-a", "stage-first")
	f.mu.Lock()
	a.CanReview = false
	f.peers["reviewer-a"] = a
	f.mu.Unlock()
	_, e = s.Decide(context.Background(), "reviewer-b", v.ID, Decision{Revision: v.Revision, RequestID: "stale-earlier-reviewer", Action: "approve"})
	assert.ErrorIs(t, e, ErrDenied)
	assert.Empty(t, f.grantStore.List())
	require.NoError(t, s.DeletePolicy(context.Background(), "publisher", original.ID, original.Revision))
	s.Tick()
	v, e = s.Get(context.Background(), "requester", v.ID)
	require.NoError(t, e)
	assert.Equal(t, "stale", v.State)
}
func TestTicketEncryptedStoreCorruptionCancellationAndBounds(t *testing.T) {
	s, _, path := setup(t)
	p := publish(t, s, 1)
	apply(t, s, p, "encrypted-input")
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	_, e = Open(path, make([]byte, 31), nil)
	assert.ErrorIs(t, e, ErrInvalid)
	wrong := make([]byte, 32)
	wrong[0] = 1
	_, e = Open(path, wrong, nil)
	assert.ErrorIs(t, e, ErrInvalid)
	raw[len(raw)/2] ^= 1
	bad := filepath.Join(t.TempDir(), "corrupt.json")
	require.NoError(t, os.WriteFile(bad, raw, 0600))
	_, e = Open(bad, make([]byte, 32), nil)
	assert.ErrorIs(t, e, ErrInvalid)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = s.SavePolicy(cancelled, "publisher", p.ID, p.PolicyInput)
	assert.Error(t, e)
	for _, in := range []Target{{Kind: "asset", ID: "asset-a", Account: "*", Actions: []string{"connect"}}, {Kind: "asset", ID: "asset-a", Account: "managed", Actions: []string{"admin"}}, {Kind: "node", ID: "bad/id", Account: "managed", Actions: []string{"view"}}} {
		_, e = normalizeTargets([]Target{in})
		assert.ErrorIs(t, e, ErrInvalid)
	}
	s.op.Lock()
	wait, done := context.WithTimeout(context.Background(), time.Millisecond)
	defer done()
	assert.ErrorIs(t, s.lock(wait), context.DeadlineExceeded)
	s.op.Unlock()
	s.Close()
	_, e = s.SavePolicy(context.Background(), "publisher", p.ID, p.PolicyInput)
	assert.ErrorIs(t, e, ErrUnavailable)
}
func TestTicketApprovedReceiptDeletionAndRecoveryNeverReissues(t *testing.T) {
	s, f, _ := setup(t)
	p := publish(t, s, 1)
	v := approve(t, s, apply(t, s, p, "manual-grant-delete"), "reviewer-a", "approved")
	require.NoError(t, f.grantStore.Delete(v.GrantIDs[0]))
	s.Tick()
	v, e := s.Get(context.Background(), "requester", v.ID)
	require.NoError(t, e)
	assert.Equal(t, "revoked", v.State)
	assert.Empty(t, f.grantStore.List())
	receipt, e := f.grantStore.TicketReceipt(v.ID)
	require.NoError(t, e)
	assert.Equal(t, "revoked", receipt.State)
	runner := f.runner()
	runner.Principal = func(context.Context, string) (Principal, error) {
		return Principal{}, errors.New("synthetic unavailable principal")
	}
	s.SetRunner(runner)
	_, e = s.Get(context.Background(), "requester", v.ID)
	assert.ErrorIs(t, e, ErrDenied)
}

func TestTicketDelayedAmendmentPreservesElapsedStartAndEmptyStartMeansNow(t *testing.T) {
	s, _, _ := setup(t)
	p := publish(t, s, 2)
	v := apply(t, s, p, "delayed-adjustment")
	now := time.Now().Add(10 * time.Minute)
	s.now = func() time.Time { return now }
	in := Amendment{Revision: v.Revision, Reason: "Narrow an existing window after waiting", StartsAt: v.StartsAt, EndsAt: v.EndsAt, Targets: []Target{v.Targets[0].Target}}
	adjusted, e := s.Amend(context.Background(), "requester", v.ID, in)
	require.NoError(t, e)
	assert.True(t, adjusted.StartsAt.Equal(v.StartsAt))
	in.Revision = adjusted.Revision
	in.StartsAt = time.Time{}
	adjusted, e = s.Amend(context.Background(), "requester", v.ID, in)
	require.NoError(t, e)
	assert.True(t, adjusted.StartsAt.Equal(now))
}

func TestTicketCloseCancelsAndDrainsAPIIssuanceBeforeRuntimeReplacement(t *testing.T) {
	s, f, path := setup(t)
	p := publish(t, s, 1)
	v := apply(t, s, p, "close-pending-issue")
	entered := make(chan struct{})
	runner := f.runner()
	runner.Issue = func(ctx context.Context, _ Intent, _ func() error, _ func(grants.TicketReceipt) error) (grants.TicketReceipt, error) {
		close(entered)
		<-ctx.Done()
		return grants.TicketReceipt{}, ctx.Err()
	}
	s.SetRunner(runner)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_, _ = s.Decide(context.Background(), "reviewer-a", v.ID, Decision{Revision: v.Revision, RequestID: "close-decision", Action: "approve"})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("issuance did not enter")
	}
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not drain issuance")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("old request still running")
	}
	assert.Empty(t, f.grantStore.List())
	peer, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	defer peer.Close()
	peer.SetRunner(f.runner())
	f.grantStore.SetTicketGuard(peer.GrantGuard)
	peer.Tick()
	current, e := peer.Get(context.Background(), "requester", v.ID)
	require.NoError(t, e)
	assert.Equal(t, "approved", current.State)
	require.Len(t, f.grantStore.List(), 1)
}
