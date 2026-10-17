package tickets

import (
	"context"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixture struct {
	mu         sync.Mutex
	peers      map[string]Principal
	bindings   map[string]string
	grantStore *grants.Store
}

func setup(t *testing.T) (*Service, *fixture, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tickets.json")
	s, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	t.Cleanup(s.Close)
	native, e := grants.OpenStore(filepath.Join(t.TempDir(), "grants.json"))
	require.NoError(t, e)
	f := &fixture{grantStore: native, peers: map[string]Principal{}, bindings: map[string]string{}}
	f.peers["publisher"] = Principal{Actor: Actor{ID: "publisher", Name: "Synthetic workflow publisher"}, CanPublish: true, CanViewAll: true, CanReview: true, CanRevoke: true}
	f.peers["requester"] = Principal{Actor: Actor{ID: "requester", Name: "Synthetic access requester"}, CanReview: true}
	for _, id := range []string{"reviewer-a", "reviewer-b", "reviewer-c", "reviewer-d", "reviewer-e", "stranger"} {
		f.peers[id] = Principal{Actor: Actor{ID: id, Name: "Synthetic " + id}, CanReview: id != "stranger"}
	}
	s.SetRunner(f.runner())
	native.SetTicketGuard(s.GrantGuard)
	return s, f, path
}
func (f *fixture) runner() Runner {
	return Runner{
		Principal: func(_ context.Context, id string) (Principal, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			p, ok := f.peers[id]
			if !ok {
				return Principal{}, ErrDenied
			}
			p.Subjects = slices.Clone(p.Subjects)
			return p, nil
		},
		People: func(context.Context) ([]Principal, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			out := []Principal{}
			for _, p := range f.peers {
				p.Subjects = slices.Clone(p.Subjects)
				out = append(out, p)
			}
			return out, nil
		},
		ValidatePolicy: func(context.Context, PolicyInput) error { return nil },
		Resolve: func(_ context.Context, in []Target) ([]Prepared, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			out := []Prepared{}
			for _, target := range in {
				binding := f.bindings[targetKey(target)]
				if binding == "" {
					binding = hash(targetKey(target))
				}
				out = append(out, Prepared{Ref: Ref{Target: target, Name: "Synthetic published asset " + target.ID, Protocol: "ssh"}, Binding: binding})
			}
			return out, nil
		},
		Issue: func(_ context.Context, in Intent, guard func() error, commit func(grants.TicketReceipt) error) (grants.TicketReceipt, error) {
			if e := guard(); e != nil {
				return grants.TicketReceipt{}, e
			}
			rows := []grants.Input{}
			for _, v := range in.Targets {
				input := grants.Input{UserID: in.Owner.ID, Account: v.Account, Actions: v.Actions, StartsAt: &in.StartsAt, EndsAt: &in.EndsAt}
				if v.Kind == "asset" {
					input.AssetID = v.ID
				} else {
					input.NodeID = v.ID
				}
				rows = append(rows, input)
			}
			receipt, e := f.grantStore.IssueTicket(in.TicketID, in.Digest, rows, in.Publisher.Name)
			if e != nil {
				return receipt, e
			}
			if e = guard(); e != nil {
				return receipt, e
			}
			return receipt, commit(receipt)
		},
		Revoke: func(_ context.Context, in Intent) (grants.TicketReceipt, error) {
			return f.grantStore.RevokeTicket(in.TicketID, in.Digest, in.EndsAt)
		},
		Receipt: f.grantStore.TicketReceipt,
	}
}
func publish(t *testing.T, s *Service, count int) Policy {
	t.Helper()
	stages := []Stage{}
	for _, id := range []string{"reviewer-a", "reviewer-b", "reviewer-c", "reviewer-d", "reviewer-e"}[:count] {
		stages = append(stages, Stage{Name: id, Subjects: []Subject{{Kind: "user", ID: id}}})
	}
	p, e := s.SavePolicy(context.Background(), "publisher", "", PolicyInput{Name: "Synthetic approval workflow", Enabled: true, AllMembers: true, Stages: stages, Scopes: []Scope{{Kind: "asset", ID: "asset-a", Accounts: []string{"managed"}, Actions: []string{"connect", "sftp"}}, {Kind: "asset", ID: "asset-b", Accounts: []string{"managed"}, Actions: []string{"connect"}}}, MaxDurationMinutes: 120, ApprovalTTLMinutes: 60})
	require.NoError(t, e)
	return p
}
func apply(t *testing.T, s *Service, p Policy, requestID string) Ticket {
	t.Helper()
	v, e := s.Submit(context.Background(), "requester", SubmitInput{Name: "Synthetic temporary access", PolicyID: p.ID, PolicyRevision: p.Revision, RequestID: requestID, Reason: "Owned automated verification", Targets: []Target{{Kind: "asset", ID: "asset-a", Account: "managed", Actions: []string{"connect"}}}, StartsAt: time.Now().UTC().Add(-time.Second), EndsAt: time.Now().UTC().Add(time.Hour)})
	require.NoError(t, e)
	return v
}
func approve(t *testing.T, s *Service, ticket Ticket, actor, request string) Ticket {
	t.Helper()
	out, e := s.Decide(context.Background(), actor, ticket.ID, Decision{Revision: ticket.Revision, RequestID: request, Action: "approve", Comment: "Synthetic checked approval"})
	require.NoError(t, e)
	return out
}
func TestTicketFiveLevelsEnforceDistinctCurrentReviewersAndIssueBoundedGrants(t *testing.T) {
	s, f, path := setup(t)
	p := publish(t, s, 5)
	ticket := apply(t, s, p, "five-level-request")
	_, e := s.Decide(context.Background(), "requester", ticket.ID, Decision{Revision: ticket.Revision, RequestID: "self-denied", Action: "approve"})
	assert.Error(t, e)
	for i, id := range []string{"reviewer-a", "reviewer-b", "reviewer-c", "reviewer-d", "reviewer-e"} {
		ticket = approve(t, s, ticket, id, "decision-"+id)
		if i < 4 {
			assert.Equal(t, "pending", ticket.State)
			assert.Empty(t, f.grantStore.List())
			assert.False(t, f.grantStore.Allows("requester", "asset-a", "managed", "connect", time.Now()))
		}
	}
	assert.Equal(t, "approved", ticket.State)
	assert.True(t, f.grantStore.Allows("requester", "asset-a", "managed", "connect", time.Now()))
	assert.False(t, f.grantStore.Allows("requester", "asset-a", "managed", "sftp", time.Now()))
	assert.False(t, f.grantStore.Allows("requester", "asset-a", "managed", "connect", ticket.EndsAt))
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "Synthetic access requester")
	_, e = s.Get(context.Background(), "stranger", ticket.ID)
	assert.ErrorIs(t, e, ErrNotFound)
}
func TestTicketFinalResultFailureLeavesSourceGrantsUnusableUntilDurableApproval(t *testing.T) {
	s, f, path := setup(t)
	p := publish(t, s, 2)
	ticket := apply(t, s, p, "write-failure-request")
	ticket = approve(t, s, ticket, "reviewer-a", "first-decision")
	writes := 0
	s.saveHook = func([]byte) error {
		writes++
		if writes >= 2 {
			return errors.New("owned final state persistence failure")
		}
		return nil
	}
	ticket = approve(t, s, ticket, "reviewer-b", "last-decision")
	assert.Equal(t, "issuing", ticket.State)
	require.Len(t, f.grantStore.List(), 1)
	assert.False(t, f.grantStore.Allows("requester", "asset-a", "managed", "connect", time.Now()))
	source := f.grantStore.List()[0].ID
	s.Close()
	peer, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	defer peer.Close()
	peer.SetRunner(f.runner())
	f.grantStore.SetTicketGuard(peer.GrantGuard)
	peer.Tick()
	ticket, e = peer.Get(context.Background(), "requester", ticket.ID)
	require.NoError(t, e)
	assert.Equal(t, "approved", ticket.State)
	require.Len(t, f.grantStore.List(), 1)
	assert.Equal(t, source, f.grantStore.List()[0].ID)
	assert.True(t, f.grantStore.Allows("requester", "asset-a", "managed", "connect", time.Now()))
}
func TestTicketRevocationGateClosesBeforeGrantStorageRecovery(t *testing.T) {
	s, f, _ := setup(t)
	p := publish(t, s, 1)
	ticket := apply(t, s, p, "revoke-request")
	ticket = approve(t, s, ticket, "reviewer-a", "approved-once")
	// Native receipt persistence fails; the workflow gate must already deny access.
	runner := f.runner()
	runner.Revoke = func(context.Context, Intent) (grants.TicketReceipt, error) {
		return grants.TicketReceipt{}, errors.New("owned native write failure")
	}
	s.SetRunner(runner)
	ticket, e := s.Cancel(context.Background(), "requester", ticket.ID, ticket.Revision)
	require.NoError(t, e)
	assert.Equal(t, "revoking", ticket.State)
	require.Len(t, f.grantStore.List(), 1)
	assert.False(t, f.grantStore.Allows("requester", "asset-a", "managed", "connect", time.Now()))
	s.SetRunner(f.runner())
	s.Tick()
	ticket, e = s.Get(context.Background(), "requester", ticket.ID)
	require.NoError(t, e)
	assert.Equal(t, "revoked", ticket.State)
	assert.Empty(t, f.grantStore.List())
	receipt, e := f.grantStore.TicketReceipt(ticket.ID)
	require.NoError(t, e)
	assert.Equal(t, "revoked", receipt.State)
}
func TestTicketAmendmentResetsPriorApprovalsAndOldDecisionRetryDoesNotApproveNewScope(t *testing.T) {
	s, f, _ := setup(t)
	p := publish(t, s, 2)
	ticket := apply(t, s, p, "amend-request")
	firstInput := Decision{Revision: ticket.Revision, RequestID: "before-amend", Action: "approve", Comment: "Original scope"}
	ticket, e := s.Decide(context.Background(), "reviewer-a", ticket.ID, firstInput)
	require.NoError(t, e)
	ticket, e = s.Amend(context.Background(), "requester", ticket.ID, Amendment{Revision: ticket.Revision, Reason: "Use the other published asset", Targets: []Target{{Kind: "asset", ID: "asset-b", Account: "managed", Actions: []string{"connect"}}}, StartsAt: ticket.StartsAt, EndsAt: ticket.EndsAt})
	require.NoError(t, e)
	assert.Zero(t, ticket.CurrentStage)
	assert.Empty(t, ticket.Approvals)
	retry, e := s.Decide(context.Background(), "reviewer-a", ticket.ID, firstInput)
	require.NoError(t, e)
	assert.Zero(t, retry.CurrentStage)
	assert.Empty(t, f.grantStore.List())
	ticket = approve(t, s, ticket, "reviewer-a", "after-amend")
	ticket = approve(t, s, ticket, "reviewer-b", "final-amended")
	assert.Equal(t, "approved", ticket.State)
	assert.False(t, f.grantStore.Allows("requester", "asset-a", "managed", "connect", time.Now()))
	assert.True(t, f.grantStore.Allows("requester", "asset-b", "managed", "connect", time.Now()))
}
func TestTicketSourceFencePublisherAuthorityAndPolicyDisableDenyNewAccess(t *testing.T) {
	s, f, _ := setup(t)
	p := publish(t, s, 2)
	ticket := apply(t, s, p, "changed-source")
	f.mu.Lock()
	f.bindings[targetKey(ticket.Targets[0].Target)] = strings.Repeat("e", 64)
	f.mu.Unlock()
	_, e := s.Decide(context.Background(), "reviewer-a", ticket.ID, Decision{Revision: ticket.Revision, RequestID: "changed-source-decision", Action: "approve"})
	assert.ErrorIs(t, e, ErrStale)
	assert.Empty(t, f.grantStore.List())
	f.mu.Lock()
	delete(f.bindings, targetKey(ticket.Targets[0].Target))
	f.mu.Unlock()
	ticket = approve(t, s, ticket, "reviewer-a", "source-back")
	f.mu.Lock()
	peer := f.peers["publisher"]
	peer.CanPublish = false
	f.peers["publisher"] = peer
	f.mu.Unlock()
	_, e = s.Decide(context.Background(), "reviewer-b", ticket.ID, Decision{Revision: ticket.Revision, RequestID: "revoked-publisher", Action: "approve"})
	assert.ErrorIs(t, e, ErrDenied)
	assert.Empty(t, f.grantStore.List())
	f.mu.Lock()
	peer.CanPublish = true
	f.peers["publisher"] = peer
	f.mu.Unlock()
	ticket = approve(t, s, ticket, "reviewer-b", "restored-publisher")
	p.Enabled = false
	p, e = s.SavePolicy(context.Background(), "publisher", p.ID, p.PolicyInput)
	require.NoError(t, e)
	assert.False(t, f.grantStore.Allows("requester", "asset-a", "managed", "connect", time.Now()))
	s.Tick()
	ticket, e = s.Get(context.Background(), "requester", ticket.ID)
	require.NoError(t, e)
	assert.Equal(t, "revoked", ticket.State)
}
