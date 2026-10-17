package tickets

import (
	"context"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"slices"
	"time"
)

func intent(r record) Intent {
	return Intent{TicketID: r.ID, Digest: r.Digest, Owner: r.Owner, Publisher: r.Publisher, Targets: r.Prepared, StartsAt: r.StartsAt, EndsAt: r.EndsAt}
}
func intentDigest(r record) string { r.Digest = ""; return hash(intent(r)) }
func (s *Service) checkIntent(ctx context.Context, r record, complete bool) (string, error) {
	if s.ctx.Err() != nil {
		return "unavailable", ErrUnavailable
	}
	if e := ctx.Err(); e != nil {
		return "unavailable", e
	}
	now := s.now()
	if !now.Before(r.EndsAt) || !complete && !now.Before(r.ApprovalExpiresAt) {
		return "expired", ErrStale
	}
	s.mu.Lock()
	p, ok := s.data.Policies[r.PolicyID]
	s.mu.Unlock()
	if !ok || !p.Enabled || p.Revision != r.PolicyRevision {
		return "policy_changed", ErrStale
	}
	owner, e := s.principal(ctx, r.Owner.ID)
	if e != nil || !canApply(p, owner) {
		return "requester_changed", ErrDenied
	}
	publisher, e := s.principal(ctx, r.Publisher.ID)
	if e != nil || !publisher.CanPublish {
		return "publisher_changed", ErrDenied
	}
	for i, a := range r.Approvals {
		current, e := s.principal(ctx, a.Actor.ID)
		if e != nil || !current.CanReview || i >= len(r.Stages) || !matches(current, r.Stages[i].Subjects) {
			return "reviewer_changed", ErrDenied
		}
	}
	if complete && (len(r.Approvals) != len(r.Stages) || r.CurrentStage != len(r.Stages)) {
		return "reviewer_changed", ErrDenied
	}
	targets := make([]Target, len(r.Targets))
	for i, v := range r.Targets {
		targets[i] = v.Target
	}
	current, e := s.prepare(ctx, p, targets)
	if e != nil {
		return "source_changed", ErrStale
	}
	for i, v := range current {
		if v.Binding != r.Prepared[i].Binding {
			return "source_changed", ErrStale
		}
	}
	return "", nil
}

// GrantGuard publishes the second half of issuance: source grants are effective
// only after this encrypted workflow has committed the final approved state.
// It deliberately takes no grant-store lock and performs no external I/O.
func (s *Service) GrantGuard(g grants.Grant, at time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return false
	}
	r, ok := s.data.Tickets[g.SourceTicketID]
	if !ok || r.State != "approved" || r.Owner.ID != g.UserID || !slices.Contains(r.GrantIDs, g.ID) || at.Before(r.StartsAt) || !at.Before(r.EndsAt) || g.StartsAt == nil || g.EndsAt == nil || !g.StartsAt.Equal(r.StartsAt) || !g.EndsAt.Equal(r.EndsAt) {
		return false
	}
	p, ok := s.data.Policies[r.PolicyID]
	if !ok || !p.Enabled {
		return false
	}
	for _, target := range r.Targets {
		scope := target.Kind == "asset" && g.AssetID == target.ID && g.NodeID == "" || target.Kind == "node" && g.NodeID == target.ID && g.AssetID == ""
		if scope && target.Account == g.Account && g.GroupID == "" && slices.Equal(target.Actions, g.Actions) {
			return true
		}
	}
	return false
}
func systemActor() Actor { return Actor{ID: "system-access-tickets", Name: "Access ticket service"} }
func (s *Service) setState(id, newState, code string, receipt *grants.TicketReceipt) error {
	return s.mutate(func(d *state) error {
		r, ok := d.Tickets[id]
		if !ok {
			return ErrNotFound
		}
		if r.State == newState && r.ErrorCode == code && receipt == nil {
			return nil
		}
		r.State = newState
		r.ErrorCode = code
		r.UpdatedAt = s.now().UTC()
		r.Revision++
		if terminal(newState) {
			r.ClosedAt = r.UpdatedAt
		}
		if receipt != nil {
			r.GrantIDs = slices.Clone(receipt.GrantIDs)
		}
		d.Tickets[id] = r
		return appendAudit(d, Audit{At: r.UpdatedAt, Actor: systemActor(), Action: newState, TicketID: id, PolicyID: r.PolicyID, Revision: r.Revision, Note: code})
	})
}
func (s *Service) beginRevoke(id, code, to string) error {
	return s.mutate(func(d *state) error {
		r, ok := d.Tickets[id]
		if !ok {
			return ErrNotFound
		}
		if r.State == "revoking" {
			return nil
		}
		r.State = "revoking"
		r.RevokeTo = to
		r.ErrorCode = code
		r.UpdatedAt = s.now().UTC()
		r.Revision++
		d.Tickets[id] = r
		return appendAudit(d, Audit{At: r.UpdatedAt, Actor: systemActor(), Action: "revocation_started", TicketID: id, PolicyID: r.PolicyID, Revision: r.Revision, Note: code})
	})
}
func (s *Service) reconcileLocked(ctx context.Context, id string) {
	step, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	defer cancel()
	ctx = step
	runner := s.runnerSnapshot()
	if runner.Issue == nil || runner.Revoke == nil || runner.Receipt == nil {
		return
	}
	s.mu.Lock()
	r, ok := s.data.Tickets[id]
	p, policyOK := s.data.Policies[r.PolicyID]
	s.mu.Unlock()
	if !ok || s.ctx.Err() != nil {
		return
	}
	now := s.now()
	if r.State == "pending" {
		if !now.Before(r.ApprovalExpiresAt) {
			_ = s.setState(id, "expired", "approval_expired", nil)
		} else if !policyOK || !p.Enabled || p.Revision != r.PolicyRevision {
			_ = s.setState(id, "stale", "policy_changed", nil)
		}
		return
	}
	if r.State == "approved" {
		receipt, e := runner.Receipt(r.ID)
		code, to := "", "revoked"
		if !now.Before(r.EndsAt) {
			code, to = "expired", "expired"
		} else if !policyOK || !p.Enabled {
			code = "policy_disabled"
		} else if e == nil && receipt.State != "issued" {
			code = "grant_changed"
		} else if e != nil {
			code = "grant_receipt_unavailable"
		}
		if code == "" {
			return
		}
		if e = s.beginRevoke(id, code, to); e != nil {
			return
		}
		s.mu.Lock()
		r = s.data.Tickets[id]
		s.mu.Unlock()
	}
	if r.State == "issuing" {
		receipt, e := runner.Receipt(r.ID)
		if e == nil && receipt.Digest != r.Digest {
			_ = s.setError(id, "grant_conflict")
			return
		}
		if e == nil && receipt.State == "revoked" {
			_ = s.setState(id, "revoked", "grant_revoked", &receipt)
			return
		}
		if e == nil && receipt.State != "issued" {
			if s.beginRevoke(id, "grant_changed", "revoked") != nil {
				return
			}
			s.mu.Lock()
			r = s.data.Tickets[id]
			s.mu.Unlock()
		} else {
			if e != nil && !errors.Is(e, grants.ErrNotFound) {
				_ = s.setError(id, "unavailable")
				return
			}
			code, valid := s.checkIntent(ctx, r, true)
			if valid != nil {
				to := "stale"
				if code == "expired" {
					to = "expired"
				}
				if s.beginRevoke(id, code, to) != nil {
					return
				}
				s.mu.Lock()
				r = s.data.Tickets[id]
				s.mu.Unlock()
			} else {
				_, e = runner.Issue(ctx, intent(r), func() error {
					s.mu.Lock()
					current, ok := s.data.Tickets[id]
					s.mu.Unlock()
					if !ok || current.State != "issuing" || current.Digest != r.Digest {
						return ErrConflict
					}
					_, e := s.checkIntent(ctx, current, true)
					return e
				}, func(receipt grants.TicketReceipt) error {
					if receipt.State != "issued" || receipt.Digest != r.Digest || len(receipt.GrantIDs) != len(r.Targets) {
						return ErrConflict
					}
					return s.setState(id, "approved", "", &receipt)
				})
				if e != nil {
					_ = s.setError(id, "issuance_unavailable")
				}
				return
			}
		}
	}
	if r.State == "revoking" {
		receipt, e := runner.Revoke(ctx, intent(r))
		if e != nil {
			_ = s.setError(id, "revocation_unavailable")
			return
		}
		if receipt.State != "revoked" || receipt.Digest != r.Digest {
			_ = s.setError(id, "grant_conflict")
			return
		}
		to := r.RevokeTo
		if to == "" {
			to = "revoked"
		}
		_ = s.setState(id, to, r.ErrorCode, &receipt)
	}
}
func (s *Service) setError(id, code string) error {
	return s.mutate(func(d *state) error {
		r, ok := d.Tickets[id]
		if !ok {
			return ErrNotFound
		}
		if r.ErrorCode == code {
			return nil
		}
		r.ErrorCode = code
		r.UpdatedAt = s.now().UTC()
		d.Tickets[id] = r
		return nil
	})
}
func (s *Service) Tick() {
	if s.ctx.Err() != nil {
		return
	}
	s.mu.Lock()
	ids := []string{}
	for id, r := range s.data.Tickets {
		if !terminal(r.State) {
			ids = append(ids, id)
		}
	}
	s.mu.Unlock()
	for _, id := range ids {
		if s.ctx.Err() != nil || !s.op.TryLock() {
			return
		}
		step, cancel := context.WithTimeout(s.ctx, 15*time.Second)
		s.reconcileLocked(step, id)
		cancel()
		s.op.Unlock()
	}
	s.mu.Lock()
	due := s.now().Sub(s.lastPrune) >= time.Hour
	s.mu.Unlock()
	if prune := s.runnerSnapshot().Prune; due && prune != nil && s.ctx.Err() == nil {
		if prune(s.now()) == nil {
			s.mu.Lock()
			s.lastPrune = s.now()
			s.mu.Unlock()
		}
	}
}
func (s *Service) Start(owner context.Context) {
	s.mu.Lock()
	if s.started || s.closed {
		s.mu.Unlock()
		return
	}
	s.started = true
	stop := context.AfterFunc(owner, s.cancel)
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		defer stop()
		timer := time.NewTicker(time.Second)
		defer timer.Stop()
		for {
			s.Tick()
			select {
			case <-s.ctx.Done():
				return
			case <-timer.C:
			}
		}
	}()
}
func (s *Service) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	// Drain API-initiated issuance as well as the background worker before a
	// new organization runtime opens the same native grant document.
	s.op.Lock()
	s.op.Unlock()
	s.wg.Wait()
}
