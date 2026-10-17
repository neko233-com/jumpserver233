package tickets

import (
	"context"
	"slices"
	"sort"
	"strings"
	"time"
)

func (s *Service) lock(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if s.op.TryLock() {
		return nil
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.ctx.Done():
			return ErrUnavailable
		case <-ticker.C:
			if s.op.TryLock() {
				return nil
			}
		}
	}
}
func canApply(p Policy, actor Principal) bool {
	return p.Enabled && (p.AllMembers || matches(actor, p.Requesters))
}
func (s *Service) Policy(ctx context.Context, actorID, id string) (Policy, error) {
	actor, e := s.principal(ctx, actorID)
	if e != nil {
		return Policy{}, e
	}
	s.mu.Lock()
	p, ok := s.data.Policies[id]
	s.mu.Unlock()
	if !ok || !actor.CanPublish && !canApply(p, actor) {
		return Policy{}, ErrNotFound
	}
	return clonePolicy(p), nil
}
func (s *Service) Policies(ctx context.Context, actorID string, offset, limit int) (Page[Policy], error) {
	if offset < 0 || limit < 1 || limit > 100 {
		return Page[Policy]{}, ErrInvalid
	}
	actor, e := s.principal(ctx, actorID)
	if e != nil {
		return Page[Policy]{}, e
	}
	s.mu.Lock()
	rows := []Policy{}
	for _, p := range s.data.Policies {
		if actor.CanPublish || canApply(p, actor) {
			rows = append(rows, p)
		}
	}
	s.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].UpdatedAt.Equal(rows[j].UpdatedAt) {
			return rows[i].ID < rows[j].ID
		}
		return rows[i].UpdatedAt.After(rows[j].UpdatedAt)
	})
	out := Page[Policy]{Results: []Policy{}, Total: len(rows)}
	offset = min(offset, len(rows))
	for _, p := range rows[offset:min(len(rows), offset+limit)] {
		out.Results = append(out.Results, clonePolicy(p))
	}
	return out, nil
}
func (s *Service) SavePolicy(ctx context.Context, actorID, id string, in PolicyInput) (Policy, error) {
	actor, e := s.principal(ctx, actorID)
	if e != nil || !actor.CanPublish {
		return Policy{}, ErrDenied
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Validate() != nil {
		return Policy{}, ErrInvalid
	}
	runner := s.runnerSnapshot()
	if runner.ValidatePolicy == nil || runner.People == nil {
		return Policy{}, ErrUnavailable
	}
	if e = runner.ValidatePolicy(ctx, in); e != nil {
		return Policy{}, e
	}
	if in.Enabled {
		people, e := runner.People(ctx)
		if e != nil {
			return Policy{}, e
		}
		if !chainPossible(in.Stages, people, "", nil) {
			return Policy{}, ErrReviewers
		}
	}
	if e = s.lock(ctx); e != nil {
		return Policy{}, e
	}
	defer s.op.Unlock()
	if actor, e = s.principal(ctx, actorID); e != nil || !actor.CanPublish {
		return Policy{}, ErrDenied
	}
	var out Policy
	e = s.mutate(func(d *state) error {
		now := s.now().UTC()
		created := now
		revision := 1
		if id == "" {
			if in.Revision != 0 {
				return ErrConflict
			}
			if len(d.Policies) >= MaxPolicies {
				return ErrCapacity
			}
			var e error
			id, e = newID("ticket-policy-")
			if e != nil {
				return e
			}
		} else {
			prior, ok := d.Policies[id]
			if !ok {
				return ErrNotFound
			}
			if prior.Revision != in.Revision {
				return ErrConflict
			}
			if prior.Revision >= 1<<53-1 {
				return ErrCapacity
			}
			created = prior.CreatedAt
			revision = prior.Revision + 1
		}
		in.Revision = revision
		out = clonePolicy(Policy{PolicyInput: in, ID: id, Publisher: actor.Actor, CreatedAt: created, UpdatedAt: now})
		d.Policies[id] = out
		action := "policy_created"
		if revision > 1 {
			action = "policy_updated"
		}
		return appendAudit(d, Audit{At: now, Actor: actor.Actor, Action: action, PolicyID: id, Revision: revision})
	})
	return clonePolicy(out), e
}
func (s *Service) DeletePolicy(ctx context.Context, actorID, id string, revision int) error {
	actor, e := s.principal(ctx, actorID)
	if e != nil || !actor.CanPublish {
		return ErrDenied
	}
	if e = s.lock(ctx); e != nil {
		return e
	}
	defer s.op.Unlock()
	return s.mutate(func(d *state) error {
		p, ok := d.Policies[id]
		if !ok {
			return ErrNotFound
		}
		if p.Revision != revision {
			return ErrConflict
		}
		delete(d.Policies, id)
		return appendAudit(d, Audit{At: s.now().UTC(), Actor: actor.Actor, Action: "policy_deleted", PolicyID: id, Revision: revision})
	})
}
func (s *Service) Catalog(ctx context.Context, actorID, id, q string, offset, limit int) (Page[Ref], error) {
	if offset < 0 || limit < 1 || limit > 100 || len(q) > 128 {
		return Page[Ref]{}, ErrInvalid
	}
	actor, e := s.principal(ctx, actorID)
	if e != nil {
		return Page[Ref]{}, e
	}
	p, e := s.Policy(ctx, actorID, id)
	if e != nil {
		return Page[Ref]{}, e
	}
	if !actor.CanPublish && !canApply(p, actor) {
		return Page[Ref]{}, ErrDenied
	}
	publisher, e := s.principal(ctx, p.Publisher.ID)
	if e != nil || !publisher.CanPublish {
		return Page[Ref]{}, ErrDenied
	}
	r := s.runnerSnapshot()
	if r.Catalog == nil {
		return Page[Ref]{}, ErrUnavailable
	}
	return r.Catalog(ctx, p, q, offset, limit)
}
func chainPossible(stages []Stage, people []Principal, owner string, used map[string]bool) bool {
	if len(stages) == 0 {
		return true
	}
	candidates := make([][]string, len(stages))
	for i, stage := range stages {
		for _, p := range people {
			if p.CanReview && p.ID != owner && !used[p.ID] && matches(p, stage.Subjects) {
				candidates[i] = append(candidates[i], p.ID)
			}
		}
		if len(candidates[i]) == 0 {
			return false
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return len(candidates[i]) < len(candidates[j]) })
	assigned := map[string]int{}
	var match func(int, map[string]bool) bool
	match = func(stage int, seen map[string]bool) bool {
		for _, id := range candidates[stage] {
			if seen[id] {
				continue
			}
			seen[id] = true
			if prior, ok := assigned[id]; !ok || match(prior, seen) {
				assigned[id] = stage
				return true
			}
		}
		return false
	}
	for i := range stages {
		if !match(i, map[string]bool{}) {
			return false
		}
	}
	return true
}
func (s *Service) prepare(ctx context.Context, p Policy, targets []Target) ([]Prepared, error) {
	runner := s.runnerSnapshot()
	if runner.Resolve == nil {
		return nil, ErrUnavailable
	}
	rows, e := runner.Resolve(ctx, targets)
	if e != nil {
		return nil, e
	}
	if len(rows) != len(targets) {
		return nil, ErrInvalid
	}
	for i, v := range rows {
		if validatePrepared(v) != nil || targetKey(v.Target) != targetKey(targets[i]) || !slices.Equal(v.Actions, targets[i].Actions) || !allowed(p, v) {
			return nil, ErrDenied
		}
	}
	return rows, nil
}
func (s *Service) window(p Policy, start, end time.Time) error {
	now := s.now().UTC()
	if start.IsZero() || end.IsZero() || !start.Before(end) || !end.After(now) || end.After(now.Add(365*24*time.Hour)) || end.Sub(start) > time.Duration(p.MaxDurationMinutes)*time.Minute {
		return ErrInvalid
	}
	return nil
}
func (s *Service) Submit(ctx context.Context, actorID string, in SubmitInput) (Ticket, error) {
	actor, e := s.principal(ctx, actorID)
	if e != nil {
		return Ticket{}, e
	}
	if !IDPattern.MatchString(in.RequestID) || !IDPattern.MatchString(in.PolicyID) || in.PolicyRevision < 1 || in.Name == "" || !validText(in.Name, 240) || !validText(in.Reason, 4000) {
		return Ticket{}, ErrInvalid
	}
	targets, e := normalizeTargets(in.Targets)
	if e != nil {
		return Ticket{}, e
	}
	in.Targets = targets
	inputHash := hash(in)
	if e = s.lock(ctx); e != nil {
		return Ticket{}, e
	}
	defer s.op.Unlock()
	s.mu.Lock()
	for _, prior := range s.data.Tickets {
		if prior.Owner.ID == actorID && prior.RequestID == in.RequestID {
			s.mu.Unlock()
			if prior.InputHash != inputHash {
				return Ticket{}, ErrConflict
			}
			return s.decorate(prior, actor), nil
		}
	}
	p, ok := s.data.Policies[in.PolicyID]
	s.mu.Unlock()
	if !ok {
		return Ticket{}, ErrNotFound
	}
	if p.Revision != in.PolicyRevision {
		return Ticket{}, ErrConflict
	}
	if !canApply(p, actor) {
		return Ticket{}, ErrDenied
	}
	publisher, e := s.principal(ctx, p.Publisher.ID)
	if e != nil || !publisher.CanPublish {
		return Ticket{}, ErrDenied
	}
	people, e := s.runnerSnapshot().People(ctx)
	if e != nil {
		return Ticket{}, e
	}
	if !chainPossible(p.Stages, people, actor.ID, nil) {
		return Ticket{}, ErrReviewers
	}
	if in.StartsAt.IsZero() {
		in.StartsAt = s.now().UTC()
	}
	in.StartsAt, in.EndsAt = in.StartsAt.UTC(), in.EndsAt.UTC()
	if in.StartsAt.Before(s.now().Add(-5 * time.Minute)) {
		return Ticket{}, ErrInvalid
	}
	if e = s.window(p, in.StartsAt, in.EndsAt); e != nil {
		return Ticket{}, e
	}
	prepared, e := s.prepare(ctx, p, targets)
	if e != nil {
		return Ticket{}, e
	}
	id, e := newID("ticket-")
	if e != nil {
		return Ticket{}, e
	}
	now := s.now().UTC()
	expires := minTime(now.Add(time.Duration(p.ApprovalTTLMinutes)*time.Minute), in.EndsAt)
	t := Ticket{ID: id, Name: in.Name, Owner: actor.Actor, Publisher: p.Publisher, PolicyID: p.ID, PolicyRevision: p.Revision, PolicyName: p.Name, Stages: p.Stages, CC: p.CC, Reason: in.Reason, StartsAt: in.StartsAt, EndsAt: in.EndsAt, ApprovalExpiresAt: expires, State: "pending", Revision: 1, Approvals: []Approval{}, Comments: []Comment{}, GrantIDs: []string{}, CreatedAt: now, UpdatedAt: now, Targets: []Ref{}}
	for _, v := range prepared {
		t.Targets = append(t.Targets, v.Ref)
	}
	record := record{Ticket: cloneTicket(t), RequestID: in.RequestID, InputHash: inputHash, Prepared: prepared, Decisions: []decisionReceipt{}}
	e = s.mutate(func(d *state) error {
		if len(d.Tickets) >= MaxTickets {
			return ErrCapacity
		}
		d.Tickets[id] = record
		return appendAudit(d, Audit{At: now, Actor: actor.Actor, Action: "submitted", TicketID: id, PolicyID: p.ID, Revision: 1})
	})
	return s.decorate(record, actor), e
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func (s *Service) canRead(r record, p Principal) bool {
	if p.ID == r.Owner.ID || p.CanViewAll || p.CanRevoke || matches(p, r.CC) {
		return true
	}
	if p.CanReview {
		for _, stage := range r.Stages {
			if matches(p, stage.Subjects) {
				return true
			}
		}
	}
	return false
}
func (s *Service) decorate(r record, p Principal) Ticket {
	out := cloneTicket(r.Ticket)
	out.CanReview = eligible(p, out) && s.now().Before(out.ApprovalExpiresAt)
	out.CanAmend = out.State == "pending" && (p.ID == out.Owner.ID || eligible(p, out))
	out.CanRevoke = !terminal(out.State) && (p.ID == out.Owner.ID || p.CanRevoke)
	s.mu.Lock()
	policy, ok := s.data.Policies[out.PolicyID]
	s.mu.Unlock()
	out.Outdated = !ok || !policy.Enabled || policy.Revision != out.PolicyRevision
	return out
}
func (s *Service) Get(ctx context.Context, actorID, id string) (Ticket, error) {
	actor, e := s.principal(ctx, actorID)
	if e != nil {
		return Ticket{}, e
	}
	s.mu.Lock()
	r, ok := s.data.Tickets[id]
	s.mu.Unlock()
	if !ok || !s.canRead(r, actor) {
		return Ticket{}, ErrNotFound
	}
	return s.decorate(r, actor), nil
}
func (s *Service) List(ctx context.Context, actorID string, q Query) (Page[Ticket], error) {
	if q.Offset < 0 || q.Limit < 1 || q.Limit > 100 || len(q.Search) > 128 || q.State != "" && !validState(q.State) || q.View != "" && q.View != "mine" && q.View != "assigned" && q.View != "all" && q.View != "cc" {
		return Page[Ticket]{}, ErrInvalid
	}
	actor, e := s.principal(ctx, actorID)
	if e != nil {
		return Page[Ticket]{}, e
	}
	if q.View == "all" && !actor.CanViewAll {
		return Page[Ticket]{}, ErrDenied
	}
	s.mu.Lock()
	rows := []record{}
	for _, r := range s.data.Tickets {
		visible := s.canRead(r, actor)
		switch q.View {
		case "mine":
			visible = r.Owner.ID == actorID
		case "assigned":
			visible = eligible(actor, r.Ticket)
		case "cc":
			visible = matches(actor, r.CC)
		}
		if visible && (q.State == "" || q.State == r.State) && (q.Search == "" || strings.Contains(strings.ToLower(r.Name+" "+r.Owner.Name+" "+r.ID), strings.ToLower(q.Search))) {
			rows = append(rows, r)
		}
	}
	s.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CreatedAt.Equal(rows[j].CreatedAt) {
			return rows[i].ID < rows[j].ID
		}
		return rows[i].CreatedAt.After(rows[j].CreatedAt)
	})
	out := Page[Ticket]{Results: []Ticket{}, Total: len(rows)}
	offset := min(q.Offset, len(rows))
	for _, r := range rows[offset:min(len(rows), offset+q.Limit)] {
		t := s.decorate(r, actor)
		t.Comments = nil
		out.Results = append(out.Results, t)
	}
	return out, nil
}
func (s *Service) Amend(ctx context.Context, actorID, id string, in Amendment) (Ticket, error) {
	actor, e := s.principal(ctx, actorID)
	if e != nil {
		return Ticket{}, e
	}
	if e = s.lock(ctx); e != nil {
		return Ticket{}, e
	}
	defer s.op.Unlock()
	s.mu.Lock()
	r, ok := s.data.Tickets[id]
	p, pok := s.data.Policies[r.PolicyID]
	s.mu.Unlock()
	if !ok || !s.canRead(r, actor) {
		return Ticket{}, ErrNotFound
	}
	if r.State != "pending" || r.Revision != in.Revision {
		return Ticket{}, ErrConflict
	}
	if actor.ID != r.Owner.ID && !eligible(actor, r.Ticket) {
		return Ticket{}, ErrDenied
	}
	owner, e := s.principal(ctx, r.Owner.ID)
	if e != nil || !pok || !canApply(p, owner) {
		return Ticket{}, ErrDenied
	}
	if in.StartsAt.IsZero() {
		in.StartsAt = s.now().UTC()
	}
	if !validText(in.Reason, 4000) || s.window(p, in.StartsAt, in.EndsAt) != nil {
		return Ticket{}, ErrInvalid
	}
	targets, e := normalizeTargets(in.Targets)
	if e != nil {
		return Ticket{}, e
	}
	prepared, e := s.prepare(ctx, p, targets)
	if e != nil {
		return Ticket{}, e
	}
	people, e := s.runnerSnapshot().People(ctx)
	if e != nil {
		return Ticket{}, e
	}
	if !chainPossible(p.Stages, people, owner.ID, nil) {
		return Ticket{}, ErrReviewers
	}
	e = s.mutate(func(d *state) error {
		current := d.Tickets[id]
		if current.Revision != in.Revision {
			return ErrConflict
		}
		current.PolicyRevision = p.Revision
		current.PolicyName = p.Name
		current.Publisher = p.Publisher
		current.Stages = p.Stages
		current.CC = p.CC
		current.CurrentStage = 0
		current.Approvals = []Approval{}
		current.StartsAt = in.StartsAt.UTC()
		current.EndsAt = in.EndsAt.UTC()
		current.Reason = in.Reason
		current.ApprovalExpiresAt = minTime(s.now().Add(time.Duration(p.ApprovalTTLMinutes)*time.Minute), current.EndsAt)
		current.Prepared = prepared
		current.Targets = []Ref{}
		for _, v := range prepared {
			current.Targets = append(current.Targets, v.Ref)
		}
		current.Revision++
		current.UpdatedAt = s.now().UTC()
		current.ErrorCode = ""
		d.Tickets[id] = current
		r = current
		return appendAudit(d, Audit{At: s.now().UTC(), Actor: actor.Actor, Action: "amended_approvals_reset", TicketID: id, PolicyID: p.ID, Revision: current.Revision})
	})
	return s.decorate(r, actor), e
}
func (s *Service) Decide(ctx context.Context, actorID, id string, in Decision) (Ticket, error) {
	actor, e := s.principal(ctx, actorID)
	if e != nil || !actor.CanReview {
		return Ticket{}, ErrDenied
	}
	if !IDPattern.MatchString(in.RequestID) || in.Revision < 1 || in.Action != "approve" && in.Action != "reject" || !validText(in.Comment, 2000) {
		return Ticket{}, ErrInvalid
	}
	if e = s.lock(ctx); e != nil {
		return Ticket{}, e
	}
	defer s.op.Unlock()
	s.mu.Lock()
	r, ok := s.data.Tickets[id]
	s.mu.Unlock()
	if !ok || !s.canRead(r, actor) {
		return Ticket{}, ErrNotFound
	}
	digest := hash(in)
	for _, receipt := range r.Decisions {
		if receipt.ID == in.RequestID {
			if receipt.ActorID != actorID || receipt.Digest != digest {
				return Ticket{}, ErrConflict
			}
			return s.decorate(r, actor), nil
		}
	}
	if r.Revision != in.Revision || r.State != "pending" {
		return Ticket{}, ErrConflict
	}
	if !eligible(actor, r.Ticket) {
		return Ticket{}, ErrDenied
	}
	if !s.now().Before(r.ApprovalExpiresAt) {
		return Ticket{}, ErrConflict
	}
	if _, e := s.checkIntent(ctx, r, false); e != nil {
		return Ticket{}, e
	}
	if in.Action == "approve" {
		used := map[string]bool{actorID: true}
		for _, a := range r.Approvals {
			used[a.Actor.ID] = true
		}
		people, e := s.runnerSnapshot().People(ctx)
		if e != nil {
			return Ticket{}, e
		}
		if !chainPossible(r.Stages[r.CurrentStage+1:], people, r.Owner.ID, used) {
			return Ticket{}, ErrReviewers
		}
	}
	e = s.mutate(func(d *state) error {
		current := d.Tickets[id]
		if current.Revision != in.Revision {
			return ErrConflict
		}
		if len(current.Decisions) >= 100 {
			return ErrCapacity
		}
		now := s.now().UTC()
		current.Decisions = append(current.Decisions, decisionReceipt{ID: in.RequestID, ActorID: actorID, Digest: digest})
		if in.Action == "reject" {
			current.State = "rejected"
			current.ClosedAt = now
		} else {
			current.Approvals = append(current.Approvals, Approval{Stage: current.CurrentStage, Actor: actor.Actor, At: now, Comment: in.Comment})
			current.CurrentStage++
			if current.CurrentStage == len(current.Stages) {
				current.State = "issuing"
				current.Digest = intentDigest(current)
			}
		}
		current.Revision++
		current.UpdatedAt = now
		d.Tickets[id] = current
		r = current
		return appendAudit(d, Audit{At: now, Actor: actor.Actor, Action: in.Action, TicketID: id, PolicyID: current.PolicyID, Revision: current.Revision, Note: in.Comment})
	})
	if e != nil {
		return Ticket{}, e
	}
	if r.State == "issuing" {
		s.reconcileLocked(ctx, id)
		s.mu.Lock()
		r = s.data.Tickets[id]
		s.mu.Unlock()
	}
	return s.decorate(r, actor), nil
}
func (s *Service) Comment(ctx context.Context, actorID, id, text string) (Ticket, error) {
	actor, e := s.principal(ctx, actorID)
	if e != nil {
		return Ticket{}, e
	}
	if text == "" || !validText(text, 4000) {
		return Ticket{}, ErrInvalid
	}
	if e = s.lock(ctx); e != nil {
		return Ticket{}, e
	}
	defer s.op.Unlock()
	var out record
	e = s.mutate(func(d *state) error {
		r, ok := d.Tickets[id]
		if !ok || !s.canRead(r, actor) {
			return ErrNotFound
		}
		if len(r.Comments) >= 100 {
			return ErrCapacity
		}
		now := s.now().UTC()
		r.Comments = append(r.Comments, Comment{Actor: actor.Actor, At: now, Text: text})
		r.UpdatedAt = now
		d.Tickets[id] = r
		out = r
		return appendAudit(d, Audit{At: now, Actor: actor.Actor, Action: "commented", TicketID: id, PolicyID: r.PolicyID, Note: text, Revision: r.Revision})
	})
	return s.decorate(out, actor), e
}
func (s *Service) Cancel(ctx context.Context, actorID, id string, revision int) (Ticket, error) {
	actor, e := s.principal(ctx, actorID)
	if e != nil {
		return Ticket{}, e
	}
	if e = s.lock(ctx); e != nil {
		return Ticket{}, e
	}
	defer s.op.Unlock()
	var out record
	e = s.mutate(func(d *state) error {
		r, ok := d.Tickets[id]
		if !ok || !s.canRead(r, actor) {
			return ErrNotFound
		}
		if actor.ID != r.Owner.ID && !actor.CanRevoke {
			return ErrDenied
		}
		if r.Revision != revision {
			return ErrConflict
		}
		if terminal(r.State) {
			out = r
			return nil
		}
		now := s.now().UTC()
		if r.State == "pending" {
			r.State = "cancelled"
			r.ClosedAt = now
		} else {
			r.State = "revoking"
			r.ErrorCode = "revocation_requested"
		}
		r.Revision++
		r.UpdatedAt = now
		d.Tickets[id] = r
		out = r
		return appendAudit(d, Audit{At: now, Actor: actor.Actor, Action: "cancellation_requested", TicketID: id, PolicyID: r.PolicyID, Revision: r.Revision})
	})
	if e != nil {
		return Ticket{}, e
	}
	if out.State == "revoking" {
		s.reconcileLocked(ctx, id)
		s.mu.Lock()
		out = s.data.Tickets[id]
		s.mu.Unlock()
	}
	return s.decorate(out, actor), nil
}
func (s *Service) Audit(ctx context.Context, actorID string, offset, limit int) (Page[Audit], error) {
	if offset < 0 || limit < 1 || limit > 100 {
		return Page[Audit]{}, ErrInvalid
	}
	actor, e := s.principal(ctx, actorID)
	if e != nil {
		return Page[Audit]{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := []Audit{}
	for i := len(s.data.Audit) - 1; i >= 0; i-- {
		a := s.data.Audit[i]
		visible := actor.CanViewAll
		if a.TicketID != "" {
			if r, ok := s.data.Tickets[a.TicketID]; ok {
				visible = visible || s.canRead(r, actor)
			}
		} else {
			visible = visible || actor.CanPublish
		}
		if visible {
			rows = append(rows, a)
		}
	}
	out := Page[Audit]{Results: []Audit{}, Total: len(rows)}
	offset = min(offset, len(rows))
	out.Results = append(out.Results, rows[offset:min(len(rows), offset+limit)]...)
	return out, nil
}
