package rotationplans

import (
	"context"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"sort"
	"time"
)

func terminal(v string) bool {
	return v == "succeeded" || v == "partial" || v == "failed" || v == "cancelled" || v == "interrupted"
}
func validRunState(v string) bool {
	return terminal(v) || v == "queued" || v == "running" || v == "recovery_required"
}
func itemTerminal(v string) bool {
	switch v {
	case "succeeded", "failed", "cancelled", "not_due", "changed", "denied", "interrupted":
		return true
	}
	return false
}
func validItemState(v string) bool {
	return itemTerminal(v) || v == "queued" || v == "running" || v == "recovering" || v == "recovery_required" || v == "linked"
}
func runState(r Run) string {
	open, pending, success, failed, skipped := 0, 0, 0, 0, 0
	for _, v := range r.Items {
		switch v.State {
		case "recovery_required", "recovering":
			pending++
		case "queued", "running", "linked":
			open++
		case "succeeded":
			success++
		case "not_due":
			skipped++
		default:
			failed++
		}
	}
	if pending > 0 {
		return "recovery_required"
	}
	if open > 0 {
		return "running"
	}
	if r.Cancelled {
		return "cancelled"
	}
	if failed == 0 {
		return "succeeded"
	}
	if success+skipped > 0 {
		return "partial"
	}
	return "failed"
}
func linkResults(r *Run) {
	states := map[string]Item{}
	for _, v := range r.Items {
		if v.LinkedTo == "" {
			states[v.ID] = v
		}
	}
	for i, v := range r.Items {
		if v.LinkedTo == "" {
			continue
		}
		leader, ok := states[v.LinkedTo]
		if !ok {
			continue
		}
		if itemTerminal(leader.State) {
			v.State, v.ErrorCode, v.FinishedAt = leader.State, leader.ErrorCode, leader.FinishedAt
			v.AfterRevision = 0 // A linked record never claims its own remote mutation.
			r.Items[i] = v
		}
	}
}
func (s *Service) Submit(ctx context.Context, actor Actor, planID, requestID string, all bool, origin ...accesspolicies.Origin) (Run, error) {
	return s.submit(ctx, actor, planID, requestID, false, all, origin...)
}
func (s *Service) submit(ctx context.Context, actor Actor, planID, requestID string, scheduled, all bool, origin ...accesspolicies.Origin) (Run, error) {
	if !ValidActor(actor) || !IDPattern.MatchString(requestID) {
		return Run{}, ErrInvalid
	}
	runner := s.runnerSnapshot()
	if runner.Prepare == nil || runner.Execute == nil || runner.Inspect == nil || runner.Authorize == nil {
		return Run{}, ErrBusy
	}
	if e := runner.Authorize(actor); e != nil {
		return Run{}, e
	}
	s.mu.Lock()
	p, ok := s.data.Plans[planID]
	if !ok || p.Actor.ID != actor.ID && !all {
		s.mu.Unlock()
		return Run{}, ErrNotFound
	}
	p.Plan = clonePlan(p.Plan)
	s.mu.Unlock()
	if e := runner.authorizeMode(actor, p.PasswordMode); e != nil {
		return Run{}, e
	}
	s.mu.Lock()
	for _, r := range s.data.Runs {
		if r.Actor.ID == actor.ID && r.RequestID == requestID {
			s.mu.Unlock()
			if r.PlanID != planID || r.Scheduled != scheduled || r.ParentRunID != "" {
				return Run{}, ErrConflict
			}
			return cloneRun(r.Run), nil
		}
	}
	s.mu.Unlock()
	if scheduled && (!p.Enabled || p.Kind == "manual") {
		return Run{}, ErrConflict
	}
	prepared, e := runner.Prepare(ctx, actor, p.Targets)
	if errors.Is(e, ErrDenied) {
		return Run{}, e
	}
	byID := map[string]Prepared{}
	if e == nil {
		if len(prepared) != len(p.Targets) {
			return Run{}, ErrInvalid
		}
		for _, v := range prepared {
			if validatePrepared(v) != nil {
				return Run{}, ErrInvalid
			}
			if _, ok := byID[v.AccountID]; ok {
				return Run{}, ErrInvalid
			}
			byID[v.AccountID] = v
		}
	} else {
		// One disappeared target does not prevent unrelated accounts from rotating.
		for _, selection := range p.Targets {
			rows, e := runner.Prepare(ctx, actor, []Selection{selection})
			if errors.Is(e, ErrDenied) {
				return Run{}, e
			}
			if e == nil && len(rows) == 1 && validatePrepared(rows[0]) == nil && rows[0].AccountID == selection.AccountID {
				byID[selection.AccountID] = rows[0]
			}
		}
	}
	if e := ctx.Err(); e != nil {
		return Run{}, e
	}
	now := s.now().UTC()
	id, e := newID("rotation-run-")
	if e != nil {
		return Run{}, e
	}
	out := Run{ID: id, PlanID: p.ID, PlanRevision: p.Revision, Name: p.Name, Actor: actor, RequestID: requestID, Scheduled: scheduled, State: "queued", CreatedAt: now, Items: []Item{}}
	out.PasswordPolicy = p.PasswordPolicy
	out.PasswordMode = p.PasswordMode
	out.AccessOrigin = p.AccessOrigin
	if !scheduled && len(origin) == 1 {
		out.AccessOrigin = origin[0]
	}
	intents := map[string]Intent{}
	groupDue := map[string]bool{}
	for _, v := range byID {
		if !scheduled || !p.OnlyDue || v.RotatedAt.IsZero() || !v.RotatedAt.Add(time.Duration(p.IntervalHours)*time.Hour).After(now) {
			groupDue[v.Group] = true
		}
	}
	groups := map[string]string{}
	for i, selection := range p.Targets {
		itemID, e := newID("rotation-item-")
		if e != nil {
			return Run{}, e
		}
		item := Item{ID: itemID, Ref: p.Refs[i], State: "changed", ErrorCode: "source_changed", FinishedAt: now}
		if v, ok := byID[selection.AccountID]; ok && v.Binding == p.Bindings[selection.AccountID] {
			item.Ref = v.Ref
			item.BeforeRevision = v.Revision
			item.State = "queued"
			item.ErrorCode = ""
			item.FinishedAt = time.Time{}
			if leader := groups[v.Group]; leader != "" {
				item.LinkedTo = leader
				item.State = "linked"
			} else {
				groups[v.Group] = itemID
				intents[itemID] = Intent{RequestID: itemID, Actor: actor, Target: v, Origin: out.AccessOrigin}
				if v.CredentialType == "password" {
					op := intents[itemID]
					op.PasswordPolicy = out.PasswordPolicy
					intents[itemID] = op
				}
				if v.CredentialType == "password" && p.PasswordMode == "fixed" {
					op := intents[itemID]
					op.FixedSecretID = p.FixedSecretID
					intents[itemID] = op
				}
				if !groupDue[v.Group] {
					item.State = "not_due"
					item.FinishedAt = now
				}
			}
		}
		out.Items = append(out.Items, item)
	}
	linkResults(&out)
	out.State = runState(out)
	if terminal(out.State) {
		out.FinishedAt = now
	}
	e = s.mutate(func(d *state) error {
		current, ok := d.Plans[p.ID]
		if !ok || current.Revision != p.Revision {
			return ErrConflict
		}
		for _, r := range d.Runs {
			if r.Actor.ID == actor.ID && r.RequestID == requestID {
				if r.PlanID != planID || r.Scheduled != scheduled || r.ParentRunID != "" {
					return ErrConflict
				}
				out = cloneRun(r.Run)
				return nil
			}
			if r.PlanID == p.ID && !terminal(r.State) {
				return ErrBusy
			}
		}
		if len(d.Runs) >= MaxRuns || len(d.Audit) >= MaxAudit {
			return ErrCapacity
		}
		d.Runs[id] = runRecord{Run: cloneRun(out), Intents: intents, FixedPassword: p.FixedPassword, FixedSecretID: p.FixedSecretID}
		current.LastRunID = id
		current.ErrorCode = ""
		if scheduled {
			if current.Kind == "once" {
				current.Enabled = false
				current.NextRun = time.Time{}
			} else {
				current.NextRun = now.Add(time.Duration(current.IntervalHours) * time.Hour)
			}
		} else if current.Kind == "once" {
			current.Enabled = false
			current.NextRun = time.Time{}
		}
		d.Plans[p.ID] = current
		d.Audit = append(d.Audit, Audit{Origin: out.AccessOrigin, At: now, Actor: actor, Action: "submitted", PlanID: p.ID, RunID: id, Revision: p.Revision})
		return nil
	})
	return out, e
}
func (s *Service) Cancel(id string, actor Actor, all bool) error {
	if !ValidActor(actor) {
		return ErrInvalid
	}
	e := s.mutate(func(d *state) error {
		r, ok := d.Runs[id]
		if !ok || r.Actor.ID != actor.ID && !all {
			return ErrNotFound
		}
		if terminal(r.State) {
			return ErrConflict
		}
		if len(d.Audit) >= MaxAudit {
			return ErrCapacity
		}
		r.Cancelled = true
		for i, v := range r.Items {
			if v.State == "queued" {
				v.State = "cancelled"
				v.FinishedAt = s.now().UTC()
				r.Items[i] = v
			}
		}
		linkResults(&r.Run)
		r.State = runState(r.Run)
		if terminal(r.State) {
			r.FinishedAt = s.now().UTC()
		}
		d.Runs[id] = r
		d.Audit = append(d.Audit, Audit{At: s.now().UTC(), Actor: actor, Action: "cancelled", PlanID: r.PlanID, RunID: id})
		return nil
	})
	if e == nil {
		s.mu.Lock()
		if s.activeRun == id && s.activeCancel != nil {
			s.activeCancel()
		}
		s.mu.Unlock()
	}
	return e
}
func (s *Service) Recover(id string, actor Actor, all bool, origin ...accesspolicies.Origin) error {
	if !ValidActor(actor) {
		return ErrInvalid
	}
	if runner := s.runnerSnapshot(); runner.Recover == nil {
		return ErrBusy
	} else if e := runner.Authorize(actor); e != nil {
		return e
	}
	e := s.mutate(func(d *state) error {
		r, ok := d.Runs[id]
		if !ok || r.Actor.ID != actor.ID && !all {
			return ErrNotFound
		}
		if err := s.runner.authorizeMode(actor, r.PasswordMode); err != nil {
			return err
		}
		if r.State != "recovery_required" || r.Recovery != nil {
			return ErrConflict
		}
		if len(d.Audit) >= MaxAudit {
			return ErrCapacity
		}
		source := accesspolicies.Origin{Method: "credential_rotation"}
		if len(origin) > 0 {
			source = origin[0]
		}
		r.Recovery = &recoveryRequest{Actor: actor, At: s.now().UTC(), Origin: source}
		d.Runs[id] = r
		d.Audit = append(d.Audit, Audit{Origin: source, At: s.now().UTC(), Actor: actor, Action: "recovery_requested", PlanID: r.PlanID, RunID: id})
		return nil
	})
	if e == nil {
		s.mu.Lock()
		delete(s.inspectAfter, id)
		s.mu.Unlock()
	}
	return e
}
func (s *Service) Start(owner context.Context) {
	s.mu.Lock()
	if s.closed || s.started {
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
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			s.Tick()
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
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
	if s.activeCancel != nil {
		s.activeCancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
}
func (s *Service) Tick() {
	s.tickMu.Lock()
	defer s.tickMu.Unlock()
	if s.ctx.Err() != nil {
		return
	}
	s.schedule()
	s.mu.Lock()
	if s.closed || s.working {
		s.mu.Unlock()
		return
	}
	records := []runRecord{}
	now := s.now()
	for _, r := range s.data.Runs {
		if !terminal(r.State) && !s.inspectAfter[r.ID].After(now) {
			records = append(records, r)
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].CreatedAt.Before(records[j].CreatedAt) })
	if len(records) == 0 {
		s.mu.Unlock()
		return
	}
	id := records[0].ID
	ctx, cancel := context.WithCancel(s.ctx)
	s.working = true
	s.activeRun = id
	s.activeCancel = cancel
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		defer cancel()
		s.work(ctx, id)
		s.mu.Lock()
		s.working = false
		s.activeRun = ""
		s.activeCancel = nil
		s.mu.Unlock()
	}()
}
func (s *Service) schedule() {
	s.mu.Lock()
	now := s.now().UTC()
	plans := []Plan{}
	for _, p := range s.data.Plans {
		if !p.Enabled || p.Kind == "manual" || p.NextRun.After(now) {
			continue
		}
		active := false
		for _, r := range s.data.Runs {
			if r.PlanID == p.ID && !terminal(r.State) {
				active = true
				break
			}
		}
		if !active {
			plans = append(plans, clonePlan(p.Plan))
		}
	}
	s.mu.Unlock()
	for _, p := range plans {
		request, e := newID("schedule-")
		if e != nil {
			return
		}
		_, e = s.submit(s.ctx, p.Actor, p.ID, request, true, true)
		if errors.Is(e, ErrDenied) || errors.Is(e, ErrCapacity) {
			_ = s.mutate(func(d *state) error {
				current, ok := d.Plans[p.ID]
				if !ok || current.Revision != p.Revision {
					return nil
				}
				current.Enabled = false
				current.NextRun = time.Time{}
				current.ErrorCode = "denied"
				if errors.Is(e, ErrCapacity) {
					current.ErrorCode = "capacity"
				}
				current.Revision++
				current.UpdatedAt = s.now().UTC()
				d.Plans[p.ID] = current
				if len(d.Audit) < MaxAudit {
					d.Audit = append(d.Audit, Audit{At: s.now().UTC(), Actor: p.Actor, Action: current.ErrorCode + "_paused", PlanID: p.ID, Revision: current.Revision})
				}
				return nil
			})
		}
	}
}
func (s *Service) updateItem(run, id string, out Outcome) error {
	return s.mutate(func(d *state) error {
		r, ok := d.Runs[run]
		if !ok {
			return ErrNotFound
		}
		for i, v := range r.Items {
			if v.ID == id {
				switch out.State {
				case "succeeded", "failed", "changed":
					v.State = out.State
				case "recovery_required":
					v.State = "recovery_required"
				case "denied":
					v.State = "denied"
				case "cancelled":
					v.State = "cancelled"
				case "not_started":
					v.State = "queued"
				default:
					v.State = "interrupted"
				}
				v.ErrorCode = out.Code
				v.AfterRevision = out.Revision
				if itemTerminal(v.State) {
					v.FinishedAt = s.now().UTC()
					if !out.At.IsZero() {
						v.FinishedAt = out.At
					}
				}
				r.Items[i] = v
				break
			}
		}
		linkResults(&r.Run)
		r.State = runState(r.Run)
		if terminal(r.State) {
			r.FinishedAt = s.now().UTC()
		}
		d.Runs[run] = r
		return nil
	})
}
func (s *Service) work(ctx context.Context, id string) {
	runner := s.runnerSnapshot()
	if runner.Execute == nil || runner.Inspect == nil || runner.Authorize == nil {
		return
	}
	s.mu.Lock()
	record, ok := s.data.Runs[id]
	record.Run = cloneRun(record.Run)
	s.mu.Unlock()
	if !ok {
		return
	}
	pending := false
	for _, item := range record.Items {
		if item.LinkedTo != "" || itemTerminal(item.State) {
			continue
		}
		intent, ok := record.Intents[item.ID]
		if !ok {
			continue
		}
		if intent.FixedSecretID != "" {
			intent.FixedPassword = record.FixedPassword
		}
		// Every claimed operation first reconciles its Vault receipt. No remote
		// mutation is replayed just because a plan result write or response failed.
		if item.State != "queued" {
			out, e := runner.Inspect(ctx, intent)
			if e != nil {
				pending = true
				continue
			}
			if out.State != "not_started" {
				if out.State == "recovery_required" && record.Recovery != nil && runner.Recover != nil {
					recoveryActor := record.Recovery.Actor
					if e := runner.authorizeMode(recoveryActor, record.PasswordMode); e == nil {
						step, cancel := context.WithTimeout(ctx, 90*time.Second)
						recoveryIntent := intent
						recoveryIntent.Origin = record.Recovery.Origin
						recovered, _ := runner.Recover(step, recoveryIntent, recoveryActor, func() error {
							if e := step.Err(); e != nil {
								return e
							}
							return runner.authorizeMode(recoveryActor, record.PasswordMode)
						})
						cancel()
						if recovered.State == "denied" {
							recovered.State = "recovery_required"
							recovered.Code = "denied"
						}
						if recovered.State != "" {
							out = recovered
						}
					}
				}
				if s.updateItem(id, item.ID, out) != nil {
					return
				}
				if out.State == "recovery_required" {
					pending = true
				}
				continue
			}
		}
		s.mu.Lock()
		current := s.data.Runs[id]
		cancelled := current.Cancelled
		s.mu.Unlock()
		if cancelled || ctx.Err() != nil {
			if ctx.Err() == nil {
				_ = s.updateItem(id, item.ID, Outcome{State: "cancelled", Code: "cancelled"})
			}
			continue
		}
		if e := runner.authorizeMode(record.Actor, record.PasswordMode); e != nil {
			_ = s.updateItem(id, item.ID, Outcome{State: "denied", Code: "denied"})
			continue
		}
		if e := s.mutate(func(d *state) error {
			r, ok := d.Runs[id]
			if !ok || r.Cancelled {
				return ErrConflict
			}
			for i := range r.Items {
				if r.Items[i].ID == item.ID {
					r.Items[i].State = "running"
					r.Items[i].StartedAt = s.now().UTC()
					r.Items[i].ErrorCode = ""
					break
				}
			}
			r.State = "running"
			d.Runs[id] = r
			return nil
		}); e != nil {
			return
		}
		step, cancel := context.WithTimeout(ctx, 90*time.Second)
		out, e := runner.Execute(step, intent, func() error {
			if e := step.Err(); e != nil {
				return e
			}
			return runner.authorizeMode(record.Actor, record.PasswordMode)
		})
		cancel()
		if out.State == "" {
			// If the executor failed before returning a receipt, preserve uncertainty.
			out = Outcome{State: "recovery_required", Code: "outcome_unavailable"}
			if errors.Is(e, ErrDenied) {
				out = Outcome{State: "denied", Code: "denied"}
			}
		}
		if s.ctx.Err() != nil {
			return
		}
		if s.updateItem(id, item.ID, out) != nil {
			return
		}
		if out.State == "recovery_required" {
			pending = true
		}
	}
	if record.Recovery != nil {
		_ = s.mutate(func(d *state) error {
			r, ok := d.Runs[id]
			if ok && r.Recovery != nil && r.Recovery.At.Equal(record.Recovery.At) {
				r.Recovery = nil
				d.Runs[id] = r
			}
			return nil
		})
	}
	if pending {
		s.mu.Lock()
		s.inspectAfter[id] = s.now().Add(5 * time.Second)
		s.mu.Unlock()
	}
}
