package rotationplans

import (
	"context"
	"errors"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
)

func (r Runner) authorizeRun(a Actor, mode, operation string) error {
	if operation == "check" {
		if r.AuthorizeCheck == nil {
			return ErrDenied
		}
		return r.AuthorizeCheck(a)
	}
	return r.authorizeMode(a, mode)
}
func (r Runner) authorizeAny(a Actor) error {
	if r.Authorize != nil && r.Authorize(a) == nil {
		return nil
	}
	if r.AuthorizeCheck != nil && r.AuthorizeCheck(a) == nil {
		return nil
	}
	return ErrDenied
}
func (r Runner) authorizeRunTargets(a Actor, targets []Selection, operation string) error {
	if operation == "check" {
		return r.authorizeRun(a, "", operation)
	}
	return r.authorizeTargets(a, targets)
}
func snapshotRunRecord(out Run, intents map[string]Intent, p planRecord) runRecord {
	r := runRecord{Run: cloneRun(out), Intents: intents}
	if out.Operation != "check" {
		r.FixedPassword = p.FixedPassword
		r.FixedSecretID = p.FixedSecretID
	}
	return r
}

// Check uses existing stored credentials. No generated/fixed candidate is copied.
func (s *Service) Check(ctx context.Context, actor Actor, planID, requestID string, all bool, origin ...accesspolicies.Origin) (Run, error) {
	return s.submitOperation(ctx, actor, planID, requestID, false, all, "check", origin...)
}

func (s *Service) scheduleChecks() {
	s.mu.Lock()
	now := s.now().UTC()
	plans := []Plan{}
	for _, p := range s.data.Plans {
		if !p.CheckEnabled || p.NextCheck.After(now) {
			continue
		}
		busy := false
		for _, r := range s.data.Runs {
			if r.PlanID == p.ID && !terminal(r.State) {
				busy = true
				break
			}
		}
		if !busy {
			plans = append(plans, clonePlan(p.Plan))
		}
	}
	s.mu.Unlock()
	for _, p := range plans {
		request, e := newID("check-schedule-")
		if e != nil {
			return
		}
		_, e = s.submitOperation(s.ctx, p.Actor, p.ID, request, true, true, "check")
		if !errors.Is(e, ErrDenied) && !errors.Is(e, ErrCapacity) {
			continue
		}
		_ = s.mutate(func(d *state) error {
			current, ok := d.Plans[p.ID]
			if !ok || current.Revision != p.Revision {
				return nil
			}
			current.CheckEnabled = false
			current.NextCheck = time.Time{}
			current.CheckErrorCode = "denied"
			if errors.Is(e, ErrCapacity) {
				current.CheckErrorCode = "capacity"
			}
			current.Revision++
			current.UpdatedAt = s.now().UTC()
			d.Plans[p.ID] = current
			if len(d.Audit) < MaxAudit {
				d.Audit = append(d.Audit, Audit{At: s.now().UTC(), Actor: p.Actor, Action: "check_" + current.CheckErrorCode + "_paused", PlanID: p.ID, Revision: current.Revision})
			}
			return nil
		})
	}
}
