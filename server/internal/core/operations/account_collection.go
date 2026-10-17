package operations

import (
	"github.com/neko233-com/jumpserver233/server/internal/core/accountdiscovery"
	"time"
)

func cloneDiscovery(o *accountdiscovery.Operation) *accountdiscovery.Operation {
	if o == nil {
		return nil
	}
	c := o.Clone()
	return &c
}

func (s *Service) CreateDiscoveryCollector(ownerID, owner string, in PlanInput, op accountdiscovery.Operation, parent, account, name string) (Plan, error) {
	if op.Validate() != nil || op.PlanID != "" || parent == "" || account == "" || len(in.AssetIDs) != 1 || in.Kind != "interval" || in.IntervalSeconds < 60 || in.IntervalSeconds > 86400 || in.TemplateID != "" {
		return Plan{}, ErrInvalid
	}
	check := op.Clone()
	check.PlanID = "plan-00000000000000000000000000000000"
	check.Account = account
	check.ParentAssetID = parent
	if check.Validate() != nil {
		return Plan{}, ErrInvalid
	}
	in.Command = op.Command()
	in.TimeoutSeconds = 180
	prepared, revision, e := s.Prepare(ownerID, in)
	if e != nil {
		return Plan{}, e
	}
	return s.createPlan(ownerID, owner, prepared, revision, nil, &op, parent, account, name)
}

// DiscoveryAllowed binds a dispatch or live job to its current enabled plan.
// A disabled plan cannot be revived by a pending review or an old run claim.
func (s *Service) DiscoveryAllowed(owner, asset string, op *accountdiscovery.Operation) bool {
	if op == nil || op.PlanID == "" || op.Sequence == 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.data.Plans[op.PlanID]
	if !ok || !p.Enabled || p.OwnerID != owner || p.Discovery == nil || len(p.AssetIDs) != 1 || p.AssetIDs[0] != asset || p.Discovery.Target != op.Target || p.Discovery.ParentAssetID != op.ParentAssetID || p.CollectionAccount != op.Account {
		return false
	}
	for _, r := range s.data.Runs {
		if r.PlanID == p.ID && r.CollectionSequence == op.Sequence && !r.Cancelled && len(r.Items) == 1 && r.Items[0].AssetID == asset {
			return r.State == "running" || r.State == "waiting_review"
		}
	}
	return false
}

func (s *Service) UpdateDiscoveryCollector(id string, revision int, enabled bool, interval int) (Plan, error) {
	if interval < 60 || interval > 86400 || revision < 1 {
		return Plan{}, ErrInvalid
	}
	var result Plan
	var jobsToCancel []string
	e := s.mutate(func(next *state) error {
		p, ok := next.Plans[id]
		if !ok || p.Discovery == nil {
			return ErrNotFound
		}
		if p.ConfigRevision != revision {
			return ErrConflict
		}
		if p.Enabled == enabled && p.IntervalSeconds == interval {
			result = p
			return nil
		}
		if p.ConfigRevision >= 1<<53-1 {
			return ErrBusy
		}
		if enabled {
			for otherID, v := range next.Plans {
				if otherID != id && v.Discovery != nil && v.Enabled && v.OwnerID == p.OwnerID && v.Discovery.ParentAssetID == p.Discovery.ParentAssetID {
					return ErrConflict
				}
			}
		}
		wasEnabled := p.Enabled
		p.Enabled = enabled
		p.IntervalSeconds = interval
		p.ConfigRevision++
		p.ErrorCode = ""
		if enabled {
			p.NextRun = s.now().UTC().Add(time.Duration(interval) * time.Second)
			if !wasEnabled {
				p.NextRun = s.now().UTC()
			}
		}
		next.Plans[id] = p
		result = p
		if !enabled {
			for runID, r := range next.Runs {
				if r.PlanID != id || r.Cancelled || r.State != "running" && r.State != "waiting_review" {
					continue
				}
				r.Cancelled = true
				for i, item := range r.Items {
					if item.JobID != "" {
						jobsToCancel = append(jobsToCancel, item.JobID)
					}
					if item.JobID == "" && item.State != "dispatching" {
						r.Items[i].State = "cancelled"
					}
				}
				r.State = runState(r)
				next.Runs[runID] = r
			}
		}
		return nil
	})
	if e != nil {
		return Plan{}, e
	}
	for _, id := range jobsToCancel {
		_ = s.jobs.Cancel(id)
	}
	result.AssetIDs = append([]string(nil), result.AssetIDs...)
	result.Discovery = cloneDiscovery(result.Discovery)
	return result, nil
}

func (s *Service) pauseDeniedDiscovery(id string) {
	_ = s.mutate(func(next *state) error {
		p, ok := next.Plans[id]
		if !ok || p.Discovery == nil || !p.Enabled {
			return errNoChange
		}
		p.Enabled = false
		p.ErrorCode = "access_denied"
		if p.ConfigRevision < 1<<53-1 {
			p.ConfigRevision++
		}
		next.Plans[id] = p
		return nil
	})
}
