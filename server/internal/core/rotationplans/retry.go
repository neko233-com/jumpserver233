package rotationplans

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
)

func canonicalRetry(in RetryInput) (RetryInput, error) {
	if !IDPattern.MatchString(in.RequestID) || in.PlanRevision < 1 || in.PlanRevision > 1<<53-1 || len(in.ItemIDs) > MaxTargets {
		return in, ErrInvalid
	}
	in.ItemIDs = slices.Clone(in.ItemIDs)
	slices.Sort(in.ItemIDs)
	for i, id := range in.ItemIDs {
		if !IDPattern.MatchString(id) || i > 0 && id == in.ItemIDs[i-1] {
			return in, ErrInvalid
		}
	}
	return in, nil
}

func retryReplay(r runRecord, parent string, in RetryInput) error {
	if r.ParentRunID != parent || r.PlanRevision != in.PlanRevision || !slices.Equal(r.RetryRequested, in.ItemIDs) {
		return ErrConflict
	}
	return nil
}

// Keep complete lineage while any member still needs its retention window.
func pruneRetryRuns(d *state, now time.Time) {
	keep := map[string]bool{}
	queue := []string{}
	for id, r := range d.Runs {
		if !terminal(r.State) || r.FinishedAt.IsZero() || !r.FinishedAt.Before(now.Add(-90*24*time.Hour)) {
			keep[id] = true
			queue = append(queue, id)
		}
	}
	for len(queue) > 0 {
		id := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		r := d.Runs[id]
		neighbors := []string{r.ParentRunID}
		for _, item := range r.Items {
			neighbors = append(neighbors, item.RetryRunID)
		}
		for _, next := range neighbors {
			if _, exists := d.Runs[next]; exists && !keep[next] {
				keep[next] = true
				queue = append(queue, next)
			}
		}
	}
	for id := range d.Runs {
		if !keep[id] {
			delete(d.Runs, id)
		}
	}
}

func validateRetries(d state) error {
	for _, r := range d.Runs {
		if r.ParentRunID == "" {
			if r.RetryAll || len(r.RetryItemIDs) != 0 || len(r.RetryRequested) != 0 {
				return ErrInvalid
			}
		} else {
			if !IDPattern.MatchString(r.ParentRunID) || r.ParentRunID == r.ID || r.Scheduled || len(r.RetryItemIDs) != len(r.Items) || r.RetryAll != (len(r.RetryRequested) == 0) {
				return ErrInvalid
			}
			parent, ok := d.Runs[r.ParentRunID]
			if !ok || parent.PlanID != r.PlanID || !terminal(parent.State) || parent.CreatedAt.After(r.CreatedAt) {
				return ErrInvalid
			}
			input, e := canonicalRetry(RetryInput{RequestID: r.RequestID, PlanRevision: r.PlanRevision, ItemIDs: r.RetryRequested})
			if e != nil || !slices.Equal(input.ItemIDs, r.RetryRequested) || !slices.IsSorted(r.RetryItemIDs) {
				return ErrInvalid
			}
			previous := map[string]Item{}
			for _, item := range parent.Items {
				previous[item.ID] = item
			}
			seen := map[string]bool{}
			for _, item := range r.Items {
				old, exists := previous[item.SourceItemID]
				if !exists || seen[item.SourceItemID] || old.RetryRunID != r.ID || !RetryableItem(old.State) || old.AccountID != item.AccountID || old.AssetID != item.AssetID || old.Username != item.Username || old.CredentialType != item.CredentialType || !slices.Contains(r.RetryItemIDs, item.SourceItemID) {
					return ErrInvalid
				}
				seen[item.SourceItemID] = true
			}
			for _, id := range r.RetryRequested {
				if !seen[id] {
					return ErrInvalid
				}
			}
			ancestry := map[string]bool{r.ID: true}
			for id := r.ParentRunID; id != ""; id = d.Runs[id].ParentRunID {
				if ancestry[id] {
					return ErrInvalid
				}
				ancestry[id] = true
			}
		}
		for _, item := range r.Items {
			if r.ParentRunID == "" && item.SourceItemID != "" {
				return ErrInvalid
			}
			if item.RetryRunID != "" {
				child, ok := d.Runs[item.RetryRunID]
				if !IDPattern.MatchString(item.RetryRunID) || !ok || child.ParentRunID != r.ID || !slices.Contains(child.RetryItemIDs, item.ID) {
					return ErrInvalid
				}
			}
		}
	}
	for _, a := range d.Audit {
		if a.ParentRunID != "" && !IDPattern.MatchString(a.ParentRunID) {
			return ErrInvalid
		}
	}
	return nil
}

// retrySelection expands a selected alias to its whole historical operation.
// A source item can be consumed once; subsequent attempts retry the child run.
func retrySelection(parent runRecord, in RetryInput) (map[string]Item, error) {
	groups := map[string]bool{}
	byID := map[string]Item{}
	for _, item := range parent.Items {
		byID[item.ID] = item
	}
	ids := in.ItemIDs
	if len(ids) == 0 {
		for _, item := range parent.Items {
			if RetryableItem(item.State) && item.RetryRunID == "" {
				ids = append(ids, item.ID)
			}
		}
	}
	for _, id := range ids {
		item, ok := byID[id]
		if !ok || !RetryableItem(item.State) || item.RetryRunID != "" {
			return nil, ErrConflict
		}
		leader := item.ID
		if item.LinkedTo != "" {
			leader = item.LinkedTo
		}
		groups[leader] = true
	}
	out := map[string]Item{}
	for _, item := range parent.Items {
		leader := item.ID
		if item.LinkedTo != "" {
			leader = item.LinkedTo
		}
		if !groups[leader] {
			continue
		}
		if !RetryableItem(item.State) || item.RetryRunID != "" {
			return nil, ErrConflict
		}
		out[item.AccountID] = item
	}
	if len(out) == 0 {
		return nil, ErrConflict
	}
	return out, nil
}

func (s *Service) Retry(ctx context.Context, actor Actor, parentID string, input RetryInput, all bool, origin ...accesspolicies.Origin) (Run, error) {
	in, err := canonicalRetry(input)
	if err != nil || !ValidActor(actor) || !IDPattern.MatchString(parentID) || len(origin) > 1 {
		return Run{}, ErrInvalid
	}
	if err = ctx.Err(); err != nil {
		return Run{}, err
	}
	runner := s.runnerSnapshot()
	if runner.Prepare == nil || runner.Execute == nil || runner.Inspect == nil || runner.Authorize == nil {
		return Run{}, ErrBusy
	}
	if err = runner.Authorize(actor); err != nil {
		return Run{}, err
	}
	s.mu.Lock()
	for _, r := range s.data.Runs {
		if r.Actor.ID == actor.ID && r.RequestID == in.RequestID {
			s.mu.Unlock()
			if err = retryReplay(r, parentID, in); err != nil {
				return Run{}, err
			}
			if err = runner.authorizeMode(actor, r.PasswordMode); err != nil {
				return Run{}, err
			}
			targets := make([]Selection, 0, len(r.Items))
			for _, item := range r.Items {
				targets = append(targets, Selection{AccountID: item.AccountID, CollectorID: item.CollectorID})
			}
			if err = runner.authorizeTargets(actor, targets); err != nil {
				return Run{}, err
			}
			return cloneRun(r.Run), nil
		}
	}
	parent, ok := s.data.Runs[parentID]
	if !ok || parent.Actor.ID != actor.ID && !all {
		s.mu.Unlock()
		return Run{}, ErrNotFound
	}
	parent.Run = cloneRun(parent.Run)
	p, ok := s.data.Plans[parent.PlanID]
	p.Plan = clonePlan(p.Plan)
	s.mu.Unlock()
	if !ok || p.Actor.ID != actor.ID && !all {
		return Run{}, ErrNotFound
	}
	if !terminal(parent.State) {
		return Run{}, ErrBusy
	}
	if p.Revision != in.PlanRevision {
		return Run{}, ErrConflict
	}
	if err = runner.authorizeMode(actor, p.PasswordMode); err != nil {
		return Run{}, err
	}
	selected, err := retrySelection(parent, in)
	if err != nil {
		return Run{}, err
	}

	// Inspect the original durable operation before creating a fresh intent.
	// No secret is needed for inspection, including a scrubbed fixed-value run.
	inspected := map[string]bool{}
	for _, item := range parent.Items {
		if _, chosen := selected[item.AccountID]; !chosen {
			continue
		}
		leader := item.ID
		if item.LinkedTo != "" {
			leader = item.LinkedTo
		}
		if inspected[leader] {
			continue
		}
		inspected[leader] = true
		if intent, exists := parent.Intents[leader]; exists {
			out, e := runner.Inspect(ctx, intent)
			if e != nil {
				return Run{}, e
			}
			switch out.State {
			case "not_started", "failed", "denied", "cancelled":
			case "succeeded", "changed":
				return Run{}, ErrConflict
			default:
				return Run{}, ErrBusy
			}
		}
	}
	selections, refs := []Selection{}, map[string]Ref{}
	for i, target := range p.Targets {
		if previous, chosen := selected[target.AccountID]; chosen {
			ref := p.Refs[i]
			if ref.AssetID != previous.AssetID || ref.Username != previous.Username || ref.CredentialType != previous.CredentialType {
				return Run{}, ErrConflict
			}
			selections = append(selections, target)
			refs[target.AccountID] = ref
		}
	}
	if len(selections) != len(selected) {
		return Run{}, ErrConflict
	}
	if err = runner.authorizeTargets(actor, selections); err != nil {
		return Run{}, err
	}
	prepared := map[string]Prepared{}
	for _, target := range selections {
		rows, e := runner.Prepare(ctx, actor, []Selection{target})
		if errors.Is(e, ErrDenied) {
			return Run{}, e
		}
		if e == nil && len(rows) == 1 && validatePrepared(rows[0]) == nil && rows[0].AccountID == target.AccountID {
			prepared[target.AccountID] = rows[0]
		}
	}
	for leader := range inspected {
		if previous, exists := parent.Intents[leader]; exists {
			if fresh, ok := prepared[previous.Target.AccountID]; ok && (fresh.Version != previous.Target.Version || fresh.Revision != previous.Target.Revision) {
				return Run{}, ErrConflict
			}
		}
	}
	if err = ctx.Err(); err != nil {
		return Run{}, err
	}
	if err = runner.authorizeMode(actor, p.PasswordMode); err != nil {
		return Run{}, err
	}
	id, err := newID("rotation-run-")
	if err != nil {
		return Run{}, err
	}
	now := s.now().UTC()
	out := Run{ID: id, ParentRunID: parentID, RetryAll: len(in.ItemIDs) == 0, PlanID: p.ID, PlanRevision: p.Revision, Name: p.Name, Actor: actor, RequestID: in.RequestID, PasswordMode: p.PasswordMode, PasswordPolicy: p.PasswordPolicy, AccessOrigin: accesspolicies.Origin{Method: "credential_rotation"}, CreatedAt: now, Items: []Item{}}
	if len(origin) == 1 {
		out.AccessOrigin = origin[0]
	}
	intents, groups := map[string]Intent{}, map[string]string{}
	for _, selection := range selections {
		itemID, e := newID("rotation-item-")
		if e != nil {
			return Run{}, e
		}
		old := selected[selection.AccountID]
		item := Item{ID: itemID, SourceItemID: old.ID, Ref: refs[selection.AccountID], State: "changed", ErrorCode: "source_changed", FinishedAt: now}
		if v, exists := prepared[selection.AccountID]; exists && v.Binding == p.Bindings[selection.AccountID] {
			item.Ref, item.BeforeRevision, item.State, item.ErrorCode, item.FinishedAt = v.Ref, v.Revision, "queued", "", time.Time{}
			if leader := groups[v.Group]; leader != "" {
				item.LinkedTo, item.State = leader, "linked"
			} else {
				groups[v.Group] = itemID
				intent := Intent{RequestID: itemID, Actor: actor, Target: v, Origin: out.AccessOrigin}
				if v.CredentialType == "password" {
					intent.PasswordPolicy = out.PasswordPolicy
					if p.PasswordMode == "fixed" {
						intent.FixedSecretID = p.FixedSecretID
					}
				}
				intents[itemID] = intent
			}
		}
		out.Items = append(out.Items, item)
		out.RetryItemIDs = append(out.RetryItemIDs, old.ID)
	}
	slices.Sort(out.RetryItemIDs)
	linkResults(&out)
	out.State = runState(out)
	if terminal(out.State) {
		out.FinishedAt = now
	}
	err = s.mutate(func(d *state) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if e := runner.authorizeMode(actor, p.PasswordMode); e != nil {
			return e
		}
		if e := runner.authorizeTargets(actor, selections); e != nil {
			return e
		}
		for _, r := range d.Runs {
			if r.Actor.ID == actor.ID && r.RequestID == in.RequestID {
				if e := retryReplay(r, parentID, in); e != nil {
					return e
				}
				out = cloneRun(r.Run)
				return nil
			}
			if r.PlanID == p.ID && !terminal(r.State) {
				return ErrBusy
			}
		}
		current, exists := d.Plans[p.ID]
		if !exists || current.Revision != p.Revision {
			return ErrConflict
		}
		source, exists := d.Runs[parentID]
		if !exists || !terminal(source.State) {
			return ErrConflict
		}
		for _, item := range source.Items {
			if old, chosen := selected[item.AccountID]; chosen && (old.ID != item.ID || old.State != item.State || item.RetryRunID != "") {
				return ErrConflict
			}
		}
		if len(d.Runs) >= MaxRuns || len(d.Audit) >= MaxAudit {
			return ErrCapacity
		}
		for i := range source.Items {
			if _, chosen := selected[source.Items[i].AccountID]; chosen {
				source.Items[i].RetryRunID = id
			}
		}
		d.Runs[parentID] = source
		d.Runs[id] = runRecord{Run: cloneRun(out), RetryRequested: slices.Clone(in.ItemIDs), Intents: intents, FixedPassword: p.FixedPassword, FixedSecretID: p.FixedSecretID}
		current.LastRunID = id
		d.Plans[p.ID] = current
		d.Audit = append(d.Audit, Audit{At: now, Actor: actor, Action: "retried", PlanID: p.ID, RunID: id, ParentRunID: parentID, Revision: p.Revision, RequestID: in.RequestID, Origin: out.AccessOrigin})
		return nil
	})
	return out, err
}
