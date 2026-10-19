package assetdiscovery

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
)

func sourceFrom(v state, id string) (sourceRecord, error) {
	r, ok := v.Sources[id]
	if !ok || r.Deleted {
		return sourceRecord{}, ErrNotFound
	}
	return r, nil
}
func (s *Store) source(id string) (sourceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.refreshLocked(); e != nil {
		return sourceRecord{}, e
	}
	r, e := sourceFrom(s.data, id)
	return copyJSON(r), e
}
func (s *Store) Source(id string) (Source, error) {
	r, e := s.source(id)
	if e != nil {
		return Source{}, e
	}
	return publicSource(r), nil
}
func (s *Store) DeleteSource(id string, revision int, actor Actor, now time.Time) error {
	if !validActor(actor) || !validID(id, "source") || revision < 1 {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.refreshLocked(); e != nil {
		return e
	}
	old, ok := s.data.Sources[id]
	if !ok {
		return ErrNotFound
	}
	if old.Deleted {
		if revision == old.Input.Revision-1 {
			return nil
		}
		return ErrConflict
	}
	if revision != old.Input.Revision {
		return ErrConflict
	}
	next := copyJSON(s.data)
	old.Deleted = true
	old.Input.Enabled = false
	old.Input.Revision++
	old.UpdatedAt = now
	next.Sources[id] = old
	for key, p := range next.Policies {
		if p.SourceID == id {
			p.Deleted = true
			p.Enabled = false
			p.NextRunAt = time.Time{}
			p.Revision++
			p.UpdatedAt = now
			next.Policies[key] = p
		}
	}
	for key, f := range next.Findings {
		if f.SourceID == id {
			delete(next.Findings, key)
		}
	}
	for key, p := range next.Previews {
		if p.Input.SourceID == id {
			delete(next.Previews, key)
		}
	}
	audit(&next, Audit{At: now, Actor: actor, Action: "source_deleted", SourceID: id, Revision: old.Input.Revision})
	return s.saveLocked(next)
}
func normalizePolicy(in PolicyInput, now time.Time) (PolicyInput, error) {
	if in.OverwriteManualChanges && !in.UpdateExisting {
		return in, ErrInvalid
	}
	in.RequestID = ""
	in.Name = strings.TrimSpace(in.Name)
	in.NamePrefix = strings.TrimSpace(in.NamePrefix)
	in.Group = strings.TrimSpace(in.Group)
	if in.Name == "" || !validText(in.Name, 120) || !validText(in.NamePrefix, 40) || !validText(in.Group, 120) || !validText(in.NodeID, 128) || !validID(in.SourceID, "source") || in.SourceRevision < 1 || in.Revision < 0 || in.Revision > 1000000000 || len(in.MatchCIDRs) > 128 {
		return in, ErrInvalid
	}
	if in.MissingAction == "" {
		in.MissingAction = "retain"
	}
	if !slices.Contains([]string{"retain", "disable"}, in.MissingAction) {
		return in, ErrInvalid
	}
	if in.MissingThreshold == 0 {
		in.MissingThreshold = 2
	}
	if in.MissingThreshold < 1 || in.MissingThreshold > 10 {
		return in, ErrInvalid
	}
	if in.MatchCIDRs == nil {
		in.MatchCIDRs = []string{}
	}
	for i, text := range in.MatchCIDRs {
		prefix, e := netip.ParsePrefix(strings.TrimSpace(text))
		if e != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
			return in, ErrInvalid
		}
		in.MatchCIDRs[i] = prefix.Masked().String()
	}
	slices.Sort(in.MatchCIDRs)
	in.MatchCIDRs = slices.Compact(in.MatchCIDRs)
	if in.Schedule != nil {
		if !slices.Contains([]string{"once", "interval", "cron"}, in.Schedule.Kind) {
			return in, ErrInvalid
		}
		canonical, e := operations.CanonicalSchedule(*in.Schedule)
		if e != nil {
			return in, ErrInvalid
		}
		in.Schedule = &canonical
	}
	return in, nil
}
func (s *Store) SavePolicy(id string, in PolicyInput, actor Actor, now time.Time, origins ...accesspolicies.Origin) (Policy, error) {
	now = now.UTC()
	if !validActor(actor) {
		return Policy{}, ErrInvalid
	}
	create := id == ""
	if create {
		if !requestPattern.MatchString(in.RequestID) {
			return Policy{}, ErrInvalid
		}
		id = s.stableID("policy", actor.ID, in.RequestID)
	} else if !validID(id, "policy") {
		return Policy{}, ErrInvalid
	}
	normalized, e := normalizePolicy(copyJSON(in), now)
	if e != nil {
		return Policy{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e = s.refreshLocked(); e != nil {
		return Policy{}, e
	}
	source, sourceError := sourceFrom(s.data, in.SourceID)
	if sourceError != nil {
		return Policy{}, sourceError
	}
	if source.Input.Revision != in.SourceRevision {
		return Policy{}, ErrConflict
	}
	if _, e = sourceFrom(s.data, in.SourceID); e != nil {
		return Policy{}, e
	}
	old, exists := s.data.Policies[id]
	if exists && old.Deleted {
		return Policy{}, ErrNotFound
	}
	if !create && !exists {
		return Policy{}, ErrNotFound
	}
	if exists {
		candidate := normalized
		candidate.Revision = old.Revision
		a, _ := json.Marshal(candidate)
		b, _ := json.Marshal(old.PolicyInput)
		if in.Revision <= old.Revision && bytes.Equal(a, b) {
			return copyJSON(old), nil
		}
		if in.Revision != old.Revision || in.SourceID != old.SourceID {
			return Policy{}, ErrConflict
		}
	} else if in.Revision != 0 {
		return Policy{}, ErrConflict
	}
	if !exists && activePolicies(s.data) >= MaxPolicies {
		return Policy{}, ErrCapacity
	}
	normalized.Revision = old.Revision + 1
	p := Policy{ID: id, PolicyInput: normalized, Owner: actor, CreatedAt: now, UpdatedAt: now}
	if len(origins) == 1 {
		p.Origin = origins[0]
	}
	p.Origin.Method = "asset_discovery"
	if exists {
		p.CreatedAt = old.CreatedAt
		p.SkippedTriggers = old.SkippedTriggers
	}
	previousSchedule, _ := json.Marshal(old.Schedule)
	currentSchedule, _ := json.Marshal(p.Schedule)
	sameSchedule := exists && bytes.Equal(previousSchedule, currentSchedule)
	if sameSchedule {
		p.CalendarWatermark = old.CalendarWatermark
	}
	if p.Enabled {
		switch {
		case sameSchedule && old.Enabled:
			p.NextRunAt = old.NextRunAt
		case sameSchedule && p.Schedule != nil && p.Schedule.Kind == "once" && !p.Schedule.RunAt.After(now):
			// Editing or re-enabling an exhausted one-time schedule is not a replay.
		case sameSchedule && p.Schedule != nil && !p.Schedule.EndAt.IsZero() && !p.Schedule.EndAt.After(now):
			// An ended interval/cron remains exhausted after a metadata edit.
		case sameSchedule && p.Schedule != nil && p.Schedule.Kind == "cron" && p.CalendarWatermark != "":
			p.NextRunAt, p.CalendarWatermark, e = operations.AdvanceSchedule(*p.Schedule, now, time.Time{}, p.CalendarWatermark)
		default:
			p.NextRunAt, e = nextOccurrence(p.Schedule, now)
		}
		if e != nil {
			return Policy{}, e
		}
	}
	next := copyJSON(s.data)
	if !exists && len(next.Policies) >= 512 {
		oldest := ""
		for key, entry := range next.Policies {
			if entry.Deleted && (oldest == "" || entry.UpdatedAt.Before(next.Policies[oldest].UpdatedAt)) {
				oldest = key
			}
		}
		if oldest == "" {
			return Policy{}, ErrCapacity
		}
		delete(next.Policies, oldest)
	}
	next.Policies[id] = p
	audit(&next, Audit{At: now, Actor: actor, Action: "policy_saved", SourceID: p.SourceID, PolicyID: id, Revision: p.Revision, Before: snapshot(old, exists), After: snapshot(p, true)})
	if e = s.saveLocked(next); e != nil {
		return Policy{}, e
	}
	return copyJSON(p), nil
}
func (s *Store) Policies() ([]Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.refreshLocked(); e != nil {
		return nil, e
	}
	out := []Policy{}
	for _, p := range s.data.Policies {
		if p.Deleted {
			continue
		}
		out = append(out, copyJSON(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (s *Store) Policy(id string) (Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.refreshLocked(); e != nil {
		return Policy{}, e
	}
	p, ok := s.data.Policies[id]
	if !ok || p.Deleted {
		return Policy{}, ErrNotFound
	}
	return copyJSON(p), nil
}
func (s *Store) DeletePolicy(id string, revision int, actor Actor, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validActor(actor) || revision < 1 || !validID(id, "policy") {
		return ErrInvalid
	}
	if e := s.refreshLocked(); e != nil {
		return e
	}
	p, ok := s.data.Policies[id]
	if !ok {
		return nil
	}
	if p.Deleted {
		if revision == p.Revision-1 {
			return nil
		}
		return ErrConflict
	}
	if p.Revision != revision {
		return ErrConflict
	}
	next := copyJSON(s.data)
	p.Deleted = true
	p.Enabled = false
	p.NextRunAt = time.Time{}
	p.Revision++
	p.UpdatedAt = now
	next.Policies[id] = p
	audit(&next, Audit{At: now, Actor: actor, Action: "policy_deleted", SourceID: p.SourceID, PolicyID: id, Revision: p.Revision})
	return s.saveLocked(next)
}
func pageBounds(offset, limit int) error {
	if offset < 0 || offset > 100000 || limit < 1 || limit > 500 {
		return ErrInvalid
	}
	return nil
}
func pageSlice[T any](rows []T, offset, limit int) []T {
	if offset >= len(rows) {
		return []T{}
	}
	return rows[offset:min(len(rows), offset+limit)]
}
func (s *Store) Findings(source string, offset, limit int) ([]Finding, int, error) {
	if pageBounds(offset, limit) != nil {
		return nil, 0, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.refreshLocked(); e != nil {
		return nil, 0, e
	}
	if _, e := sourceFrom(s.data, source); e != nil {
		return nil, 0, e
	}
	out := []Finding{}
	for _, f := range s.data.Findings {
		if f.SourceID == source {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := netip.ParseAddr(out[i].Host)
		b, _ := netip.ParseAddr(out[j].Host)
		if a != b {
			return a.Compare(b) < 0
		}
		return out[i].Port < out[j].Port
	})
	return pageSlice(out, offset, limit), len(out), nil
}
func (s *Store) Runs(source string, offset, limit int) ([]Run, int, error) {
	if pageBounds(offset, limit) != nil {
		return nil, 0, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.refreshLocked(); e != nil {
		return nil, 0, e
	}
	if source != "" {
		if _, e := sourceFrom(s.data, source); e != nil {
			return nil, 0, e
		}
	}
	out := []Run{}
	for _, r := range s.data.Runs {
		if source == "" || r.SourceID == source {
			out = append(out, r.Run)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].StartedAt.Equal(out[j].StartedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].StartedAt.After(out[j].StartedAt)
	})
	return pageSlice(out, offset, limit), len(out), nil
}
func (s *Store) Run(id string) (Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.refreshLocked(); e != nil {
		return Run{}, e
	}
	r, ok := s.data.Runs[id]
	if !ok {
		return Run{}, ErrNotFound
	}
	return r.Run, nil
}
func (s *Store) Audit(offset, limit int) ([]Audit, int, error) {
	if pageBounds(offset, limit) != nil {
		return nil, 0, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.refreshLocked(); e != nil {
		return nil, 0, e
	}
	out := slices.Clone(s.data.Audit)
	slices.Reverse(out)
	return pageSlice(out, offset, limit), len(out), nil
}
func matchPolicy(p Policy, host string) bool {
	if len(p.MatchCIDRs) == 0 {
		return true
	}
	ip, e := netip.ParseAddr(host)
	if e != nil {
		return false
	}
	for _, text := range p.MatchCIDRs {
		prefix, e := netip.ParsePrefix(text)
		if e == nil && prefix.Contains(ip) {
			return true
		}
	}
	return false
}
