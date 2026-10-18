package monitoralerts

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sort"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
)

func instanceKey(rule, asset string) string { return rule + "/" + asset }
func retire(d *state, rule, reason string, now time.Time) {
	for key, v := range d.Instances {
		if v.RuleID != rule {
			continue
		}
		retireInstance(d, v, reason, now)
		delete(d.Instances, key)
	}
}
func retireInstance(d *state, v instance, reason string, now time.Time) {
	if v.AlertID == "" {
		return
	}
	a := d.Alerts[v.AlertID]
	a.State = "retired"
	a.Reason = reason
	a.EndedAt = now
	a.Revision++
	d.Alerts[a.ID] = a
}
func (s *Service) SetRunner(r Runner) { s.mu.Lock(); defer s.mu.Unlock(); s.runner = r }
func (s *Service) Start(owner context.Context) {
	s.mu.Lock()
	if s.started || s.closed {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.start = s.now().UTC()
	stop := context.AfterFunc(owner, s.cancel)
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		defer stop()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			_ = s.Tick()
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
	s.mu.Unlock()
	s.wg.Wait()
	s.op.Lock()
	s.op.Unlock()
}
func (s *Service) Health() Health {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.health
	h.Rules = len(s.data.Rules)
	for _, v := range s.data.Instances {
		if v.AlertID != "" {
			h.Firing++
		} else if v.Count > 0 {
			h.Pending++
		}
	}
	return h
}
func (s *Service) Tick() (err error) {
	s.mu.Lock()
	r := s.runner
	closed := s.closed
	hasRules := len(s.data.Rules) > 0
	s.mu.Unlock()
	if closed || s.ctx.Err() != nil {
		return ErrClosed
	}
	if !hasRules {
		return nil
	}
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.health.LastEvaluation = s.now().UTC()
		s.health.ErrorCode = ""
		if err != nil {
			switch {
			case errors.Is(err, ErrDenied):
				s.health.ErrorCode = "denied"
			case errors.Is(err, ErrCapacity):
				s.health.ErrorCode = "capacity"
			case errors.Is(err, ErrInvalid):
				s.health.ErrorCode = "invalid_sample"
			default:
				s.health.ErrorCode = "unavailable"
			}
		}
	}()
	if r.Sources == nil || r.Authorized == nil {
		return ErrDenied
	}
	release := func() {}
	if r.Acquire != nil {
		var e error
		release, e = r.Acquire(s.ctx)
		if e != nil {
			return e
		}
		defer release()
	}
	if !s.op.TryLock() {
		return nil
	}
	defer s.op.Unlock()
	if s.ctx.Err() != nil {
		return ErrClosed
	}
	sources, e := r.Sources(s.ctx)
	if e != nil {
		return e
	}
	now := s.now().UTC()
	sourceIDs := map[string]bool{}
	for _, v := range sources {
		if !idPattern.MatchString(v.AssetID) || !textOK(v.AssetName, 480) || !hashPattern.MatchString(v.Binding) || len(v.Nodes) > 64 || !slices.Contains([]string{"online", "offline", "unknown"}, v.State) || v.At.After(now.Add(2*time.Second)) || len(v.Values) > 6 || sourceIDs[v.AssetID] {
			return ErrInvalid
		}
		sourceIDs[v.AssetID] = true
		for k, n := range v.Values {
			if !slices.Contains(Metrics[:6], k) || !finite(n) || n < 0 || n > 1e15 || len(k) >= 8 && k[len(k)-8:] == "_percent" && n > 100 {
				return ErrInvalid
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	next := clone(s.data)
	prune(&next, now)
	seen := map[string]time.Time{}
	first := map[string]time.Time{}
	wanted := map[string]bool{}
	tracking := map[string]bool{}
	for _, v := range next.Instances {
		tracking[v.RuleID] = true
	}
	pairs := 0
	capacity := false
	keys := make([]string, 0, len(next.Rules))
	for id := range next.Rules {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	for _, id := range keys {
		rule := next.Rules[id]
		if !rule.Enabled || !r.Authorized(s.ctx, rule.Owner) {
			if rule.Enabled {
				rule.LastError = "permission_changed"
			} else {
				rule.LastError = ""
			}
			next.Rules[id] = rule
			retire(&next, id, func() string {
				if rule.Enabled {
					return "authority_revoked"
				}
				return "rule_disabled"
			}(), now)
			continue
		}
		rule.LastError = ""
		next.Rules[id] = rule
		for _, source := range sources {
			if !matches(rule.Scope, source) {
				continue
			}
			pairs++
			if pairs > MaxInstances {
				return ErrCapacity
			}
			// Normal, untracked samples need no per-rule maps or allocations.
			// The source watermark is shared by all rules for this evaluation.
			if rule.Metric != "no_data" && !tracking[id] {
				n, _, available := s.reading(rule, source, time.Time{}, now)
				if !available || n < rule.Threshold {
					at := s.seen[source.Binding]
					if source.At.After(at) {
						at = source.At
					}
					seen[source.Binding] = at
					continue
				}
			}
			key := instanceKey(id, source.AssetID)
			wanted[key] = true
			v, exists := next.Instances[key]
			previousAt := v.LastSample
			changed := exists && (v.Binding != source.Binding || v.Definition != rule.Definition)
			if changed {
				retireInstance(&next, v, "target_changed", now)
				delete(next.Instances, key)
				v = instance{}
				exists = false
			}
			if !exists {
				v = instance{RuleID: id, AssetID: source.AssetID, Binding: source.Binding, Definition: rule.Definition}
			}
			observationKey := source.Binding
			if rule.Metric == "no_data" {
				observationKey += "/no_data"
			}
			firstKey := key + "/" + source.Binding
			firstAt, ok := s.firstSeen[firstKey]
			if changed {
				ok = false
			}
			if !ok {
				firstAt = now
			}
			if rule.Metric == "no_data" {
				first[firstKey] = firstAt
			}
			at := s.seen[observationKey]
			if changed {
				at = previousAt
			}
			if v.LastSample.After(at) {
				at = v.LastSample
			}
			value, token, available := s.reading(rule, source, firstAt, now)
			if token.After(at) {
				seen[observationKey] = token
			} else {
				seen[observationKey] = at
			}
			if !available {
				if v.AlertID == "" {
					delete(next.Instances, key)
				} else {
					v.Count = 0
					v.RecoverCount = 0
					v.RecoverSince = time.Time{}
					next.Instances[key] = v
				}
				continue
			}
			if token.After(at) {
				if !v.LastSample.IsZero() && token.Sub(v.LastSample) > time.Duration(rule.MaxAgeSeconds)*time.Second {
					v.Count = 0
					v.Since = time.Time{}
					v.RecoverCount = 0
					v.RecoverSince = time.Time{}
				}
				v.LastSample = token
				if v.AlertID == "" {
					if value >= rule.Threshold {
						if v.Count == 0 {
							v.Since = token
						}
						v.Count = min(v.Count+1, 30)
						if v.Count >= rule.ForSamples && token.Sub(v.Since) >= time.Duration(rule.ForSeconds)*time.Second {
							if len(next.Alerts) >= MaxAlerts {
								// Evict oldest finished history first. Active episodes
								// are never removed to make room for another alert.
								oldest := ""
								for aid, a := range next.Alerts {
									if a.State != "firing" && (oldest == "" || a.EndedAt.Before(next.Alerts[oldest].EndedAt)) {
										oldest = aid
									}
								}
								if oldest != "" {
									delete(next.Alerts, oldest)
								} else {
									capacity = true
									rule.LastError = "capacity"
									next.Rules[id] = rule
									next.Instances[key] = v
									continue
								}
							}
							aid := newID("monitor-alert-")
							if aid == "" {
								return ErrInvalid
							}
							n := value
							a := Alert{ID: aid, Revision: 1, RuleID: id, RuleRevision: rule.Definition, RuleName: rule.Name, AssetID: source.AssetID, AssetName: eventfeed.MetadataText(source.AssetName, 480), Metric: rule.Metric, State: "firing", Value: &n, Threshold: rule.Threshold, RecoveryThreshold: rule.RecoveryThreshold, StartedAt: now, LastObservedAt: token}
							next.Alerts[aid] = a
							v.AlertID = aid
							v.Count = 0
							if rule.MutedUntil.After(now) {
								v.Suppressed = true
							} else {
								emit(&next, a, "monitoring_firing", now)
								v.LastEvent = now
							}
						}
						next.Instances[key] = v
					} else {
						delete(next.Instances, key)
					}
				} else {
					a := next.Alerts[v.AlertID]
					n := value
					a.Value = &n
					a.LastObservedAt = token
					a.Revision++
					next.Alerts[a.ID] = a
					if value <= rule.RecoveryThreshold {
						if v.RecoverCount == 0 {
							v.RecoverSince = token
						}
						v.RecoverCount = min(v.RecoverCount+1, 30)
						if v.RecoverCount >= rule.RecoverySamples && token.Sub(v.RecoverSince) >= time.Duration(rule.RecoverySeconds)*time.Second {
							a.State = "resolved"
							a.EndedAt = now
							a.Revision++
							next.Alerts[a.ID] = a
							if !v.LastEvent.IsZero() && !rule.MutedUntil.After(now) {
								emit(&next, a, "monitoring_resolved", now)
							}
							delete(next.Instances, key)
							continue
						}
					} else {
						v.RecoverCount = 0
						v.RecoverSince = time.Time{}
					}
					next.Instances[key] = v
				}
			}
			if current, ok := next.Instances[key]; ok && current.AlertID != "" {
				a := next.Alerts[current.AlertID]
				if rule.MutedUntil.After(now) {
					current.Suppressed = true
					next.Instances[key] = current
				} else if a.AcknowledgedAt.IsZero() && (current.Suppressed || rule.RepeatSeconds > 0 && now.Sub(current.LastEvent) >= time.Duration(rule.RepeatSeconds)*time.Second) {
					emit(&next, a, "monitoring_firing", now)
					current.LastEvent = now
					current.Suppressed = false
					next.Instances[key] = current
				}
			}
		}
	}
	for key, v := range next.Instances {
		if !wanted[key] {
			retireInstance(&next, v, "target_unavailable", now)
			delete(next.Instances, key)
		}
	}
	if len(next.Events) > MaxEvents {
		next.Events = slices.Clone(next.Events[len(next.Events)-MaxEvents:])
	}
	if !reflect.DeepEqual(next, s.data) {
		if e := s.persist(next); e != nil {
			return e
		}
		s.data = next
	}
	s.seen = seen
	s.firstSeen = first
	if capacity {
		return ErrCapacity
	}
	return nil
}
func (s *Service) reading(rule Rule, source Source, first, now time.Time) (float64, time.Time, bool) {
	fresh := !source.At.IsZero() && !source.At.After(now) && now.Sub(source.At) <= time.Duration(rule.MaxAgeSeconds)*time.Second
	if rule.Metric == "no_data" {
		grace := s.start
		if rule.UpdatedAt.After(grace) {
			grace = rule.UpdatedAt
		}
		if first.After(grace) {
			grace = first
		}
		if !fresh && now.Sub(grace) < time.Duration(rule.MaxAgeSeconds)*time.Second {
			return 0, time.Time{}, false
		}
		if fresh {
			return 0, source.At, true
		}
		return 1, now.Truncate(time.Second), true
	}
	if !fresh || source.State == "unknown" {
		return 0, time.Time{}, false
	}
	if rule.Metric == "offline" {
		if source.State == "offline" {
			return 1, source.At, true
		}
		return 0, source.At, true
	}
	if source.State != "online" {
		return 0, time.Time{}, false
	}
	value, ok := source.Values[rule.Metric]
	return value, source.At, ok
}
func emit(d *state, a Alert, state string, now time.Time) {
	prior := ""
	if len(d.Events) > 0 {
		prior = d.Events[len(d.Events)-1].ID
	}
	e := Event{AlertID: a.ID, AssetID: a.AssetID, AssetName: a.AssetName, State: state, At: now}
	e.ID = eventfeed.Digest([]any{a.ID, state, now, prior})
	d.Events = append(d.Events, e)
}
