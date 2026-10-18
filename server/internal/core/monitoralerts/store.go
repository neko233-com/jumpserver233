package monitoralerts

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

type instance struct {
	RuleID, AssetID, Binding, AlertID          string
	Definition                                 int
	LastSample, Since, RecoverSince, LastEvent time.Time
	Count, RecoverCount                        int
	Suppressed                                 bool
}
type state struct {
	Version   int
	Rules     map[string]Rule
	Instances map[string]instance
	Alerts    map[string]Alert
	Events    []Event
	Audit     []Audit
}
type envelope struct {
	Version           int
	Nonce, Ciphertext []byte
}
type Service struct {
	mu              sync.Mutex
	op              sync.Mutex
	path            string
	docs            *storage.Documents
	aead            cipher.AEAD
	data            state
	runner          Runner
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	started, closed bool
	start           time.Time
	now             func() time.Time
	health          Health
	seen            map[string]time.Time
	firstSeen       map[string]time.Time
	saveHook        func([]byte) error
}

func Open(path string, key []byte, docs *storage.Documents) (*Service, error) {
	if len(key) != 32 {
		return nil, ErrInvalid
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{path: path, docs: docs, aead: a, ctx: ctx, cancel: cancel, now: time.Now, start: time.Now().UTC(), seen: map[string]time.Time{}, firstSeen: map[string]time.Time{}, data: state{Version: 1, Rules: map[string]Rule{}, Instances: map[string]instance{}, Alerts: map[string]Alert{}, Events: []Event{}, Audit: []Audit{}}}
	var raw []byte
	if docs != nil {
		raw, e = docs.LoadOrImport("monitor-alerts", path)
	} else {
		raw, e = os.ReadFile(path)
		if errors.Is(e, os.ErrNotExist) {
			e = nil
		}
	}
	if e != nil {
		cancel()
		return nil, e
	}
	if len(raw) > 0 {
		var box envelope
		if len(raw) > maxStateBytes*2 || decode(raw, &box) != nil || box.Version != 1 || len(box.Nonce) != a.NonceSize() {
			cancel()
			return nil, ErrInvalid
		}
		plain, e := a.Open(nil, box.Nonce, box.Ciphertext, []byte("jms233/monitor-alerts/v1"))
		if e != nil || len(plain) > maxStateBytes || decode(plain, &s.data) != nil || validState(s.data) != nil {
			cancel()
			return nil, ErrInvalid
		}
	}
	// Pending/recovery streaks cannot prove continuity across restart/takeover.
	// Firing episodes and their last consumed sample remain durable.
	changed := false
	for key, v := range s.data.Instances {
		if v.AlertID == "" {
			delete(s.data.Instances, key)
			changed = true
		} else if v.RecoverCount != 0 {
			v.RecoverCount = 0
			v.RecoverSince = time.Time{}
			s.data.Instances[key] = v
			changed = true
		}
	}
	if changed {
		if e = s.persist(s.data); e != nil {
			cancel()
			return nil, e
		}
	}
	return s, nil
}
func decode(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func validState(d state) error {
	if d.Version != 1 || d.Rules == nil || d.Instances == nil || d.Alerts == nil || len(d.Rules) > MaxRules || len(d.Instances) > MaxInstances || len(d.Alerts) > MaxAlerts || len(d.Events) > MaxEvents || len(d.Audit) > MaxAudit {
		return ErrInvalid
	}
	for id, r := range d.Rules {
		if id != r.ID || !idPattern.MatchString(id) || validate(r.Input) != nil || r.Revision < 1 || r.Definition < 1 || r.Definition > r.Revision || !actorOK(r.Owner) || r.UpdatedAt.IsZero() || !textOK(r.MuteReason, 500) || !slices.Contains([]string{"", "permission_changed", "capacity"}, r.LastError) {
			return ErrInvalid
		}
	}
	for id, a := range d.Alerts {
		if id != a.ID || !idPattern.MatchString(id) || a.Revision < 1 || !idPattern.MatchString(a.AssetID) || !idPattern.MatchString(a.RuleID) || a.StartedAt.IsZero() || a.LastObservedAt.IsZero() || !slices.Contains([]string{"firing", "resolved", "retired"}, a.State) || !slices.Contains(Metrics, a.Metric) || !textOK(a.AssetName, 480) || !textOK(a.RuleName, 120) || !textOK(a.Comment, 500) || a.Value != nil && !finite(*a.Value) {
			return ErrInvalid
		}
		if a.RuleRevision < 1 || !finite(a.Threshold) || !finite(a.RecoveryThreshold) || a.Threshold <= a.RecoveryThreshold || a.RecoveryThreshold < 0 || a.Threshold > 1e12 || a.State == "firing" && !a.EndedAt.IsZero() || a.State != "firing" && (a.EndedAt.IsZero() || a.EndedAt.Before(a.StartedAt)) || !a.AcknowledgedAt.IsZero() && !actorOK(a.AcknowledgedBy) || a.Value != nil && (*a.Value < 0 || *a.Value > 1e15) || !slices.Contains([]string{"", "rule_changed", "rule_deleted", "authority_revoked", "rule_disabled", "target_changed", "target_unavailable"}, a.Reason) {
			return ErrInvalid
		}
	}
	tracked := map[string]bool{}
	for key, v := range d.Instances {
		if key != instanceKey(v.RuleID, v.AssetID) || !hashPattern.MatchString(v.Binding) || v.Count < 0 || v.Count > 30 || v.RecoverCount < 0 || v.RecoverCount > 30 {
			return ErrInvalid
		}
		r, ok := d.Rules[v.RuleID]
		if !ok || v.Definition != r.Definition || !idPattern.MatchString(v.AssetID) || v.LastSample.IsZero() || v.Count > 0 && v.Since.IsZero() || v.RecoverCount > 0 && v.RecoverSince.IsZero() {
			return ErrInvalid
		}
		if v.AlertID != "" {
			a, ok := d.Alerts[v.AlertID]
			if !ok || a.RuleID != v.RuleID || a.AssetID != v.AssetID || a.State != "firing" || tracked[a.ID] {
				return ErrInvalid
			}
			tracked[a.ID] = true
		}
	}
	for id, a := range d.Alerts {
		if a.State == "firing" && !tracked[id] {
			return ErrInvalid
		}
	}
	eventIDs := map[string]bool{}
	for _, e := range d.Events {
		if !hashPattern.MatchString(e.ID) || !idPattern.MatchString(e.AlertID) || !idPattern.MatchString(e.AssetID) || !textOK(e.AssetName, 480) || e.At.IsZero() || !slices.Contains([]string{"monitoring_firing", "monitoring_resolved"}, e.State) || eventIDs[e.ID] {
			return ErrInvalid
		}
		eventIDs[e.ID] = true
	}
	auditIDs := map[string]bool{}
	for _, a := range d.Audit {
		if !idPattern.MatchString(a.ID) || !actorOK(a.Actor) || a.At.IsZero() || !idPattern.MatchString(a.Target) || !textOK(a.Reason, 500) || !slices.Contains([]string{"rule_saved", "rule_muted", "rule_deleted", "alert_acknowledged"}, a.Action) || auditIDs[a.ID] {
			return ErrInvalid
		}
		auditIDs[a.ID] = true
	}
	return nil
}
func clone(d state) state {
	out := state{Version: d.Version, Rules: map[string]Rule{}, Instances: map[string]instance{}, Alerts: map[string]Alert{}, Events: slices.Clone(d.Events), Audit: slices.Clone(d.Audit)}
	for k, v := range d.Rules {
		v.Scope.AssetIDs = slices.Clone(v.Scope.AssetIDs)
		v.Scope.NodeIDs = slices.Clone(v.Scope.NodeIDs)
		out.Rules[k] = v
	}
	for k, v := range d.Instances {
		out.Instances[k] = v
	}
	for k, v := range d.Alerts {
		if v.Value != nil {
			n := *v.Value
			v.Value = &n
		}
		out.Alerts[k] = v
	}
	return out
}
func (s *Service) persist(d state) error {
	raw, e := json.Marshal(d)
	if e != nil {
		return e
	}
	if len(raw) > maxStateBytes {
		return ErrCapacity
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	raw, e = json.Marshal(envelope{1, nonce, s.aead.Seal(nil, nonce, raw, []byte("jms233/monitor-alerts/v1"))})
	if e != nil {
		return e
	}
	if s.saveHook != nil {
		if e = s.saveHook(raw); e != nil {
			return e
		}
	}
	if s.docs != nil {
		return s.docs.Save("monitor-alerts", raw)
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".monitor-alerts-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(raw)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(f.Name(), s.path)
}
func (s *Service) mutate(fn func(*state) error) error {
	s.op.Lock()
	defer s.op.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return ErrClosed
	}
	next := clone(s.data)
	prune(&next, s.now().UTC())
	if e := fn(&next); e != nil {
		return e
	}
	if e := s.persist(next); e != nil {
		return e
	}
	s.data = next
	return nil
}
func newID(prefix string) string {
	var raw [16]byte
	if _, e := rand.Read(raw[:]); e != nil {
		return ""
	}
	return prefix + hex.EncodeToString(raw[:])
}
func audit(d *state, actor Actor, action, target, reason string, now time.Time) {
	d.Audit = append(d.Audit, Audit{ID: newID("monitor-audit-"), At: now, Actor: actor, Action: action, Target: target, Reason: reason})
	if len(d.Audit) > MaxAudit {
		d.Audit = slices.Clone(d.Audit[len(d.Audit)-MaxAudit:])
	}
}
func prune(d *state, now time.Time) {
	cutoff := now.Add(-30 * 24 * time.Hour)
	for id, a := range d.Alerts {
		if a.State != "firing" && !a.EndedAt.IsZero() && a.EndedAt.Before(cutoff) {
			delete(d.Alerts, id)
		}
	}
	d.Events = slices.DeleteFunc(d.Events, func(v Event) bool { return v.At.Before(cutoff) })
	if len(d.Events) > MaxEvents {
		d.Events = slices.Clone(d.Events[len(d.Events)-MaxEvents:])
	}
	d.Audit = slices.DeleteFunc(d.Audit, func(v Audit) bool { return v.At.Before(now.Add(-365 * 24 * time.Hour)) })
}
func (s *Service) SaveRule(id string, in Input, actor Actor) (Rule, error) {
	if validate(in) != nil || !actorOK(actor) {
		return Rule{}, ErrInvalid
	}
	var out Rule
	e := s.mutate(func(d *state) error {
		old, exists := d.Rules[id]
		if id == "" {
			if in.Revision != 0 {
				return ErrConflict
			}
			if len(d.Rules) >= MaxRules {
				return ErrCapacity
			}
			id = newID("monitor-rule-")
			if id == "" {
				return ErrInvalid
			}
		} else if !exists {
			return ErrNotFound
		}
		if exists && old.Revision != in.Revision {
			return ErrConflict
		}
		now := s.now().UTC()
		retire(d, id, "rule_changed", now)
		in.Revision++
		in.Scope.AssetIDs = slices.Clone(in.Scope.AssetIDs)
		in.Scope.NodeIDs = slices.Clone(in.Scope.NodeIDs)
		out = Rule{ID: id, Input: in, Owner: actor, UpdatedAt: now, Definition: old.Definition + 1}
		d.Rules[id] = out
		audit(d, actor, "rule_saved", id, "", now)
		return nil
	})
	out.Scope.AssetIDs = slices.Clone(out.Scope.AssetIDs)
	out.Scope.NodeIDs = slices.Clone(out.Scope.NodeIDs)
	return out, e
}
func (s *Service) MuteRule(id string, revision int, until time.Time, reason string, actor Actor) (Rule, error) {
	now := s.now().UTC()
	if !actorOK(actor) || !textOK(reason, 500) || !until.IsZero() && (!until.After(now) || until.After(now.Add(30*24*time.Hour))) {
		return Rule{}, ErrInvalid
	}
	var out Rule
	e := s.mutate(func(d *state) error {
		r, ok := d.Rules[id]
		if !ok {
			return ErrNotFound
		}
		if r.Revision != revision {
			return ErrConflict
		}
		r.MutedUntil = until.UTC()
		r.MuteReason = reason
		r.Revision++
		d.Rules[id] = r
		out = r
		if until.After(now) {
			for key, v := range d.Instances {
				if v.RuleID == id && v.AlertID != "" {
					v.Suppressed = true
					d.Instances[key] = v
				}
			}
		}
		audit(d, actor, "rule_muted", id, reason, now)
		return nil
	})
	out.Scope.AssetIDs = slices.Clone(out.Scope.AssetIDs)
	out.Scope.NodeIDs = slices.Clone(out.Scope.NodeIDs)
	return out, e
}
func (s *Service) DeleteRule(id string, revision int, actor Actor) error {
	if !actorOK(actor) {
		return ErrInvalid
	}
	return s.mutate(func(d *state) error {
		r, ok := d.Rules[id]
		if !ok {
			return ErrNotFound
		}
		if r.Revision != revision {
			return ErrConflict
		}
		now := s.now().UTC()
		retire(d, id, "rule_deleted", now)
		delete(d.Rules, id)
		audit(d, actor, "rule_deleted", id, "", now)
		return nil
	})
}
func (s *Service) Rules() []Rule {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Rule{}
	for _, v := range cloneRules(s.data.Rules) {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out
}
func cloneRules(in map[string]Rule) map[string]Rule {
	out := map[string]Rule{}
	for id, r := range in {
		r.Scope.AssetIDs = slices.Clone(r.Scope.AssetIDs)
		r.Scope.NodeIDs = slices.Clone(r.Scope.NodeIDs)
		out[id] = r
	}
	return out
}
func (s *Service) Rule(id string) (Rule, bool) {
	for _, r := range s.Rules() {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}
func (s *Service) Alert(id string) (Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.data.Alerts[id]
	if !ok {
		return Alert{}, ErrNotFound
	}
	if a.Value != nil {
		v := *a.Value
		a.Value = &v
	}
	return a, nil
}
func (s *Service) Acknowledge(id string, revision int, comment string, actor Actor) (Alert, error) {
	if !actorOK(actor) || !textOK(comment, 500) {
		return Alert{}, ErrInvalid
	}
	var out Alert
	e := s.mutate(func(d *state) error {
		a, ok := d.Alerts[id]
		if !ok {
			return ErrNotFound
		}
		if a.Revision != revision {
			return ErrConflict
		}
		if a.State != "firing" || !a.AcknowledgedAt.IsZero() {
			return ErrConflict
		}
		now := s.now().UTC()
		a.Revision++
		a.AcknowledgedAt = now
		a.AcknowledgedBy = actor
		a.Comment = comment
		d.Alerts[id] = a
		out = a
		audit(d, actor, "alert_acknowledged", id, comment, now)
		return nil
	})
	if out.Value != nil {
		v := *out.Value
		out.Value = &v
	}
	return out, e
}
func (s *Service) Alerts(offset, limit int, stateFilter string, visible func(Alert) bool) (Page[Alert], error) {
	if offset < 0 || limit < 1 || limit > 200 || !slices.Contains([]string{"", "firing", "resolved", "retired"}, stateFilter) {
		return Page[Alert]{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	list := []Alert{}
	for _, a := range s.data.Alerts {
		if (stateFilter == "" || a.State == stateFilter) && (visible == nil || visible(a)) {
			if a.Value != nil {
				v := *a.Value
				a.Value = &v
			}
			list = append(list, a)
		}
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].StartedAt.Equal(list[j].StartedAt) {
			return list[i].ID > list[j].ID
		}
		return list[i].StartedAt.After(list[j].StartedAt)
	})
	total := len(list)
	offset = min(offset, total)
	return Page[Alert]{list[offset:min(offset+limit, total)], total}, nil
}
func (s *Service) Audit(offset, limit int) (Page[Audit], error) {
	if offset < 0 || limit < 1 || limit > 200 {
		return Page[Audit]{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	list := slices.Clone(s.data.Audit)
	slices.Reverse(list)
	total := len(list)
	offset = min(offset, total)
	return Page[Audit]{list[offset:min(offset+limit, total)], total}, nil
}
func (s *Service) NotificationFeed(ctx context.Context, after string, since time.Time, limit int) (eventfeed.Batch, error) {
	if ctx.Err() != nil {
		return eventfeed.Batch{}, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return eventfeed.Batch{}, ErrClosed
	}
	if len(s.data.Events) > 0 && s.data.Events[len(s.data.Events)-1].ID == after {
		return eventfeed.Batch{Events: []eventfeed.Event{}, Cursor: after}, nil
	}
	rows := make([]eventfeed.Event, 0, len(s.data.Events))
	for _, v := range s.data.Events {
		rows = append(rows, eventfeed.Event{ID: v.ID, Kind: "monitor-alerts", ResourceID: v.AlertID, Name: v.AssetName, State: v.State, At: v.At})
	}
	return eventfeed.Read(rows, after, since, limit), nil
}
