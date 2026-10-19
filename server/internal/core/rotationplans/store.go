package rotationplans

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
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/credentialpolicy"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

type planRecord struct {
	Plan
	Bindings map[string]string `json:"bindings"`
}
type runRecord struct {
	Run
	Intents  map[string]Intent `json:"intents"`
	Recovery *recoveryRequest  `json:"recovery,omitempty"`
}
type recoveryRequest struct {
	Actor  Actor                 `json:"actor"`
	At     time.Time             `json:"at"`
	Origin accesspolicies.Origin `json:"origin"`
}
type state struct {
	Version int                   `json:"version"`
	Plans   map[string]planRecord `json:"plans"`
	Runs    map[string]runRecord  `json:"runs"`
	Audit   []Audit               `json:"audit"`
}
type envelope struct {
	Version    int    `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}
type Service struct {
	mu                       sync.Mutex
	tickMu                   sync.Mutex
	path                     string
	docs                     *storage.Documents
	aead                     cipher.AEAD
	data                     state
	runner                   Runner
	now                      func() time.Time
	ctx                      context.Context
	cancel                   context.CancelFunc
	wg                       sync.WaitGroup
	started, closed, working bool
	activeRun                string
	activeCancel             context.CancelFunc
	inspectAfter             map[string]time.Time
	saveHook                 func([]byte) error
}

func Open(path string, key []byte, docs *storage.Documents) (*Service, error) {
	if len(key) != 32 {
		return nil, ErrInvalid
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{path: path, docs: docs, aead: aead, now: time.Now, ctx: ctx, cancel: cancel, inspectAfter: map[string]time.Time{}, data: state{Version: 1, Plans: map[string]planRecord{}, Runs: map[string]runRecord{}, Audit: []Audit{}}}
	var raw []byte
	if docs != nil {
		raw, e = docs.LoadOrImport("rotation-plans", path)
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
	if len(raw) == 0 {
		return s, nil
	}
	var box envelope
	if len(raw) > maxStateBytes*2 || strictJSON(raw, &box) != nil || box.Version != 1 || len(box.Nonce) != aead.NonceSize() {
		cancel()
		return nil, ErrInvalid
	}
	plain, e := aead.Open(nil, box.Nonce, box.Ciphertext, []byte("jms233/rotation-plans/v1"))
	if e != nil || len(plain) > maxStateBytes || strictJSON(plain, &s.data) != nil || validateState(s.data) != nil {
		cancel()
		return nil, ErrInvalid
	}
	changed := false
	for id, r := range s.data.Runs {
		for i := range r.Items {
			if r.Items[i].State == "running" {
				r.Items[i].State = "recovering"
				changed = true
			}
		}
		if !terminal(r.State) {
			r.State = runState(r.Run)
		}
		s.data.Runs[id] = r
	}
	if changed {
		if e = s.persistLocked(s.data); e != nil {
			cancel()
			return nil, e
		}
	}
	return s, nil
}
func strictJSON(raw []byte, out any) error {
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
func digest(v string) bool {
	if len(v) != 64 {
		return false
	}
	_, e := hex.DecodeString(v)
	return e == nil
}
func validRef(r Ref) bool {
	return IDPattern.MatchString(r.AccountID) && IDPattern.MatchString(r.AssetID) && validText(r.AssetName, 480) && r.Username != "" && validText(r.Username, 128) && (r.CredentialType == "password" || r.CredentialType == "ssh_key") && (r.CollectorID == "" && r.CollectorUsername == "" || r.CredentialType == "password" && IDPattern.MatchString(r.CollectorID) && r.CollectorUsername != "") && validText(r.CollectorUsername, 128)
}
func validOrigin(v accesspolicies.Origin) bool {
	if v.Method != "" && v.Method != "credential_rotation" {
		return false
	}
	if v.SourceIP == "" || v.SourceIP == "unknown" {
		return true
	}
	p, e := netip.ParseAddr(v.SourceIP)
	return e == nil && p.Zone() == ""
}
func validatePrepared(v Prepared) error {
	if !validRef(v.Ref) || !digest(v.Version) || !digest(v.Binding) || !digest(v.Group) || v.Revision == 0 || v.Revision >= 1<<53 {
		return ErrInvalid
	}
	return nil
}
func validateState(d state) error {
	if d.Version != 1 || d.Plans == nil || d.Runs == nil || len(d.Plans) > MaxPlans || len(d.Runs) > MaxRuns || len(d.Audit) > MaxAudit {
		return ErrInvalid
	}
	for id, p := range d.Plans {
		if !validOrigin(p.AccessOrigin) {
			return ErrInvalid
		}
		if id != p.ID || !IDPattern.MatchString(id) || !ValidActor(p.Actor) || p.Validate() != nil || p.Revision < 1 || p.TargetCount != len(p.Targets) || len(p.Bindings) != len(p.Targets) || len(p.Refs) != len(p.Targets) || p.CreatedAt.IsZero() || p.UpdatedAt.IsZero() {
			return ErrInvalid
		}
		hasPassword := false
		for i, v := range p.Targets {
			if !validRef(p.Refs[i]) || p.Refs[i].AccountID != v.AccountID || !digest(p.Bindings[v.AccountID]) {
				return ErrInvalid
			}
			hasPassword = hasPassword || p.Refs[i].CredentialType == "password"
		}
		if !p.PasswordPolicy.IsZero() && !hasPassword {
			return ErrInvalid
		}
	}
	for id, r := range d.Runs {
		if !r.PasswordPolicy.OptionalValid() {
			return ErrInvalid
		}
		if r.Recovery != nil && (!ValidActor(r.Recovery.Actor) || r.Recovery.At.IsZero() || !validOrigin(r.Recovery.Origin)) {
			return ErrInvalid
		}
		if id != r.ID || !IDPattern.MatchString(id) || !IDPattern.MatchString(r.PlanID) || !IDPattern.MatchString(r.RequestID) || !ValidActor(r.Actor) || !validText(r.Name, 240) || !validOrigin(r.AccessOrigin) || r.PlanRevision < 1 || r.CreatedAt.IsZero() || len(r.Items) < 1 || len(r.Items) > MaxTargets || len(r.Intents) > len(r.Items) || !validRunState(r.State) {
			return ErrInvalid
		}
		seen := map[string]bool{}
		leaders := map[string]bool{}
		for _, v := range r.Items {
			if !validRef(v.Ref) || !IDPattern.MatchString(v.ID) || seen[v.ID] || !validItemState(v.State) || v.LinkedTo != "" && !IDPattern.MatchString(v.LinkedTo) {
				return ErrInvalid
			}
			seen[v.ID] = true
			if v.LinkedTo == "" {
				leaders[v.ID] = true
			}
			if op, ok := r.Intents[v.ID]; ok {
				expectedPolicy := r.PasswordPolicy
				if v.CredentialType != "password" {
					expectedPolicy = credentialpolicy.Rules{}
				}
				if op.PasswordPolicy != expectedPolicy {
					return ErrInvalid
				}
				if v.LinkedTo != "" || op.RequestID != v.ID || op.Actor != r.Actor || op.Origin != r.AccessOrigin || op.Target.Ref != v.Ref || op.Target.Revision != v.BeforeRevision || validatePrepared(op.Target) != nil {
					return ErrInvalid
				}
			} else if v.LinkedTo == "" && v.State != "changed" && v.State != "denied" && v.State != "failed" && v.State != "cancelled" {
				return ErrInvalid
			}
		}
		for _, v := range r.Items {
			if v.LinkedTo != "" && (!leaders[v.LinkedTo] || v.LinkedTo == v.ID) {
				return ErrInvalid
			}
		}
		for key := range r.Intents {
			if !seen[key] {
				return ErrInvalid
			}
		}
	}
	for _, v := range d.Audit {
		if !validOrigin(v.Origin) || !ValidActor(v.Actor) || v.At.IsZero() || !validText(v.Action, 64) || !IDPattern.MatchString(v.PlanID) {
			return ErrInvalid
		}
	}
	return nil
}
func clonePlan(p Plan) Plan {
	p.Targets = slices.Clone(p.Targets)
	p.Refs = slices.Clone(p.Refs)
	return p
}
func cloneRun(r Run) Run { r.Items = slices.Clone(r.Items); return r }
func cloneState(d state) state {
	out := state{Version: d.Version, Plans: map[string]planRecord{}, Runs: map[string]runRecord{}, Audit: slices.Clone(d.Audit)}
	for id, p := range d.Plans {
		p.Plan = clonePlan(p.Plan)
		binds := map[string]string{}
		for k, v := range p.Bindings {
			binds[k] = v
		}
		p.Bindings = binds
		out.Plans[id] = p
	}
	for id, r := range d.Runs {
		r.Run = cloneRun(r.Run)
		ops := map[string]Intent{}
		for k, v := range r.Intents {
			ops[k] = v
		}
		r.Intents = ops
		out.Runs[id] = r
	}
	return out
}
func (s *Service) persistLocked(d state) error {
	if s.closed || s.ctx.Err() != nil {
		return ErrBusy
	}
	if e := validateState(d); e != nil {
		return e
	}
	plain, e := json.Marshal(d)
	if e != nil {
		return e
	}
	if len(plain) > maxStateBytes {
		return ErrCapacity
	}
	n := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return e
	}
	raw, e := json.Marshal(envelope{1, n, s.aead.Seal(nil, n, plain, []byte("jms233/rotation-plans/v1"))})
	if e != nil {
		return e
	}
	if s.saveHook != nil {
		if e = s.saveHook(raw); e != nil {
			return e
		}
	}
	if s.docs != nil {
		return s.docs.Save("rotation-plans", raw)
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".rotation-plans-*")
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrBusy
	}
	next := cloneState(s.data)
	now := s.now().UTC()
	for id, r := range next.Runs {
		if terminal(r.State) && !r.FinishedAt.IsZero() && r.FinishedAt.Before(now.Add(-90*24*time.Hour)) {
			delete(next.Runs, id)
		}
	}
	next.Audit = slices.DeleteFunc(next.Audit, func(a Audit) bool { return a.At.Before(now.Add(-365 * 24 * time.Hour)) })
	if e := fn(&next); e != nil {
		return e
	}
	if reflect.DeepEqual(next, s.data) {
		return nil
	}
	if e := s.persistLocked(next); e != nil {
		return e
	}
	s.data = next
	return nil
}
func newID(prefix string) (string, error) {
	var raw [16]byte
	if _, e := rand.Read(raw[:]); e != nil {
		return "", e
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}
func (s *Service) SetRunner(r Runner)     { s.mu.Lock(); defer s.mu.Unlock(); s.runner = r }
func (s *Service) runnerSnapshot() Runner { s.mu.Lock(); defer s.mu.Unlock(); return s.runner }
func (s *Service) Save(ctx context.Context, actor Actor, id string, in PlanInput, all bool) (Plan, error) {
	if !ValidActor(actor) || in.Validate() != nil {
		return Plan{}, ErrInvalid
	}
	r := s.runnerSnapshot()
	if r.Prepare == nil || r.Authorize == nil {
		return Plan{}, ErrBusy
	}
	targets, e := r.Prepare(ctx, actor, in.Targets)
	if e != nil {
		return Plan{}, e
	}
	if len(targets) != len(in.Targets) {
		return Plan{}, ErrInvalid
	}
	binds := map[string]string{}
	refs := make([]Ref, len(targets))
	hasPassword := false
	for i, v := range targets {
		if validatePrepared(v) != nil || v.AccountID != in.Targets[i].AccountID {
			return Plan{}, ErrInvalid
		}
		binds[v.AccountID] = v.Binding
		refs[i] = v.Ref
		hasPassword = hasPassword || v.CredentialType == "password"
	}
	if !in.PasswordPolicy.IsZero() && !hasPassword {
		return Plan{}, ErrInvalid
	}
	if in.Enabled {
		if e = r.Authorize(actor); e != nil {
			return Plan{}, e
		}
	}
	var out Plan
	e = s.mutate(func(d *state) error {
		if len(d.Audit) >= MaxAudit {
			return ErrCapacity
		}
		now := s.now().UTC()
		owner := actor
		created := now
		revision := 1
		if id == "" {
			if in.Revision != 0 {
				return ErrConflict
			}
			if len(d.Plans) >= MaxPlans {
				return ErrCapacity
			}
			var e error
			id, e = newID("rotation-plan-")
			if e != nil {
				return e
			}
		} else {
			p, ok := d.Plans[id]
			if !ok || p.Actor.ID != actor.ID && !all {
				return ErrNotFound
			}
			if in.Revision != p.Revision {
				return ErrConflict
			}
			if p.Revision >= 1<<53-1 {
				return ErrCapacity
			}
			owner = p.Actor
			created = p.CreatedAt
			revision = p.Revision + 1
			if in.Enabled {
				if e := r.Authorize(owner); e != nil {
					return e
				}
			}
		}
		in.Revision = revision
		out = Plan{ID: id, Actor: owner, PlanInput: in, Refs: refs, CreatedAt: created, UpdatedAt: now, AccessOrigin: in.Origin, TargetCount: len(refs)}
		if prior, ok := d.Plans[id]; ok && prior.Actor.ID != actor.ID {
			out.AccessOrigin = prior.AccessOrigin
		}
		out.Targets = slices.Clone(in.Targets)
		if in.Enabled {
			out.NextRun = now
			if in.Kind == "once" {
				if !in.RunAt.After(now) || in.RunAt.After(now.Add(365*24*time.Hour)) {
					return ErrInvalid
				}
				out.NextRun = in.RunAt
			}
		}
		if prior, ok := d.Plans[id]; ok {
			out.LastRunID = prior.LastRunID
		}
		d.Plans[id] = planRecord{Plan: clonePlan(out), Bindings: binds}
		d.Audit = append(d.Audit, Audit{Origin: in.Origin, At: now, Actor: actor, Action: "saved", PlanID: id, Revision: revision})
		return nil
	})
	return out, e
}
func (s *Service) Plan(id string) (Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.data.Plans[id]
	if !ok {
		return Plan{}, ErrNotFound
	}
	return clonePlan(p.Plan), nil
}
func (s *Service) Plans(offset, limit int) ([]Plan, int, error) {
	if offset < 0 || limit < 1 || limit > 100 {
		return nil, 0, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.data.Plans))
	for _, p := range s.data.Plans {
		ids = append(ids, p.ID)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := s.data.Plans[ids[i]], s.data.Plans[ids[j]]
		if a.UpdatedAt.Equal(b.UpdatedAt) {
			return a.ID < b.ID
		}
		return a.UpdatedAt.After(b.UpdatedAt)
	})
	total := len(ids)
	offset = min(offset, total)
	items := make([]Plan, 0, min(limit, total-offset))
	for _, id := range ids[offset:min(total, offset+limit)] {
		p := s.data.Plans[id].Plan
		p.Targets = nil
		p.Refs = nil
		items = append(items, p)
	}
	return items, total, nil
}
func (s *Service) Run(id string) (Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.data.Runs[id]
	if !ok {
		return Run{}, ErrNotFound
	}
	return cloneRun(r.Run), nil
}
func (s *Service) Runs(plan string, offset, limit int) ([]RunSummary, int, error) {
	if offset < 0 || limit < 1 || limit > 100 {
		return nil, 0, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := []string{}
	for _, r := range s.data.Runs {
		if plan == "" || plan == r.PlanID {
			ids = append(ids, r.ID)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := s.data.Runs[ids[i]], s.data.Runs[ids[j]]
		if a.CreatedAt.Equal(b.CreatedAt) {
			return a.ID < b.ID
		}
		return a.CreatedAt.After(b.CreatedAt)
	})
	total := len(ids)
	offset = min(offset, total)
	items := make([]RunSummary, 0, min(limit, total-offset))
	for _, id := range ids[offset:min(total, offset+limit)] {
		run := s.data.Runs[id].Run
		summary := RunSummary{Run: run, Total: len(run.Items)}
		for _, item := range run.Items {
			switch item.State {
			case "succeeded":
				summary.Succeeded++
			case "not_due":
				summary.Skipped++
			case "failed", "denied", "changed", "interrupted":
				summary.Failed++
			}
		}
		summary.Items = nil
		items = append(items, summary)
	}
	return items, total, nil
}
func (s *Service) Audit(offset, limit int) ([]Audit, int, error) {
	if offset < 0 || limit < 1 || limit > 100 {
		return nil, 0, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	items := slices.Clone(s.data.Audit)
	slices.Reverse(items)
	total := len(items)
	offset = min(offset, total)
	return items[offset:min(total, offset+limit)], total, nil
}
func (s *Service) Delete(id string, revision int, actor Actor, all bool) error {
	return s.mutate(func(d *state) error {
		p, ok := d.Plans[id]
		if !ok || p.Actor.ID != actor.ID && !all {
			return ErrNotFound
		}
		if p.Revision != revision {
			return ErrConflict
		}
		for _, r := range d.Runs {
			if r.PlanID == id && !terminal(r.State) {
				return ErrBusy
			}
		}
		if len(d.Audit) >= MaxAudit {
			return ErrCapacity
		}
		delete(d.Plans, id)
		d.Audit = append(d.Audit, Audit{At: s.now().UTC(), Actor: actor, Action: "deleted", PlanID: id, Revision: revision})
		return nil
	})
}
