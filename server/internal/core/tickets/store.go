package tickets

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"time"
)

type decisionReceipt struct {
	ID      string `json:"id"`
	ActorID string `json:"actor_id"`
	Digest  string `json:"digest"`
}
type record struct {
	RevokeTo string `json:"revoke_to,omitempty"`
	Ticket
	RequestID string            `json:"request_id"`
	InputHash string            `json:"input_hash"`
	Prepared  []Prepared        `json:"prepared"`
	Digest    string            `json:"digest,omitempty"`
	Decisions []decisionReceipt `json:"decision_receipts"`
}
type state struct {
	Version  int               `json:"version"`
	Policies map[string]Policy `json:"policies"`
	Tickets  map[string]record `json:"tickets"`
	Audit    []Audit           `json:"audit"`
}
type envelope struct {
	Version    int    `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
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
	now             func() time.Time
	lastPrune       time.Time
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
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{path: path, docs: docs, aead: aead, ctx: ctx, cancel: cancel, now: time.Now, data: state{Version: 1, Policies: map[string]Policy{}, Tickets: map[string]record{}, Audit: []Audit{}}}
	var raw []byte
	if docs != nil {
		raw, e = docs.LoadOrImport("access-tickets", path)
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
	plain, e := aead.Open(nil, box.Nonce, box.Ciphertext, []byte("jms233/access-tickets/v1"))
	if e != nil || len(plain) > maxStateBytes || strictJSON(plain, &s.data) != nil || validateState(s.data) != nil {
		cancel()
		return nil, ErrInvalid
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
func hash(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func validHash(v string) bool {
	if len(v) != 64 {
		return false
	}
	_, e := hex.DecodeString(v)
	return e == nil
}
func newID(prefix string) (string, error) {
	var raw [16]byte
	if _, e := rand.Read(raw[:]); e != nil {
		return "", e
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}
func clonePolicy(p Policy) Policy {
	p.Requesters = slices.Clone(p.Requesters)
	p.CC = slices.Clone(p.CC)
	p.Stages = slices.Clone(p.Stages)
	for i := range p.Stages {
		p.Stages[i].Subjects = slices.Clone(p.Stages[i].Subjects)
	}
	p.Scopes = slices.Clone(p.Scopes)
	for i := range p.Scopes {
		p.Scopes[i].Accounts = slices.Clone(p.Scopes[i].Accounts)
		p.Scopes[i].Actions = slices.Clone(p.Scopes[i].Actions)
	}
	return p
}
func cloneTicket(t Ticket) Ticket {
	t.Targets = slices.Clone(t.Targets)
	for i := range t.Targets {
		t.Targets[i].Actions = slices.Clone(t.Targets[i].Actions)
	}
	t.Stages = slices.Clone(t.Stages)
	for i := range t.Stages {
		t.Stages[i].Subjects = slices.Clone(t.Stages[i].Subjects)
	}
	t.CC = slices.Clone(t.CC)
	t.Approvals = slices.Clone(t.Approvals)
	t.Comments = slices.Clone(t.Comments)
	t.GrantIDs = slices.Clone(t.GrantIDs)
	return t
}
func cloneRecord(r record) record {
	r.Ticket = cloneTicket(r.Ticket)
	r.Prepared = slices.Clone(r.Prepared)
	for i := range r.Prepared {
		r.Prepared[i].Nodes = slices.Clone(r.Prepared[i].Nodes)
		r.Prepared[i].Actions = slices.Clone(r.Prepared[i].Actions)
	}
	r.Decisions = slices.Clone(r.Decisions)
	return r
}
func cloneState(d state) state {
	next := state{Version: d.Version, Policies: map[string]Policy{}, Tickets: map[string]record{}, Audit: slices.Clone(d.Audit)}
	for id, p := range d.Policies {
		next.Policies[id] = clonePolicy(p)
	}
	for id, t := range d.Tickets {
		next.Tickets[id] = cloneRecord(t)
	}
	return next
}
func validState(v string) bool {
	switch v {
	case "pending", "issuing", "approved", "revoking", "revoked", "cancelled", "rejected", "expired", "stale":
		return true
	}
	return false
}
func terminal(v string) bool {
	return v == "revoked" || v == "cancelled" || v == "rejected" || v == "expired" || v == "stale"
}
func validatePrepared(v Prepared) error {
	if _, e := normalizeTargets([]Target{v.Target}); e != nil || v.Name == "" || !validText(v.Name, 480) || !validHash(v.Binding) || len(v.Nodes) > 128 || !validText(v.Protocol, 40) {
		return ErrInvalid
	}
	return nil
}
func validateState(d state) error {
	if d.Version != 1 || d.Policies == nil || d.Tickets == nil || len(d.Policies) > MaxPolicies || len(d.Tickets) > MaxTickets || len(d.Audit) > MaxAudit {
		return ErrInvalid
	}
	for id, p := range d.Policies {
		if id != p.ID || !IDPattern.MatchString(id) || !validActor(p.Publisher) || p.Validate() != nil || p.Revision < 1 || p.CreatedAt.IsZero() || p.UpdatedAt.IsZero() {
			return ErrInvalid
		}
	}
	for id, r := range d.Tickets {
		if id != r.ID || !IDPattern.MatchString(id) || !IDPattern.MatchString(r.PolicyID) || !IDPattern.MatchString(r.RequestID) || !validHash(r.InputHash) || !validActor(r.Owner) || !validActor(r.Publisher) || !validState(r.State) || r.Revision < 1 || r.CurrentStage < 0 || r.CurrentStage > len(r.Stages) || len(r.Stages) < 1 || len(r.Stages) > 5 || len(r.Targets) < 1 || len(r.Targets) > MaxTargets || len(r.Prepared) != len(r.Targets) || len(r.Comments) > 100 || len(r.Decisions) > 100 || len(r.Approvals) > 5 || r.CreatedAt.IsZero() || r.UpdatedAt.IsZero() || !r.StartsAt.Before(r.EndsAt) || r.ApprovalExpiresAt.IsZero() {
			return ErrInvalid
		}
		if !validText(r.Name, 240) || r.Name == "" || !validText(r.Reason, 4000) || !validSubjects(r.CC, 32) || len(r.Approvals) != r.CurrentStage || r.Revision >= 1<<53 || r.PolicyRevision < 1 || (r.State == "issuing" || r.State == "approved") && r.CurrentStage != len(r.Stages) {
			return ErrInvalid
		}
		if r.Digest != "" && (!validHash(r.Digest) || r.Digest != intentDigest(r)) {
			return ErrInvalid
		}
		if (r.State == "issuing" || r.State == "approved" || r.State == "revoking" || r.State == "revoked") && r.Digest == "" {
			return ErrInvalid
		}
		seen := map[string]bool{}
		for i, v := range r.Prepared {
			if validatePrepared(v) != nil || !reflect.DeepEqual(v.Ref, r.Targets[i]) || seen[targetKey(v.Target)] {
				return ErrInvalid
			}
			seen[targetKey(v.Target)] = true
		}
		reviewers := map[string]bool{}
		for i, a := range r.Approvals {
			if a.Stage != i || !validActor(a.Actor) || a.Actor.ID == r.Owner.ID || reviewers[a.Actor.ID] || a.At.IsZero() || !validText(a.Comment, 2000) {
				return ErrInvalid
			}
			reviewers[a.Actor.ID] = true
		}
		for _, c := range r.Comments {
			if !validActor(c.Actor) || c.At.IsZero() || !validText(c.Text, 4000) {
				return ErrInvalid
			}
		}
		for _, s := range r.Stages {
			if !validSubjects(s.Subjects, 32) || len(s.Subjects) == 0 {
				return ErrInvalid
			}
		}
		decisions := map[string]bool{}
		for _, v := range r.Decisions {
			if !IDPattern.MatchString(v.ID) || !IDPattern.MatchString(v.ActorID) || !validHash(v.Digest) || decisions[v.ID] {
				return ErrInvalid
			}
			decisions[v.ID] = true
		}
	}
	for _, a := range d.Audit {
		if !validActor(a.Actor) || a.At.IsZero() || !validText(a.Action, 64) || !validText(a.Note, 4000) {
			return ErrInvalid
		}
	}
	return nil
}
func (s *Service) persist(d state) error {
	if s.closed || s.ctx.Err() != nil {
		return ErrUnavailable
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
	raw, e := json.Marshal(envelope{1, n, s.aead.Seal(nil, n, plain, []byte("jms233/access-tickets/v1"))})
	if e != nil {
		return e
	}
	if s.saveHook != nil {
		if e = s.saveHook(raw); e != nil {
			return e
		}
	}
	if s.docs != nil {
		return s.docs.Save("access-tickets", raw)
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	file, e := os.CreateTemp(filepath.Dir(s.path), ".tickets-*")
	if e != nil {
		return e
	}
	defer os.Remove(file.Name())
	if e = file.Chmod(0600); e == nil {
		_, e = file.Write(raw)
	}
	if e == nil {
		e = file.Sync()
	}
	ce := file.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(file.Name(), s.path)
}
func (s *Service) mutate(fn func(*state) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrUnavailable
	}
	next := cloneState(s.data)
	now := s.now().UTC()
	for id, r := range next.Tickets {
		if terminal(r.State) && !r.ClosedAt.IsZero() && r.ClosedAt.Before(now.Add(-180*24*time.Hour)) {
			delete(next.Tickets, id)
		}
	}
	next.Audit = slices.DeleteFunc(next.Audit, func(a Audit) bool { return a.At.Before(now.Add(-365 * 24 * time.Hour)) })
	if e := fn(&next); e != nil {
		return e
	}
	if reflect.DeepEqual(next, s.data) {
		return nil
	}
	if e := s.persist(next); e != nil {
		return e
	}
	s.data = next
	return nil
}
func (s *Service) SetRunner(r Runner)     { s.mu.Lock(); defer s.mu.Unlock(); s.runner = r }
func (s *Service) runnerSnapshot() Runner { s.mu.Lock(); defer s.mu.Unlock(); return s.runner }
func (s *Service) principal(ctx context.Context, id string) (Principal, error) {
	r := s.runnerSnapshot()
	if r.Principal == nil {
		return Principal{}, ErrUnavailable
	}
	p, e := r.Principal(ctx, id)
	if e != nil || !validActor(p.Actor) || p.ID != id {
		return Principal{}, ErrDenied
	}
	return p, nil
}
func appendAudit(d *state, a Audit) error {
	if len(d.Audit) >= MaxAudit {
		d.Audit = slices.Delete(d.Audit, 0, len(d.Audit)-MaxAudit+1)
	}
	d.Audit = append(d.Audit, a)
	return nil
}
