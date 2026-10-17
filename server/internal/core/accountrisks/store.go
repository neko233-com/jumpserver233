package accountrisks

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

type state struct {
	Version  int                 `json:"version"`
	Policy   Policy              `json:"policy"`
	Findings map[string]entry    `json:"findings"`
	Groups   map[string][]Member `json:"groups"`
	Usage    map[string]Usage    `json:"usage"`
	Scans    []Scan              `json:"scans"`
	Audit    []Audit             `json:"audit"`
}
type envelope struct {
	Version    int    `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}
type Service struct {
	mu        sync.Mutex
	scanMu    sync.Mutex
	path      string
	docs      *storage.Documents
	aead      cipher.AEAD
	data      state
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	started   bool
	closed    bool
	collect   Collector
	authority Authority
	running   map[string]context.CancelFunc
	now       func() time.Time
	saveHook  func([]byte) error
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
	s := &Service{path: path, docs: docs, aead: aead, ctx: ctx, cancel: cancel, running: map[string]context.CancelFunc{}, now: time.Now,
		data: state{Version: 1, Policy: DefaultPolicy(), Findings: map[string]entry{}, Groups: map[string][]Member{}, Usage: map[string]Usage{}, Scans: []Scan{}, Audit: []Audit{}}}
	var raw []byte
	if docs != nil {
		raw, e = docs.LoadOrImport("account-risks", path)
	} else {
		raw, e = os.ReadFile(path)
		if errors.Is(e, os.ErrNotExist) {
			return s, nil
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
	plain, e := aead.Open(nil, box.Nonce, box.Ciphertext, []byte("jms233/account-risks/v1"))
	if e != nil || len(plain) > maxStateBytes || strictJSON(plain, &s.data) != nil || validateState(s.data) != nil {
		cancel()
		return nil, ErrInvalid
	}
	changed := false
	for i := range s.data.Scans {
		if s.data.Scans[i].State == "running" {
			s.data.Scans[i].State = "interrupted"
			s.data.Scans[i].ErrorCode = "interrupted"
			s.data.Scans[i].FinishedAt = s.now().UTC()
			changed = true
		}
	}
	if changed {
		if s.data.Policy.Enabled {
			s.data.Policy.NextRun = s.now().UTC()
		}
		if e = s.persistLocked(s.data); e != nil {
			cancel()
			return nil, e
		}
	}
	return s, nil
}
func strictJSON(raw []byte, out any) error {
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func validateState(d state) error {
	if d.Usage == nil || len(d.Usage) > MaxAccounts {
		return ErrInvalid
	}
	if d.Version != 1 || d.Policy.Validate() != nil || d.Findings == nil || d.Groups == nil || len(d.Findings) > maxFindings || len(d.Scans) > maxScans || len(d.Audit) > maxAudit {
		return ErrInvalid
	}
	for id, e := range d.Findings {
		if id != e.ID || !idPattern.MatchString(id) || !validRef(e.Ref) || !slices.Contains(kinds, e.Kind) || e.Revision < 1 || e.Revision > 1<<53-1 || e.PolicyRevision < 1 || !validDigest(e.Binding) || !validDigest(e.Identity) || !validDigest(e.SourceVersion) || e.GroupID != "" && !validDigest(e.GroupID) || e.FirstSeen.IsZero() || e.LastSeen.IsZero() || !validText(e.Note, 2048) || !slices.Contains([]string{"open", "confirmed", "ignored", "resolved"}, e.State) {
			return ErrInvalid
		}
	}
	seen := map[string]bool{}
	for _, r := range d.Scans {
		if !idPattern.MatchString(r.ID) || !idPattern.MatchString(r.RequestID) || !validActor(r.Actor) || r.PolicyRevision < 1 || r.StartedAt.IsZero() || !slices.Contains([]string{"running", "succeeded", "failed", "cancelled", "interrupted"}, r.State) || seen[r.ID] {
			return ErrInvalid
		}
		seen[r.ID] = true
	}
	if len(d.Groups) > maxFindings {
		return ErrInvalid
	}
	for key, refs := range d.Groups {
		if !validDigest(key) || len(refs) > MaxAccounts {
			return ErrInvalid
		}
		for _, r := range refs {
			if !validRef(r.Ref) || !validDigest(r.Identity) {
				return ErrInvalid
			}
		}
	}
	for id, u := range d.Usage {
		if !idPattern.MatchString(id) || !validDigest(u.Identity) {
			return ErrInvalid
		}
	}
	return nil
}
func validDigest(v string) bool {
	if len(v) != 64 {
		return false
	}
	_, e := hex.DecodeString(v)
	return e == nil
}
func cloneState(d state) state {
	out := d
	out.Policy.Checks = slices.Clone(d.Policy.Checks)
	out.Findings = make(map[string]entry, len(d.Findings))
	out.Groups = make(map[string][]Member, len(d.Groups))
	out.Usage = make(map[string]Usage, len(d.Usage))
	for id, u := range d.Usage {
		out.Usage[id] = u
	}
	for id, e := range d.Findings {
		e.Reasons = slices.Clone(e.Reasons)
		e.Peers = nil
		out.Findings[id] = e
	}
	for id, g := range d.Groups {
		out.Groups[id] = slices.Clone(g)
	}
	out.Scans = slices.Clone(d.Scans)
	out.Audit = slices.Clone(d.Audit)
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
	nonce := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	raw, e := json.Marshal(envelope{1, nonce, s.aead.Seal(nil, nonce, plain, []byte("jms233/account-risks/v1"))})
	if e != nil {
		return e
	}
	if s.saveHook != nil {
		if e = s.saveHook(raw); e != nil {
			return e
		}
	}
	if s.docs != nil {
		return s.docs.Save("account-risks", raw)
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".account-risks-*")
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
func (s *Service) mutate(f func(*state) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.data)
	cutoff := s.now().UTC().Add(-time.Duration(next.Policy.AuditRetentionDays) * 24 * time.Hour)
	next.Audit = slices.DeleteFunc(next.Audit, func(a Audit) bool { return a.At.Before(cutoff) })
	if e := f(&next); e != nil {
		return e
	}
	if e := s.persistLocked(next); e != nil {
		return e
	}
	s.data = next
	return nil
}
func (s *Service) Policy() Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.data.Policy
	p.Checks = slices.Clone(p.Checks)
	return p
}
func (s *Service) Configure(in Policy, actor Actor) (Policy, error) {
	in.Owner = actor
	if !validActor(actor) || in.Validate() != nil {
		return Policy{}, ErrInvalid
	}
	var out Policy
	e := s.mutate(func(d *state) error {
		if in.Revision != d.Policy.Revision {
			return ErrConflict
		}
		if d.Policy.Revision >= 1<<53-1 {
			return ErrCapacity
		}
		if len(d.Audit) >= maxAudit {
			return ErrCapacity
		}
		in.Revision++
		in.Owner = actor
		in.LastError = ""
		in.NextRun = time.Time{}
		if in.Enabled {
			in.NextRun = s.now().UTC()
		}
		d.Policy = in
		d.Policy.Checks = slices.Clone(in.Checks)
		d.Audit = append(d.Audit, Audit{At: s.now().UTC(), Actor: actor, Action: "configure"})
		out = d.Policy
		return nil
	})
	if e == nil {
		s.mu.Lock()
		for _, cancel := range s.running {
			cancel()
		}
		s.mu.Unlock()
	}
	return out, e
}
func (s *Service) SetRunner(collect Collector, authority Authority) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.collect = collect
	s.authority = authority
}
func (s *Service) Start(owner context.Context) {
	s.mu.Lock()
	if s.started || s.closed {
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
		timer := time.NewTicker(time.Minute)
		defer timer.Stop()
		for {
			s.tick()
			select {
			case <-s.ctx.Done():
				return
			case <-timer.C:
			}
		}
	}()
}
func (s *Service) tick() {
	p := s.Policy()
	if !p.Enabled || p.NextRun.After(s.now()) {
		return
	}
	var raw [16]byte
	if _, e := rand.Read(raw[:]); e != nil {
		return
	}
	_, e := s.Scan(s.ctx, p.Owner, "auto-"+hex.EncodeToString(raw[:]), p.Revision, true)
	if errors.Is(e, ErrDenied) {
		_ = s.mutate(func(d *state) error {
			if d.Policy.Revision != p.Revision {
				return nil
			}
			d.Policy.Enabled = false
			d.Policy.LastError = "denied"
			d.Policy.NextRun = time.Time{}
			d.Policy.Revision++
			if len(d.Audit) < maxAudit {
				d.Audit = append(d.Audit, Audit{At: s.now().UTC(), Actor: p.Owner, Action: "schedule_paused"})
			}
			return nil
		})
	}
}
func (s *Service) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.cancel()
	for _, cancel := range s.running {
		cancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
}
func (s *Service) Scan(ctx context.Context, actor Actor, requestID string, revision int, scheduled bool) (Scan, error) {
	if !validActor(actor) || !idPattern.MatchString(requestID) {
		return Scan{}, ErrInvalid
	}
	if !s.scanMu.TryLock() {
		return Scan{}, ErrBusy
	}
	defer s.scanMu.Unlock()
	s.mu.Lock()
	p := s.data.Policy
	collector, authority := s.collect, s.authority
	s.mu.Unlock()
	if collector == nil || authority == nil {
		return Scan{}, ErrBusy
	}
	release, e := authority(actor)
	if e != nil {
		return Scan{}, e
	}
	defer release()
	s.mu.Lock()
	for _, r := range s.data.Scans {
		if r.Actor.ID == actor.ID && r.RequestID == requestID {
			s.mu.Unlock()
			if r.PolicyRevision != revision {
				return Scan{}, ErrConflict
			}
			return r, nil
		}
	}
	s.mu.Unlock()
	if p.Revision != revision || scheduled && (!p.Enabled || p.Owner.ID != actor.ID) {
		return Scan{}, ErrConflict
	}
	var raw [16]byte
	if _, e = rand.Read(raw[:]); e != nil {
		return Scan{}, e
	}
	now := s.now().UTC()
	run := Scan{ID: "risk-scan-" + hex.EncodeToString(raw[:]), RequestID: requestID, Actor: actor, PolicyRevision: revision, State: "running", StartedAt: now}
	if e = s.mutate(func(d *state) error {
		if d.Policy.Revision != revision {
			return ErrConflict
		}
		if len(d.Audit) >= maxAudit {
			return ErrCapacity
		}
		if len(d.Scans) >= maxScans {
			d.Scans = d.Scans[len(d.Scans)-maxScans+1:]
		}
		d.Scans = append(d.Scans, run)
		if scheduled {
			d.Policy.NextRun = now.Add(time.Duration(p.IntervalHours) * time.Hour)
		}
		return nil
	}); e != nil {
		return Scan{}, e
	}
	work, cancel := context.WithTimeout(ctx, time.Minute)
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	defer cancel()
	s.mu.Lock()
	s.running[run.ID] = cancel
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.running, run.ID); s.mu.Unlock() }()
	e = collector(work, actor, p, now, func(snapshot Snapshot) error { return s.commitScan(work, run, p, snapshot) })
	s.mu.Lock()
	for _, r := range s.data.Scans {
		if r.ID == run.ID {
			run = r
			break
		}
	}
	s.mu.Unlock()
	if e == nil && run.State == "succeeded" {
		return run, nil
	}
	code := "unavailable"
	if errors.Is(e, ErrCapacity) {
		code = "capacity"
	} else if errors.Is(e, ErrConflict) {
		code = "conflict"
	} else if errors.Is(e, ErrDenied) {
		code = "denied"
	} else if work.Err() != nil {
		code = "cancelled"
	}
	_ = s.mutate(func(d *state) error {
		for i := range d.Scans {
			if d.Scans[i].ID == run.ID && d.Scans[i].State == "running" {
				d.Scans[i].State = "failed"
				if code == "cancelled" {
					d.Scans[i].State = "cancelled"
				}
				d.Scans[i].ErrorCode = code
				d.Scans[i].FinishedAt = s.now().UTC()
				run = d.Scans[i]
				if len(d.Audit) < maxAudit {
					d.Audit = append(d.Audit, Audit{At: s.now().UTC(), Actor: actor, Action: "scan_failed", ScanID: run.ID})
				}
			}
		}
		return nil
	})
	if e == nil {
		e = ErrConflict
	}
	return run, e
}
func (s *Service) commitScan(ctx context.Context, run Scan, p Policy, snapshot Snapshot) error {
	if len(snapshot.Accounts) > MaxAccounts {
		return ErrCapacity
	}
	return s.mutate(func(d *state) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.Policy.Revision != p.Revision {
			return ErrConflict
		}
		scanIndex := -1
		for i, r := range d.Scans {
			if r.ID == run.ID && r.State == "running" {
				scanIndex = i
			}
		}
		if scanIndex < 0 {
			return ErrConflict
		}
		if len(d.Audit) >= maxAudit {
			return ErrCapacity
		}
		now := s.now().UTC()
		for id, e := range d.Findings {
			if e.State == "resolved" && e.ResolvedAt.Before(now.Add(-time.Duration(p.ResolvedRetentionDays)*24*time.Hour)) {
				delete(d.Findings, id)
			}
		}
		d.Usage = map[string]Usage{}
		seen := map[string]bool{}
		accountIDs := map[string]bool{}
		for _, o := range snapshot.Accounts {
			if !validRef(o.Ref) || !validDigest(o.Binding) || !validDigest(o.SourceVersion) || o.CreatedAt.IsZero() || accountIDs[o.AccountID] {
				return ErrInvalid
			}
			accountIDs[o.AccountID] = true
			if !validDigest(o.Identity) {
				return ErrInvalid
			}
			d.Usage[o.AccountID] = Usage{o.Identity, o.LastUsedAt}
			for _, c := range o.Checks {
				if !p.Has(c.Kind) || !slices.Contains(kinds, c.Kind) || !slices.Contains([]string{"high", "medium", "low"}, c.Severity) {
					return ErrInvalid
				}
				key := sha256.Sum256([]byte(o.AccountID + "\x00" + c.Kind))
				id := "risk-" + hex.EncodeToString(key[:16])
				if seen[id] {
					return ErrInvalid
				}
				seen[id] = true
				old, exists := d.Findings[id]
				fresh := !exists || old.Binding != o.Binding || old.PolicyRevision != p.Revision || old.State == "resolved"
				f := old.Finding
				if fresh {
					f.State = "open"
					f.Note = ""
					f.ResolvedAt = time.Time{}
					f.Occurrences++
					if !exists {
						f.FirstSeen = now
					}
				}
				f.Ref = o.Ref
				f.ID = id
				f.Kind = c.Kind
				f.Severity = c.Severity
				f.Reasons = slices.Clone(c.Reasons)
				f.CredentialType = o.CredentialType
				f.Active = o.Active
				f.SourceVersion = o.SourceVersion
				f.PolicyRevision = p.Revision
				f.LastSeen = now
				f.LastUsedAt = o.LastUsedAt
				f.RotatedAt = o.RotatedAt
				f.Revision++
				d.Findings[id] = entry{Finding: f, Identity: o.Identity, Binding: o.Binding, GroupID: c.GroupID}
			}
		}
		for id, e := range d.Findings {
			if !seen[id] && e.State != "resolved" {
				e.State = "resolved"
				e.ResolvedAt = now
				e.Revision++
				d.Findings[id] = e
				d.Scans[scanIndex].Resolved++
			}
		}
		if len(d.Findings) > maxFindings {
			return ErrCapacity
		}
		for id, g := range snapshot.Groups {
			d.Groups[id] = slices.Clone(g)
		}
		referenced := map[string]bool{}
		for _, e := range d.Findings {
			if e.GroupID != "" {
				referenced[e.GroupID] = true
			}
			if e.State == "open" || e.State == "confirmed" {
				d.Scans[scanIndex].Open++
			}
		}
		for id := range d.Groups {
			if !referenced[id] {
				delete(d.Groups, id)
			}
		}
		d.Scans[scanIndex].Accounts = len(snapshot.Accounts)
		d.Scans[scanIndex].State = "succeeded"
		d.Scans[scanIndex].FinishedAt = now
		d.Policy.LastError = ""
		d.Audit = append(d.Audit, Audit{At: now, Actor: run.Actor, Action: "scan", ScanID: run.ID})
		return nil
	})
}
func (s *Service) Cancel(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cancel := s.running[id]; cancel != nil {
		cancel()
		return nil
	}
	return ErrNotFound
}
func (s *Service) Find(id string) (Finding, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data.Findings[id]
	e.Reasons = slices.Clone(e.Reasons)
	return e.Finding, ok
}

// VisibleFind applies the same peer redaction as the list endpoint. A caller
// cannot infer a hidden reuse risk by constructing a deterministic finding ID.
func (s *Service) VisibleFind(id string, visible func(Ref) bool, current func(Finding) bool) (Finding, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data.Findings[id]
	if !ok {
		return Finding{}, false
	}
	return s.publicFinding(e, visible, current, map[string]*visibleGroup{})
}

type visibleGroup struct {
	members []Member
	counts  map[string]int
	peers   map[string][]Ref
}

func (s *Service) visibleMembers(id string, visible func(Ref) bool, groups map[string]*visibleGroup) *visibleGroup {
	g := groups[id]
	if g != nil {
		return g
	}
	source := s.data.Groups[id]
	g = &visibleGroup{members: make([]Member, 0, len(source)), counts: map[string]int{}, peers: map[string][]Ref{}}
	for _, r := range source {
		if visible == nil || visible(r.Ref) {
			g.members = append(g.members, r)
			g.counts[r.Identity]++
		}
	}
	groups[id] = g
	return g
}

func (s *Service) publicFinding(e entry, visible func(Ref) bool, current func(Finding) bool, groups map[string]*visibleGroup) (Finding, bool) {
	f := e.Finding
	if visible != nil && !visible(f.Ref) {
		return Finding{}, false
	}
	f.Reasons = slices.Clone(f.Reasons)
	f.Peers = []Ref{}
	f.PeerCount = 0
	if e.GroupID != "" {
		g := s.visibleMembers(e.GroupID, visible, groups)
		f.PeerCount = len(g.members) - g.counts[e.Identity]
		peers, ok := g.peers[e.Identity]
		if !ok {
			peers = []Ref{}
			for _, r := range g.members {
				if r.Identity != e.Identity {
					peers = append(peers, r.Ref)
					if len(peers) == 20 {
						break
					}
				}
			}
			g.peers[e.Identity] = peers
		}
		f.Peers = slices.Clone(peers)
	}
	if e.GroupID != "" && f.PeerCount == 0 {
		return Finding{}, false
	}
	if current != nil {
		f.Outdated = !current(f)
	}
	f.Outdated = f.Outdated || f.PolicyRevision != s.data.Policy.Revision
	return f, true
}
func (s *Service) Review(id string, revision int, action, note string, actor Actor) (Finding, error) {
	if !validActor(actor) || !validText(note, 2048) || !slices.Contains([]string{"confirm", "ignore", "reopen"}, action) {
		return Finding{}, ErrInvalid
	}
	var out Finding
	e := s.mutate(func(d *state) error {
		v, ok := d.Findings[id]
		if !ok {
			return ErrNotFound
		}
		if v.Revision != revision || v.State == "resolved" || v.PolicyRevision != d.Policy.Revision {
			return ErrConflict
		}
		if len(d.Audit) >= maxAudit {
			return ErrCapacity
		}
		next := map[string]string{"confirm": "confirmed", "ignore": "ignored", "reopen": "open"}[action]
		before := v.State
		v.State = next
		v.Note = note
		v.Revision++
		d.Findings[id] = v
		out = v.Finding
		d.Audit = append(d.Audit, Audit{At: s.now().UTC(), Actor: actor, Action: action, FindingID: id, Before: before, After: next})
		return nil
	})
	return out, e
}
func (s *Service) List(q Query, visible func(Ref) bool, current func(Finding) bool) (Page, error) {
	if q.Limit > 200 {
		return Page{}, ErrInvalid
	}
	return s.listPage(q, visible, current)
}
func (s *Service) Export(q Query, visible func(Ref) bool, current func(Finding) bool) (Page, error) {
	q.Offset = 0
	q.Limit = maxFindings
	return s.listPage(q, visible, current)
}
func (s *Service) listPage(q Query, visible func(Ref) bool, current func(Finding) bool) (Page, error) {
	if q.Offset < 0 || q.Limit < 1 || q.Limit > maxFindings || len(q.Search) > 128 || q.Kind != "" && !slices.Contains(kinds, q.Kind) || q.State != "" && !slices.Contains([]string{"open", "confirmed", "ignored", "resolved"}, q.State) {
		return Page{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.data.Findings))
	groups := map[string]*visibleGroup{}
	for id, e := range s.data.Findings {
		f := e.Finding
		if q.State != "" && q.State != f.State || q.Kind != "" && q.Kind != f.Kind || q.AssetID != "" && q.AssetID != f.AssetID || q.Search != "" && !strings.Contains(strings.ToLower(f.AssetName+" "+f.Username), strings.ToLower(q.Search)) {
			continue
		}
		if visible != nil && !visible(f.Ref) {
			continue
		}
		if e.GroupID != "" {
			g := s.visibleMembers(e.GroupID, visible, groups)
			if len(g.members) == g.counts[e.Identity] {
				continue
			}
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := s.data.Findings[ids[i]], s.data.Findings[ids[j]]
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		return ids[i] < ids[j]
	})
	total := len(ids)
	offset := min(q.Offset, total)
	selected := ids[offset:min(total, offset+q.Limit)]
	out := make([]Finding, 0, len(selected))
	for _, id := range selected {
		f, _ := s.publicFinding(s.data.Findings[id], visible, current, groups)
		out = append(out, f)
	}
	return Page{out, total}, nil
}
func (s *Service) KnownUsage() map[string]Usage {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]Usage{}
	for id, u := range s.data.Usage {
		out[id] = u
	}
	return out
}
func (s *Service) ScanRecord(id string) (Scan, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.data.Scans {
		if v.ID == id {
			return v, true
		}
	}
	return Scan{}, false
}
func (s *Service) Scans(offset, limit int) ([]Scan, int, error) {
	if offset < 0 || limit < 1 || limit > 100 {
		return nil, 0, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := slices.Clone(s.data.Scans)
	slices.Reverse(out)
	total := len(out)
	offset = min(offset, total)
	return out[offset:min(total, offset+limit)], total, nil
}
func (s *Service) Audit(offset, limit int) ([]Audit, int, error) {
	if offset < 0 || limit < 1 || limit > 100 {
		return nil, 0, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := slices.Clone(s.data.Audit)
	slices.Reverse(out)
	total := len(out)
	offset = min(offset, total)
	return out[offset:min(total, offset+limit)], total, nil
}
