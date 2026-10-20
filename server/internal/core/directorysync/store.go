// Package directorysync persists complete LDAP snapshots and the ownership of
// automatic group/organization memberships separately from manual assignments.
package directorysync

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
	"regexp"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/ldapclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/groups"
	"github.com/neko233-com/jumpserver233/server/internal/core/identityscope"
	"github.com/neko233-com/jumpserver233/server/internal/core/identitysources"
	"github.com/neko233-com/jumpserver233/server/internal/core/ldaplogin"
	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
)

var (
	ErrInvalid     = errors.New("invalid directory synchronization")
	ErrConflict    = errors.New("directory synchronization revision or request conflicts")
	ErrPending     = errors.New("directory synchronization requires retry or abort")
	ErrUnavailable = errors.New("directory synchronization unavailable")
	ErrCapacity    = errors.New("directory synchronization capacity reached")
)

const maxBytes = 32 << 20

var requestPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,100}$`)

type Mapping struct {
	DirectoryGroupDN string   `json:"directory_group_dn"`
	GroupIDs         []string `json:"group_ids"`
	OrganizationID   string   `json:"organization_id,omitempty"`
	OrganizationRole string   `json:"organization_role,omitempty"`
}
type Config struct {
	ldapclient.ScanOptions
	Mappings        []Mapping `json:"mappings"`
	MissingAction   string    `json:"missing_action"`
	IntervalMinutes int       `json:"interval_minutes"`
	Revision        int       `json:"revision"`
}
type ConfigInput struct {
	Config
	RequestID string `json:"request_id"`
}
type Operation struct {
	RequestID string `json:"request_id"`
	Revision  int    `json:"revision"`
	PreviewID string `json:"preview_id,omitempty"`
}
type Entry struct {
	Subject       string            `json:"subject"`
	UserID        string            `json:"user_id"`
	Username      string            `json:"username"`
	GroupIDs      []string          `json:"group_ids"`
	Organizations map[string]string `json:"organizations"`
	MissingCount  int               `json:"missing_count"`
	Suspended     bool              `json:"suspended"`
}
type Preview struct {
	ID             string               `json:"id"`
	SourceID       string               `json:"source_id"`
	Revision       int                  `json:"revision"`
	SourceRevision int                  `json:"source_revision"`
	At             time.Time            `json:"at"`
	ExpiresAt      time.Time            `json:"expires_at"`
	Result         ldaplogin.ScanResult `json:"result"`
	Issuer         string               `json:"issuer"`
}
type Run struct {
	ID        string    `json:"id"`
	SourceID  string    `json:"source_id"`
	ActorID   string    `json:"actor_id"`
	RequestID string    `json:"request_id"`
	PreviewID string    `json:"preview_id"`
	Revision  int       `json:"revision"`
	State     string    `json:"state"`
	At        time.Time `json:"at"`
	UpdatedAt time.Time `json:"updated_at"`
	Users     int       `json:"users"`
}
type Audit struct {
	At       time.Time `json:"at"`
	SourceID string    `json:"source_id"`
	ActorID  string    `json:"actor_id"`
	Action   string    `json:"action"`
	Revision int       `json:"revision"`
}
type receipt struct {
	ActorID, RequestID, Hash, SourceID, Action, ResultID string
	Config                                               *Config `json:"config,omitempty"`
	Run                                                  *Run    `json:"run,omitempty"`
}
type state struct {
	Configs       map[string]Config    `json:"configs"`
	Previews      map[string]Preview   `json:"previews"`
	Entries       map[string][]Entry   `json:"entries"`
	Runs          []Run                `json:"runs"`
	Receipts      []receipt            `json:"receipts"`
	Audit         []Audit              `json:"audit"`
	LastScheduled map[string]time.Time `json:"last_scheduled"`
}
type envelope struct {
	Version           int `json:"version"`
	Nonce, Ciphertext []byte
}
type membershipIndex struct {
	Groups        map[string]map[string]bool
	Organizations map[string]map[string]organizations.Member
}
type Store struct {
	mu              sync.Mutex
	path            string
	docs            *storage.Documents
	aead            cipher.AEAD
	sources         *identitysources.Store
	identities      *auth.Service
	groups          *groups.Store
	organizations   *organizations.Store
	data            state
	index           atomic.Pointer[membershipIndex]
	lifetime        context.Context
	cancel          context.CancelFunc
	operations      sync.WaitGroup
	closed, started bool
	done            chan struct{}
	slots           chan struct{}
}

func clone[T any](v T) T { b, _ := json.Marshal(v); var out T; _ = json.Unmarshal(b, &out); return out }
func hash(v any) string {
	b, _ := json.Marshal(v)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}
func randomID(prefix string) (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return prefix + hex.EncodeToString(b[:]), nil
}
func validConfig(c Config) bool {
	if c.Revision < 0 || c.Revision > 1_000_000_000 || ldapclient.ValidateScan(c.ScanOptions) != nil || len(c.Mappings) > 200 || c.MissingAction != "keep" && c.MissingAction != "remove" && c.MissingAction != "disable" || c.IntervalMinutes != 0 && (c.IntervalMinutes < 15 || c.IntervalMinutes > 10080) {
		return false
	}
	keys := map[string]bool{}
	for _, m := range c.Mappings {
		k, e := ldapclient.DNKey(m.DirectoryGroupDN)
		if e != nil || keys[k] || len(m.GroupIDs) > 64 || m.OrganizationID == "" && m.OrganizationRole != "" || m.OrganizationID != "" && (!organizations.ValidID(m.OrganizationID) || m.OrganizationRole != "member" && m.OrganizationRole != "auditor" && m.OrganizationRole != "admin") {
			return false
		}
		keys[k] = true
		seen := map[string]bool{}
		for _, id := range m.GroupIDs {
			if id == "" || len(id) > 128 || seen[id] {
				return false
			}
			seen[id] = true
		}
		if len(m.GroupIDs) == 0 && m.OrganizationID == "" {
			return false
		}
	}
	return true
}
func validate(st state) error {
	if st.Configs == nil || st.Previews == nil || st.Entries == nil || st.LastScheduled == nil || len(st.Configs) > 100 || len(st.Previews) > 100 || len(st.Entries) > 100 || len(st.Runs) > 1000 || len(st.Receipts) > 4000 || len(st.Audit) > 2000 {
		return ErrInvalid
	}
	total := 0
	for id, c := range st.Configs {
		if !identityscope.ValidID(id) || !validConfig(c) || c.Revision < 1 {
			return ErrInvalid
		}
	}
	for source, entries := range st.Entries {
		if !identityscope.ValidID(source) || len(entries) > 10000 {
			return ErrInvalid
		}
		seen := map[string]bool{}
		for _, e := range entries {
			total++
			if total > 20000 || e.Subject == "" || len(e.Subject) > 1024 || e.UserID == "" || seen[e.Subject] || len(e.GroupIDs) > 64 || len(e.Organizations) > 100 || e.MissingCount < 0 || e.MissingCount > 2 {
				return ErrInvalid
			}
			seen[e.Subject] = true
		}
	}
	for source, p := range st.Previews {
		if source != p.SourceID || !identityscope.ValidID(source) || p.ID == "" || p.Revision < 1 || p.Result.Revision < 1 || p.Issuer == "" || len(p.Result.Users) > 10000 || len(p.Result.Groups) > 2000 || p.At.IsZero() || !p.ExpiresAt.After(p.At) {
			return ErrInvalid
		}
	}
	pending := map[string]bool{}
	for _, run := range st.Runs {
		if !identityscope.ValidID(run.SourceID) || run.ID == "" || run.ActorID == "" || !requestPattern.MatchString(run.RequestID) || run.State != "applying" && run.State != "completed" && run.State != "aborted" {
			return ErrInvalid
		}
		if run.State == "applying" {
			if pending[run.SourceID] || st.Previews[run.SourceID].ID != run.PreviewID {
				return ErrInvalid
			}
			pending[run.SourceID] = true
		}
	}
	for _, r := range st.Receipts {
		if r.ActorID == "" || !requestPattern.MatchString(r.RequestID) || len(r.Hash) != 64 {
			return ErrInvalid
		}
	}
	return nil
}
func Open(path string, key []byte, docs *storage.Documents, sources *identitysources.Store, identities *auth.Service, groupStore *groups.Store, orgs *organizations.Store) (*Store, error) {
	if sources == nil || identities == nil || groupStore == nil || orgs == nil {
		return nil, ErrInvalid
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Store{path: path, docs: docs, aead: a, sources: sources, identities: identities, groups: groupStore, organizations: orgs, lifetime: ctx, cancel: cancel, done: make(chan struct{}), slots: make(chan struct{}, 4), data: state{Configs: map[string]Config{}, Previews: map[string]Preview{}, Entries: map[string][]Entry{}, LastScheduled: map[string]time.Time{}, Runs: []Run{}, Receipts: []receipt{}, Audit: []Audit{}}}
	var raw []byte
	if docs != nil {
		raw, e = docs.LoadOrImport("directory-sync", path)
	} else {
		var f *os.File
		f, e = os.Open(path)
		if e == nil {
			raw, e = io.ReadAll(io.LimitReader(f, 2*maxBytes+1))
			_ = f.Close()
		} else if errors.Is(e, os.ErrNotExist) {
			e = nil
		}
	}
	if e != nil {
		cancel()
		return nil, e
	}
	if len(raw) > 0 {
		var box envelope
		if len(raw) > 2*maxBytes || json.Unmarshal(raw, &box) != nil || box.Version != 1 || len(box.Nonce) != a.NonceSize() {
			cancel()
			return nil, ErrInvalid
		}
		plain, err := a.Open(nil, box.Nonce, box.Ciphertext, []byte("jms233/directory-sync/v1"))
		if err != nil || len(plain) > maxBytes || json.Unmarshal(plain, &s.data) != nil || validate(s.data) != nil {
			cancel()
			return nil, ErrInvalid
		}
	}
	s.publish()
	for _, run := range s.data.Runs {
		if run.State == "applying" {
			_, runtime, ok := sources.Get(run.SourceID)
			if ok {
				runtime.SetSyncBlocked(true)
			}
		}
	}
	groupStore.SetManagedMemberships(s.GroupMembers, s.GroupContains)
	orgs.SetManagedMemberships(s.OrganizationMembers, s.OrganizationRole, s.OrganizationMember)
	return s, nil
}
func (s *Store) persist(st state) error {
	if e := validate(st); e != nil {
		return e
	}
	plain, e := json.Marshal(st)
	if e != nil {
		return e
	}
	if len(plain) > maxBytes {
		return ErrCapacity
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	raw, e := json.Marshal(envelope{1, nonce, s.aead.Seal(nil, nonce, plain, []byte("jms233/directory-sync/v1"))})
	if e != nil {
		return e
	}
	if s.docs != nil {
		return s.docs.Save("directory-sync", raw)
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".directory-sync-*")
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
func (s *Store) commit(st state, audit Audit) error {
	compactScheduled(&st)
	st.Audit = append(st.Audit, audit)
	if len(st.Audit) > 2000 {
		st.Audit = st.Audit[len(st.Audit)-2000:]
	}
	if e := s.persist(st); e != nil {
		return e
	}
	s.data = st
	return nil
}

// Compact only terminal scheduler-owned receipts. Pending intents and every
// human request retain their idempotency receipts; recurring work cannot fill
// the manual request budget within a few days.
func compactScheduled(st *state) {
	counts := map[string]int{}
	keepRuns := map[string]bool{}
	kept := []Run{}
	for i := len(st.Runs) - 1; i >= 0; i-- {
		run := st.Runs[i]
		if run.ActorID != "directory-scheduler" || run.State == "applying" || counts[run.SourceID] < 20 {
			kept = append(kept, run)
			keepRuns[run.ID] = true
			if run.ActorID == "directory-scheduler" {
				counts[run.SourceID]++
			}
		}
	}
	slices.Reverse(kept)
	st.Runs = kept
	previews := map[string]int{}
	receipts := []receipt{}
	for i := len(st.Receipts) - 1; i >= 0; i-- {
		r := st.Receipts[i]
		retain := r.ActorID != "directory-scheduler" || r.Action == "apply" && keepRuns[r.ResultID]
		if r.ActorID == "directory-scheduler" && r.Action == "preview" {
			retain = previews[r.SourceID] < 20 || st.Previews[r.SourceID].ID == r.ResultID
			previews[r.SourceID]++
		}
		if retain {
			receipts = append(receipts, r)
		}
	}
	slices.Reverse(receipts)
	st.Receipts = receipts
}
func (s *Store) find(actor, request, digest string) (receipt, bool, error) {
	for _, r := range s.data.Receipts {
		if r.ActorID == actor && r.RequestID == request {
			if r.Hash != digest {
				return receipt{}, true, ErrConflict
			}
			return r, true, nil
		}
	}
	return receipt{}, false, nil
}
func (s *Store) pending(source string) int {
	for i, run := range s.data.Runs {
		if run.SourceID == source && run.State == "applying" {
			return i
		}
	}
	return -1
}
func defaultConfig() Config {
	return Config{ScanOptions: ldapclient.ScanOptions{UserFilter: "(objectClass=person)", UsernameAttribute: "uid"}, Mappings: []Mapping{}, MissingAction: "keep"}
}
func (s *Store) Config(source string) Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.data.Configs[source]; ok {
		return clone(c)
	}
	return defaultConfig()
}
func (s *Store) validTargets(c Config) error {
	for _, m := range c.Mappings {
		for _, id := range m.GroupIDs {
			if _, e := s.groups.Get(id); e != nil {
				return ErrInvalid
			}
		}
		if m.OrganizationID != "" && !s.organizations.Enabled(m.OrganizationID) {
			return ErrInvalid
		}
	}
	return nil
}
func (s *Store) SaveConfig(source, actor string, in ConfigInput) (Config, error) {
	digest := hash([]any{"config", source, in})
	if !identityscope.ValidID(source) || actor == "" || !requestPattern.MatchString(in.RequestID) || !validConfig(in.Config) {
		return Config{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Config{}, ErrUnavailable
	}
	if r, found, e := s.find(actor, in.RequestID, digest); found {
		if e != nil {
			return Config{}, e
		}
		if r.Config == nil {
			return Config{}, ErrConflict
		}
		return clone(*r.Config), nil
	}
	if len(s.data.Receipts) >= 4000 {
		return Config{}, ErrCapacity
	}
	src, _, ok := s.sources.Get(source)
	if !ok || src.Kind != "ldap" || src.Archived {
		return Config{}, ErrInvalid
	}
	if s.pending(source) >= 0 {
		return Config{}, ErrPending
	}
	if s.data.Configs[source].Revision != in.Revision {
		return Config{}, ErrConflict
	}
	if e := s.validTargets(in.Config); e != nil {
		return Config{}, e
	}
	config := clone(in.Config)
	config.Revision++
	next := clone(s.data)
	next.Configs[source] = config
	delete(next.Previews, source)
	delete(next.LastScheduled, source)
	next.Receipts = append(next.Receipts, receipt{ActorID: actor, RequestID: in.RequestID, Hash: digest, SourceID: source, Action: "config", Config: &config})
	if e := s.commit(next, Audit{time.Now().UTC(), source, actor, "config", config.Revision}); e != nil {
		return Config{}, e
	}
	return clone(config), nil
}
func (s *Store) begin(ctx context.Context) (context.Context, func(), error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, nil, ErrUnavailable
	}
	s.operations.Add(1)
	s.mu.Unlock()
	operation, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.lifetime, cancel)
	return operation, func() { stop(); cancel(); s.operations.Done() }, nil
}
func (s *Store) Preview(ctx context.Context, source, actor string, in Operation) (Preview, error) {
	ctx, finish, e := s.begin(ctx)
	if e != nil {
		return Preview{}, e
	}
	defer finish()
	ctx, release, e := workgate.FromContext(ctx).Enter(ctx, "directory_sync")
	if e != nil {
		return Preview{}, e
	}
	defer release()
	if actor == "" || !identityscope.ValidID(source) || !requestPattern.MatchString(in.RequestID) || in.PreviewID != "" {
		return Preview{}, ErrInvalid
	}
	digest := hash([]any{"preview", source, in})
	s.mu.Lock()
	if r, found, err := s.find(actor, in.RequestID, digest); found {
		p, ok := s.data.Previews[source]
		s.mu.Unlock()
		if err != nil {
			return Preview{}, err
		}
		if !ok || p.ID != r.ResultID || !time.Now().Before(p.ExpiresAt) {
			return Preview{}, ErrConflict
		}
		return clone(p), nil
	}
	config, configured := s.data.Configs[source]
	if !configured || config.Revision != in.Revision {
		s.mu.Unlock()
		return Preview{}, ErrConflict
	}
	if s.pending(source) >= 0 {
		s.mu.Unlock()
		return Preview{}, ErrPending
	}
	s.mu.Unlock()
	src, runtime, ok := s.sources.Get(source)
	if !ok || src.Kind != "ldap" || !runtime.Active() {
		return Preview{}, ErrUnavailable
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return Preview{}, ErrCapacity
	}
	result, e := runtime.LDAP.Scan(ctx, config.ScanOptions)
	if e != nil {
		return Preview{}, e
	}
	if e = ctx.Err(); e != nil {
		return Preview{}, e
	}
	id, e := randomID("preview-")
	if e != nil {
		return Preview{}, e
	}
	now := time.Now().UTC()
	preview := Preview{id, source, config.Revision, src.Revision, now, now.Add(10 * time.Minute), result, result.Issuer}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Preview{}, ErrUnavailable
	}
	if s.data.Configs[source].Revision != config.Revision || s.pending(source) >= 0 {
		return Preview{}, ErrConflict
	}
	current, _, ok := s.sources.Get(source)
	if !ok || current.Revision != src.Revision || !runtime.Active() || runtime.LDAP.Snapshot().Revision != result.Revision {
		return Preview{}, ErrConflict
	}
	if r, found, err := s.find(actor, in.RequestID, digest); found {
		if err != nil {
			return Preview{}, err
		}
		if p := s.data.Previews[source]; p.ID == r.ResultID {
			return clone(p), nil
		}
		return Preview{}, ErrConflict
	}
	if len(s.data.Receipts) >= 4000 {
		return Preview{}, ErrCapacity
	}
	next := clone(s.data)
	next.Previews[source] = preview
	next.Receipts = append(next.Receipts, receipt{ActorID: actor, RequestID: in.RequestID, Hash: digest, SourceID: source, Action: "preview", ResultID: id})
	if e = s.commit(next, Audit{now, source, actor, "preview", config.Revision}); e != nil {
		return Preview{}, e
	}
	return clone(preview), nil
}
func (s *Store) Apply(ctx context.Context, source, actor string, in Operation) (Run, error) {
	ctx, finish, e := s.begin(ctx)
	if e != nil {
		return Run{}, e
	}
	defer finish()
	_, release, e := workgate.FromContext(ctx).Enter(ctx, "directory_sync")
	if e != nil {
		return Run{}, e
	}
	defer release()
	if actor == "" || !requestPattern.MatchString(in.RequestID) || !identityscope.ValidID(source) || in.PreviewID == "" {
		return Run{}, ErrInvalid
	}
	digest := hash([]any{"apply", source, in})
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Run{}, ErrUnavailable
	}
	if r, found, err := s.find(actor, in.RequestID, digest); found {
		if err != nil {
			return Run{}, err
		}
		if r.Run == nil {
			return Run{}, ErrConflict
		}
		return *r.Run, nil
	}
	config, ok := s.data.Configs[source]
	p := s.data.Previews[source]
	pending := s.pending(source)
	if !ok || config.Revision != in.Revision || p.ID != in.PreviewID {
		return Run{}, ErrConflict
	}
	src, runtime, ok := s.sources.Get(source)
	if !ok || !runtime.Active() || runtime.LDAP == nil || !runtime.LDAP.IssuerAllowed(p.Issuer) || runtime.LDAP.Snapshot().Revision != p.Result.Revision {
		return Run{}, ErrConflict
	}
	var run Run
	if pending >= 0 {
		run = s.data.Runs[pending]
		if run.ActorID != actor || run.RequestID != in.RequestID || run.PreviewID != in.PreviewID {
			return Run{}, ErrPending
		}
	} else {
		if src.Revision != p.SourceRevision || !time.Now().Before(p.ExpiresAt) {
			return Run{}, ErrConflict
		}
		if len(s.data.Receipts) >= 4000 || len(s.data.Runs) >= 1000 {
			return Run{}, ErrCapacity
		}
		if e = s.validTargets(config); e != nil {
			return Run{}, e
		}
		id, err := randomID("sync-")
		if err != nil {
			return Run{}, err
		}
		now := time.Now().UTC()
		run = Run{id, source, actor, in.RequestID, p.ID, config.Revision, "applying", now, now, 0}
		runtime.SetSyncBlocked(true)
		next := clone(s.data)
		next.Runs = append(next.Runs, run)
		if e = s.commit(next, Audit{now, source, actor, "applying", config.Revision}); e != nil {
			runtime.SetSyncBlocked(false)
			return Run{}, e
		}
		pending = len(s.data.Runs) - 1
	}
	// Authentication stays blocked until both identity state and the authoritative
	// membership snapshot are durable. A crash retries the same pending intent.
	runtime.SetSyncBlocked(true)
	if e = ctx.Err(); e != nil {
		return Run{}, e
	}
	subjects := make([]string, 0, len(p.Result.Users))
	for _, u := range p.Result.Users {
		subjects = append(subjects, u.Subject)
	}
	users, e := s.identities.EnsureNamedDirectoryUsers(source, p.Issuer, subjects)
	if e != nil {
		return Run{}, e
	}
	entries, e := mappedEntries(config, p.Result.DirectorySnapshot, users, s.data.Entries[source])
	if e != nil {
		return Run{}, e
	}
	statuses := map[string]bool{}
	for _, entry := range entries {
		statuses[entry.UserID] = entry.Suspended
	}
	if e = s.identities.SetNamedDirectorySuspensions(source, statuses); e != nil {
		return Run{}, e
	}
	next := clone(s.data)
	next.Entries[source] = entries
	run.State = "completed"
	run.UpdatedAt = time.Now().UTC()
	run.Users = len(p.Result.Users)
	next.Runs[pending] = run
	next.Receipts = append(next.Receipts, receipt{ActorID: actor, RequestID: in.RequestID, Hash: digest, SourceID: source, Action: "apply", ResultID: run.ID, Run: &run})
	delete(next.Previews, source)
	if e = s.commit(next, Audit{run.UpdatedAt, source, actor, "completed", config.Revision}); e != nil {
		return Run{}, e
	}
	s.publish()
	runtime.SetSyncBlocked(false)
	return run, nil
}
func mappedEntries(config Config, snapshot ldapclient.DirectorySnapshot, users map[string]auth.User, previous []Entry) ([]Entry, error) {
	compiled := map[string]Mapping{}
	dnKeys := map[string]string{}
	for _, mapping := range config.Mappings {
		key, e := ldapclient.DNKey(mapping.DirectoryGroupDN)
		if e != nil {
			return nil, ErrInvalid
		}
		compiled[key] = mapping
		dnKeys[mapping.DirectoryGroupDN] = key
	}
	old := map[string]Entry{}
	for _, row := range previous {
		old[row.Subject] = row
	}
	out := []Entry{}
	for _, u := range snapshot.Users {
		user, ok := users[u.Subject]
		if !ok {
			return nil, ErrInvalid
		}
		row := Entry{Subject: u.Subject, UserID: user.ID, Username: u.Username, GroupIDs: []string{}, Organizations: map[string]string{}, Suspended: u.Disabled}
		delete(old, u.Subject)
		if !u.Disabled {
			ids := map[string]bool{}
			for _, dn := range u.Groups {
				key, known := dnKeys[dn]
				if !known {
					var e error
					key, e = ldapclient.DNKey(dn)
					if e != nil {
						return nil, ErrInvalid
					}
					dnKeys[dn] = key
				}
				m, exists := compiled[key]
				if !exists {
					continue
				}
				for _, id := range m.GroupIDs {
					ids[id] = true
				}
				if m.OrganizationID != "" {
					oldRole := row.Organizations[m.OrganizationID]
					if rank(m.OrganizationRole) > rank(oldRole) {
						row.Organizations[m.OrganizationID] = m.OrganizationRole
					}
				}
			}
			for id := range ids {
				row.GroupIDs = append(row.GroupIDs, id)
			}
			sort.Strings(row.GroupIDs)
			if len(row.GroupIDs) > 64 {
				return nil, ErrCapacity
			}
		}
		out = append(out, row)
	}
	for _, row := range old {
		row.MissingCount = min(2, row.MissingCount+1)
		if config.MissingAction != "keep" {
			row.GroupIDs = []string{}
			row.Organizations = map[string]string{}
		}
		if config.MissingAction == "disable" && row.MissingCount >= 2 {
			row.Suspended = true
		}
		out = append(out, row)
	}
	if len(out) > 10000 {
		return nil, ErrCapacity
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Subject < out[j].Subject })
	return out, nil
}
func rank(role string) int {
	switch role {
	case "member":
		return 1
	case "auditor":
		return 2
	case "admin":
		return 3
	}
	return 0
}
func (s *Store) Abort(ctx context.Context, source, actor string, in Operation) (Run, error) {
	ctx, finish, e := s.begin(ctx)
	if e != nil {
		return Run{}, e
	}
	defer finish()
	_, release, e := workgate.FromContext(ctx).Enter(ctx, "directory_sync")
	if e != nil {
		return Run{}, e
	}
	defer release()
	if actor == "" || !requestPattern.MatchString(in.RequestID) || !identityscope.ValidID(source) {
		return Run{}, ErrInvalid
	}
	digest := hash([]any{"abort", source, in})
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, found, err := s.find(actor, in.RequestID, digest); found {
		if err != nil {
			return Run{}, err
		}
		if r.Run == nil {
			return Run{}, ErrConflict
		}
		return *r.Run, nil
	}
	index := s.pending(source)
	if index < 0 || s.data.Configs[source].Revision != in.Revision || s.data.Runs[index].PreviewID != in.PreviewID {
		return Run{}, ErrConflict
	}
	if len(s.data.Receipts) >= 4000 {
		return Run{}, ErrCapacity
	}
	_, runtime, ok := s.sources.Get(source)
	if !ok {
		return Run{}, ErrUnavailable
	}
	runtime.SetSyncBlocked(true)
	if e = s.identities.SuspendNamedDirectorySource(source); e != nil {
		return Run{}, e
	}
	runtime.InvalidateFlows()
	next := clone(s.data)
	run := next.Runs[index]
	run.State = "aborted"
	run.UpdatedAt = time.Now().UTC()
	next.Runs[index] = run
	delete(next.Entries, source)
	delete(next.Previews, source)
	next.Receipts = append(next.Receipts, receipt{ActorID: actor, RequestID: in.RequestID, Hash: digest, SourceID: source, Action: "abort", Run: &run})
	if e = s.commit(next, Audit{run.UpdatedAt, source, actor, "aborted", run.Revision}); e != nil {
		return Run{}, e
	}
	s.publish()
	runtime.SetSyncBlocked(false)
	return run, nil
}
func (s *Store) publish() {
	index := &membershipIndex{Groups: map[string]map[string]bool{}, Organizations: map[string]map[string]organizations.Member{}}
	updated := map[string]time.Time{}
	for _, run := range s.data.Runs {
		if run.State == "completed" && run.UpdatedAt.After(updated[run.SourceID]) {
			updated[run.SourceID] = run.UpdatedAt
		}
	}
	for source, entries := range s.data.Entries {
		for _, row := range entries {
			if row.Suspended {
				continue
			}
			for _, id := range row.GroupIDs {
				if index.Groups[id] == nil {
					index.Groups[id] = map[string]bool{}
				}
				index.Groups[id][row.UserID] = true
			}
			for id, role := range row.Organizations {
				if index.Organizations[id] == nil {
					index.Organizations[id] = map[string]organizations.Member{}
				}
				index.Organizations[id][row.UserID] = organizations.Member{MemberInput: organizations.MemberInput{UserID: row.UserID, Role: role, Revision: 0}, SourceID: source, UpdatedAt: updated[source]}
			}
		}
	}
	s.index.Store(index)
}
func (s *Store) GroupMembers(group string) []string {
	index := s.index.Load()
	out := []string{}
	if index != nil {
		for user := range index.Groups[group] {
			out = append(out, user)
		}
	}
	sort.Strings(out)
	return out
}
func (s *Store) GroupContains(group, user string) bool {
	index := s.index.Load()
	return index != nil && index.Groups[group][user]
}
func (s *Store) OrganizationMembers(org string) map[string]organizations.Member {
	index := s.index.Load()
	out := map[string]organizations.Member{}
	if index != nil {
		for id, m := range index.Organizations[org] {
			out[id] = m
		}
	}
	return out
}
func (s *Store) OrganizationRole(org, user string) string {
	index := s.index.Load()
	if index != nil {
		return index.Organizations[org][user].Role
	}
	return ""
}
func (s *Store) OrganizationMember(org, user string) (organizations.Member, bool) {
	index := s.index.Load()
	if index != nil {
		member, ok := index.Organizations[org][user]
		return member, ok
	}
	return organizations.Member{}, false
}
func (s *Store) Entries(source string) []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return clone(s.data.Entries[source])
}
func (s *Store) Runs(source string) []Run {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Run{}
	for i := len(s.data.Runs) - 1; i >= 0; i-- {
		if s.data.Runs[i].SourceID == source {
			out = append(out, s.data.Runs[i])
		}
	}
	return out
}
func (s *Store) Audit(source string) []Audit {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Audit{}
	for i := len(s.data.Audit) - 1; i >= 0; i-- {
		if s.data.Audit[i].SourceID == source {
			out = append(out, s.data.Audit[i])
		}
	}
	return out
}
func (s *Store) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.cancel()
	started := s.started
	s.mu.Unlock()
	if started {
		<-s.done
	}
	s.operations.Wait()
}
func (s *Store) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrUnavailable
	}
	if s.started {
		return nil
	}
	s.started = true
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-s.lifetime.Done():
				return
			case <-ticker.C:
				s.schedule(ctx)
			}
		}
	}()
	return nil
}
func (s *Store) schedule(ctx context.Context) {
	s.mu.Lock()
	configs := clone(s.data.Configs)
	runs := slices.Clone(s.data.Runs)
	last := clone(s.data.LastScheduled)
	s.mu.Unlock()
	for _, run := range runs {
		if run.State == "applying" {
			_, _ = s.Apply(ctx, run.SourceID, run.ActorID, Operation{run.RequestID, run.Revision, run.PreviewID})
		}
	}
	now := time.Now().UTC()
	for source, c := range configs {
		if c.IntervalMinutes == 0 || now.Sub(last[source]) < time.Duration(c.IntervalMinutes)*time.Minute {
			continue
		}
		src, runtime, ok := s.sources.Get(source)
		if !ok || src.Archived || !runtime.Ready() {
			continue
		}
		request, e := randomID("schedule-")
		if e != nil {
			continue
		}
		s.mu.Lock()
		if s.closed || s.pending(source) >= 0 {
			s.mu.Unlock()
			continue
		}
		next := clone(s.data)
		next.LastScheduled[source] = now
		e = s.persist(next)
		if e == nil {
			s.data = next
		}
		s.mu.Unlock()
		if e != nil {
			continue
		}
		p, e := s.Preview(ctx, source, "directory-scheduler", Operation{RequestID: request, Revision: c.Revision})
		if e == nil {
			_, _ = s.Apply(ctx, source, "directory-scheduler", Operation{RequestID: request + "-apply", Revision: c.Revision, PreviewID: p.ID})
		}
	}
}
