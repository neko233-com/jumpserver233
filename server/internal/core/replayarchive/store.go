// Package replayarchive owns durable, organization-scoped encrypted replay archives.
// It does not grant access to session content; callers must authorize the session.
package replayarchive

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/neko233-com/jumpserver233/server/internal/connector/replaystore"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

var (
	ErrInvalid     = errors.New("invalid replay archive request")
	ErrConflict    = errors.New("replay archive revision or request conflicts")
	ErrNotFound    = errors.New("replay archive not found")
	ErrUnavailable = errors.New("replay archive unavailable")
	ErrIntegrity   = errors.New("replay archive integrity mismatch")
	ErrCapacity    = errors.New("replay archive capacity reached")
	ErrClosed      = errors.New("replay archive closed")
)

const maxStateBytes = 32 << 20
const maxRecords = 20000

var sessionPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
var requestPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,100}$`)

type Config struct {
	Provider      string                   `json:"provider"`
	Enabled       bool                     `json:"enabled"`
	Prefix        string                   `json:"prefix"`
	Cloud         *replaystore.CloudConfig `json:"cloud,omitempty"`
	SFTPAssetID   string                   `json:"sftp_asset_id,omitempty"`
	SFTPDirectory string                   `json:"sftp_directory,omitempty"`
	// SFTPTarget is a server-resolved digest of the pinned host, route and workspace.
	SFTPTarget      string    `json:"sftp_target,omitempty"`
	Revision        int       `json:"revision"`
	UpdatedAt       time.Time `json:"updated_at,omitzero"`
	HasSecret       bool      `json:"has_secret"`
	HasSessionToken bool      `json:"has_session_token"`
}
type Input struct {
	Config
	RequestID         string `json:"request_id"`
	ClearSessionToken bool   `json:"clear_session_token,omitempty"`
}
type Ref struct {
	Kind      string `json:"kind"`
	SessionID string `json:"session_id"`
}

func ValidRef(r Ref) bool {
	return (r.Kind == "terminal" || r.Kind == "desktop") && sessionPattern.MatchString(r.SessionID)
}
func refKey(r Ref) string { return r.Kind + ":" + r.SessionID }

type Record struct {
	Ref
	ConfigRevision int       `json:"config_revision"`
	Status         string    `json:"status"`
	Size           int64     `json:"size"`
	SHA256         string    `json:"sha256,omitempty"`
	Attempts       int       `json:"attempts"`
	ErrorCode      string    `json:"error_code,omitempty"`
	QueuedAt       time.Time `json:"queued_at"`
	NextAttempt    time.Time `json:"next_attempt,omitzero"`
	StoredAt       time.Time `json:"stored_at,omitzero"`
	VerifiedAt     time.Time `json:"verified_at,omitzero"`
	LocalEvictedAt time.Time `json:"local_evicted_at,omitzero"`
}
type storedRecord struct {
	Record
	Key string `json:"object_key"`
}
type Audit struct {
	At       time.Time `json:"at"`
	ActorID  string    `json:"actor_id"`
	Action   string    `json:"action"`
	Ref      *Ref      `json:"ref,omitempty"`
	Revision int       `json:"revision"`
}
type receipt struct {
	Actor   string  `json:"actor"`
	Request string  `json:"request"`
	Hash    string  `json:"hash"`
	Config  *Config `json:"config,omitempty"`
	Record  *Record `json:"record,omitempty"`
}
type state struct {
	Revision int                     `json:"revision"`
	History  map[int]Config          `json:"history"`
	Records  map[string]storedRecord `json:"records"`
	Receipts []receipt               `json:"receipts"`
	Audit    []Audit                 `json:"audit"`
}
type envelope struct {
	Version    int    `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

type SeekCloser interface {
	io.Reader
	io.Seeker
	io.Closer
}

// Prepare must authenticate a finalized local recording, return ciphertext at
// offset zero, and remove only its own temporary files when the reader closes.
type Source interface {
	Prepare(context.Context, Ref) (SeekCloser, error)
}
type Factory func(context.Context, Config) (replaystore.Objects, error)
type Store struct {
	mu             sync.Mutex
	path           string
	docs           *storage.Documents
	aead           cipher.AEAD
	hashKey        []byte
	data           state
	source         Source
	factory        Factory
	now            func() time.Time
	busy           map[string]context.CancelFunc
	wake           chan struct{}
	closed         bool
	startOnce      sync.Once
	stop           context.CancelFunc
	lifetime       context.Context
	cancelLifetime context.CancelFunc
	startError     error
	workers        sync.WaitGroup
	operations     sync.WaitGroup
	cache          *cipherCache
}

func cloneConfig(c Config) Config {
	if c.Cloud != nil {
		v := *c.Cloud
		c.Cloud = &v
	}
	return c
}
func publicConfig(c Config) Config {
	c = cloneConfig(c)
	if c.Cloud != nil {
		c.HasSecret = c.Cloud.SecretAccessKey != ""
		c.HasSessionToken = c.Cloud.SessionToken != ""
		c.Cloud.SecretAccessKey = ""
		c.Cloud.SessionToken = ""
	}
	return c
}
func validActor(s string) bool {
	return s != "" && utf8.ValidString(s) && len(s) <= 128 && strings.IndexFunc(s, unicode.IsControl) < 0
}
func location(c Config) string {
	c = cloneConfig(c)
	c.Enabled = false
	c.Revision = 0
	c.UpdatedAt = time.Time{}
	c.HasSecret = false
	c.HasSessionToken = false
	if c.Cloud != nil {
		c.Cloud.AccessKeyID = ""
		c.Cloud.SecretAccessKey = ""
		c.Cloud.SessionToken = ""
		c.Cloud.RootCAPEM = ""
	}
	raw, _ := json.Marshal(c)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func validateConfig(c Config) error {
	if c.Provider == "local" {
		if c.Enabled || c.Cloud != nil || c.SFTPAssetID != "" || c.SFTPDirectory != "" || c.SFTPTarget != "" {
			return ErrInvalid
		}
		return nil
	}
	if !replaystore.ValidKey(c.Prefix) || len(c.Prefix) > 256 {
		return ErrInvalid
	}
	switch c.Provider {
	case "s3", "oss", "cos", "obs":
		if c.Cloud == nil || c.Cloud.Provider != c.Provider || replaystore.ValidateCloud(*c.Cloud, true) != nil || c.SFTPAssetID != "" || c.SFTPDirectory != "" || c.SFTPTarget != "" {
			return ErrInvalid
		}
	case "sftp":
		if c.Cloud != nil || !regexpAssetID.MatchString(c.SFTPAssetID) || !replaystore.ValidKey(c.SFTPDirectory) || len(c.SFTPDirectory) > 256 || !replaystore.ValidDigest(c.SFTPTarget) {
			return ErrInvalid
		}
	case "postgres":
		if c.Cloud != nil || c.SFTPAssetID != "" || c.SFTPDirectory != "" || c.SFTPTarget != "" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

var regexpAssetID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

func validate(st state) error {
	if st.Revision < 0 || st.Revision != len(st.History) || st.History == nil || st.Records == nil || len(st.History) > 1000 || len(st.Records) > maxRecords || len(st.Receipts) > 4000 || len(st.Audit) > 2000 {
		return ErrInvalid
	}
	if st.Revision > 0 {
		if _, ok := st.History[st.Revision]; !ok {
			return ErrInvalid
		}
	}
	for rev, c := range st.History {
		if rev < 1 || rev > st.Revision || c.Revision != rev || c.UpdatedAt.IsZero() || c.HasSecret || c.HasSessionToken || validateConfig(c) != nil {
			return ErrInvalid
		}
	}
	for key, r := range st.Records {
		c, ok := st.History[r.ConfigRevision]
		if !ok || c.Provider == "local" || !ValidRef(r.Ref) || key != refKey(r.Ref) || r.QueuedAt.IsZero() || r.Attempts < 0 || r.Attempts > 10 {
			return ErrInvalid
		}
		if r.Size == 0 {
			if r.SHA256 != "" || r.Key != "" {
				return ErrInvalid
			}
		} else if r.Size < 1 || r.Size > replaystore.MaxObjectBytes || !replaystore.ValidDigest(r.SHA256) || !replaystore.ValidKey(r.Key) {
			return ErrInvalid
		}
		switch r.Status {
		case "queued":
		case "failed":
			if r.Attempts == 0 {
				return ErrInvalid
			}
		case "stored":
			if r.Size == 0 || r.StoredAt.IsZero() || r.VerifiedAt.IsZero() {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
		if r.Status != "stored" && !r.LocalEvictedAt.IsZero() {
			return ErrInvalid
		}
		if r.ErrorCode != "" && r.ErrorCode != "source_unavailable" && r.ErrorCode != "storage_unavailable" && r.ErrorCode != "integrity_mismatch" {
			return ErrInvalid
		}
	}
	seen := map[string]bool{}
	for _, r := range st.Receipts {
		key := r.Actor + "\x00" + r.Request
		if !validActor(r.Actor) || !requestPattern.MatchString(r.Request) || !replaystore.ValidDigest(r.Hash) || seen[key] || (r.Config == nil) == (r.Record == nil) {
			return ErrInvalid
		}
		seen[key] = true
		if r.Config != nil {
			if r.Config.Revision < 1 || r.Config.Revision > st.Revision {
				return ErrInvalid
			}
			expected, _ := json.Marshal(publicConfig(st.History[r.Config.Revision]))
			actual, _ := json.Marshal(r.Config)
			if !bytes.Equal(expected, actual) {
				return ErrInvalid
			}
		}
		if r.Record != nil && !ValidRef(r.Record.Ref) {
			return ErrInvalid
		}
	}
	for _, a := range st.Audit {
		if a.At.IsZero() || !validActor(a.ActorID) || a.Revision < 1 || a.Revision > st.Revision || a.Action != "configure" && a.Action != "archive" && a.Action != "retry" && a.Action != "verify" && a.Action != "evict" || a.Ref != nil && !ValidRef(*a.Ref) {
			return ErrInvalid
		}
	}
	return nil
}
func Open(path string, key []byte, docs *storage.Documents, source Source, factory Factory) (*Store, error) {
	if len(key) != 32 || source == nil || factory == nil {
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
	s := &Store{path: path, docs: docs, aead: a, hashKey: append([]byte(nil), key...), source: source, factory: factory, now: time.Now, busy: map[string]context.CancelFunc{}, wake: make(chan struct{}, 2), cache: newCipherCache(filepath.Join(filepath.Dir(path), "replay-cache")), data: state{History: map[int]Config{}, Records: map[string]storedRecord{}, Receipts: []receipt{}, Audit: []Audit{}}}
	s.lifetime, s.cancelLifetime = context.WithCancel(context.Background())
	var raw []byte
	if docs != nil {
		raw, e = docs.LoadOrImport("replay-archive", path)
	} else {
		var f *os.File
		f, e = os.Open(path)
		if e == nil {
			raw, e = io.ReadAll(io.LimitReader(f, 2*maxStateBytes+1))
			_ = f.Close()
		} else if errors.Is(e, os.ErrNotExist) {
			e = nil
		}
	}
	if e != nil {
		return nil, e
	}
	if len(raw) == 0 {
		return s, nil
	}
	if len(raw) > 2*maxStateBytes {
		return nil, ErrInvalid
	}
	var box envelope
	if json.Unmarshal(raw, &box) != nil || box.Version != 1 || len(box.Nonce) != a.NonceSize() {
		return nil, ErrInvalid
	}
	plain, e := a.Open(nil, box.Nonce, box.Ciphertext, []byte("jms233/replay-archive/v1"))
	if e != nil || len(plain) > maxStateBytes {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if d.Decode(&s.data) != nil || d.Decode(new(any)) != io.EOF || validate(s.data) != nil {
		return nil, ErrInvalid
	}
	return s, nil
}
func (s *Store) copy() state {
	st := state{Revision: s.data.Revision, History: map[int]Config{}, Records: map[string]storedRecord{}, Receipts: append([]receipt{}, s.data.Receipts...), Audit: append([]Audit{}, s.data.Audit...)}
	for k, v := range s.data.History {
		st.History[k] = cloneConfig(v)
	}
	for k, v := range s.data.Records {
		st.Records[k] = v
	}
	return st
}
func (s *Store) persist(st state) error {
	if e := validate(st); e != nil {
		return e
	}
	plain, e := json.Marshal(st)
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
	raw, e := json.Marshal(envelope{Version: 1, Nonce: n, Ciphertext: s.aead.Seal(nil, n, plain, []byte("jms233/replay-archive/v1"))})
	if e != nil {
		return e
	}
	if s.docs != nil {
		return s.docs.Save("replay-archive", raw)
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".replay-archive-*")
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
func (s *Store) requestHash(v any) string {
	raw, _ := json.Marshal(v)
	h := hmac.New(sha256.New, s.hashKey)
	_, _ = h.Write([]byte("jms233/replay-archive-request/v1\x00"))
	_, _ = h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}
func (s *Store) replay(actor, request, hash string) (receipt, bool, error) {
	for _, r := range s.data.Receipts {
		if r.Actor == actor && r.Request == request {
			if r.Hash != hash {
				return receipt{}, true, ErrConflict
			}
			return r, true, nil
		}
	}
	return receipt{}, false, nil
}
func addAudit(st *state, a Audit) {
	st.Audit = append(st.Audit, a)
	if len(st.Audit) > 2000 {
		st.Audit = st.Audit[len(st.Audit)-2000:]
	}
}
func (s *Store) commit(st state, r receipt, a Audit) error {
	if len(st.Receipts) >= 4000 {
		return ErrCapacity
	}
	st.Receipts = append(st.Receipts, r)
	addAudit(&st, a)
	if e := s.persist(st); e != nil {
		return e
	}
	s.data = st
	return nil
}
func (s *Store) notify() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
func (s *Store) Config() (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Config{}, ErrClosed
	}
	if s.data.Revision == 0 {
		return Config{Provider: "local"}, nil
	}
	return publicConfig(s.data.History[s.data.Revision]), nil
}

// Save retains every locator revision so existing objects survive future backend
// changes. Blank secrets retain the current credential only for the same locator.
func (s *Store) Save(actor string, in Input) (Config, error) {
	if !validActor(actor) || !requestPattern.MatchString(in.RequestID) || in.Revision < 0 {
		return Config{}, ErrInvalid
	}
	in.Config = cloneConfig(in.Config)
	in.HasSecret = false
	in.HasSessionToken = false
	in.UpdatedAt = time.Time{}
	if in.Prefix == "" && in.Provider != "local" {
		in.Prefix = "recordings"
	}
	hash := s.requestHash([]any{"configure", in})
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Config{}, ErrClosed
	}
	if r, yes, e := s.replay(actor, in.RequestID, hash); yes {
		if e != nil {
			return Config{}, e
		}
		if r.Config == nil {
			return Config{}, ErrConflict
		}
		return cloneConfig(*r.Config), nil
	}
	if in.Revision != s.data.Revision {
		return Config{}, ErrConflict
	}
	if len(s.data.History) >= 1000 {
		return Config{}, ErrCapacity
	}
	old := s.data.History[s.data.Revision]
	if in.Cloud != nil && old.Cloud != nil && location(in.Config) == location(old) {
		if in.Cloud.SecretAccessKey == "" && in.Cloud.AccessKeyID == old.Cloud.AccessKeyID {
			in.Cloud.SecretAccessKey = old.Cloud.SecretAccessKey
		}
		if in.Cloud.SessionToken == "" && !in.ClearSessionToken && in.Cloud.AccessKeyID == old.Cloud.AccessKeyID {
			in.Cloud.SessionToken = old.Cloud.SessionToken
		}
	}
	if in.ClearSessionToken && in.Cloud != nil {
		in.Cloud.SessionToken = ""
	}
	if validateConfig(in.Config) != nil {
		return Config{}, ErrInvalid
	}
	c := cloneConfig(in.Config)
	c.Revision = s.data.Revision + 1
	c.UpdatedAt = s.now().UTC()
	st := s.copy()
	st.Revision = c.Revision
	st.History[c.Revision] = c
	out := publicConfig(c)
	if e := s.commit(st, receipt{Actor: actor, Request: in.RequestID, Hash: hash, Config: &out}, Audit{At: s.now().UTC(), ActorID: actor, Action: "configure", Revision: c.Revision}); e != nil {
		return Config{}, e
	}
	for _, cancel := range s.busy {
		cancel()
	}
	s.notify()
	return cloneConfig(out), nil
}

// Enqueue records only a locator and identity; preparation and network I/O happen
// in workers after explicit Start. Duplicate completion notifications are safe.
func (s *Store) Enqueue(ref Ref) error {
	if !ValidRef(ref) {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if _, ok := s.data.Records[refKey(ref)]; ok {
		return nil
	}
	c := s.data.History[s.data.Revision]
	if !c.Enabled || c.Provider == "local" {
		return nil
	}
	if len(s.data.Records) >= maxRecords {
		return ErrCapacity
	}
	at := s.now().UTC()
	st := s.copy()
	st.Records[refKey(ref)] = storedRecord{Record: Record{Ref: ref, ConfigRevision: c.Revision, Status: "queued", QueuedAt: at, NextAttempt: at}}
	if e := s.persist(st); e != nil {
		return e
	}
	s.data = st
	s.notify()
	return nil
}
func (s *Store) Retry(ref Ref, actor, request string) (Record, error) {
	if !ValidRef(ref) || !validActor(actor) || !requestPattern.MatchString(request) {
		return Record{}, ErrInvalid
	}
	hash := s.requestHash([]any{"retry", ref})
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Record{}, ErrClosed
	}
	if r, yes, e := s.replay(actor, request, hash); yes {
		if e != nil {
			return Record{}, e
		}
		if r.Record == nil {
			return Record{}, ErrConflict
		}
		return *r.Record, nil
	}
	r, ok := s.data.Records[refKey(ref)]
	if !ok {
		return Record{}, ErrNotFound
	}
	if _, ok = s.busy[refKey(ref)]; ok {
		return Record{}, ErrConflict
	}
	if r.Status != "stored" {
		r.Status = "queued"
		r.Attempts = 0
		r.ErrorCode = ""
		r.NextAttempt = s.now().UTC()
	}
	st := s.copy()
	st.Records[refKey(ref)] = r
	out := r.Record
	if e := s.commit(st, receipt{Actor: actor, Request: request, Hash: hash, Record: &out}, Audit{At: s.now().UTC(), ActorID: actor, Action: "retry", Ref: &ref, Revision: s.data.Revision}); e != nil {
		return Record{}, e
	}
	s.notify()
	return out, nil
}
func (s *Store) Get(ref Ref) (Record, error) {
	if !ValidRef(ref) {
		return Record{}, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Record{}, ErrClosed
	}
	r, ok := s.data.Records[refKey(ref)]
	if !ok {
		return Record{}, ErrNotFound
	}
	return r.Record, nil
}
func (s *Store) Available(ref Ref) bool { r, e := s.Get(ref); return e == nil && r.Status == "stored" }
func (s *Store) List(offset, limit int) ([]Record, int, error) {
	return s.ListFor(offset, limit, nil)
}

// Visibility callbacks run outside the state lock, before sorting/pagination.
func (s *Store) ListFor(offset, limit int, visible func(Ref) bool) ([]Record, int, error) {
	if offset < 0 || limit < 1 || limit > 100 {
		return nil, 0, ErrInvalid
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, 0, ErrClosed
	}
	rows := make([]Record, 0, len(s.data.Records))
	for _, r := range s.data.Records {
		rows = append(rows, r.Record)
	}
	s.mu.Unlock()
	if visible != nil {
		filtered := rows[:0]
		for _, r := range rows {
			if visible(r.Ref) {
				filtered = append(filtered, r)
			}
		}
		rows = filtered
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].QueuedAt.Equal(rows[j].QueuedAt) {
			return refKey(rows[i].Ref) < refKey(rows[j].Ref)
		}
		return rows[i].QueuedAt.After(rows[j].QueuedAt)
	})
	n := len(rows)
	offset = min(offset, n)
	return rows[offset:min(offset+limit, n)], n, nil
}
func (s *Store) Audit(offset, limit int) ([]Audit, int, error) {
	return s.AuditFor(offset, limit, nil)
}
func (s *Store) AuditFor(offset, limit int, visible func(Ref) bool) ([]Audit, int, error) {
	if offset < 0 || limit < 1 || limit > 100 {
		return nil, 0, ErrInvalid
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, 0, ErrClosed
	}
	rows := append([]Audit{}, s.data.Audit...)
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	for i := range rows {
		if rows[i].Ref != nil {
			v := *rows[i].Ref
			rows[i].Ref = &v
		}
	}
	s.mu.Unlock()
	if visible != nil {
		filtered := rows[:0]
		for _, a := range rows {
			if a.Ref == nil || visible(*a.Ref) {
				filtered = append(filtered, a)
			}
		}
		rows = filtered
	}
	n := len(rows)
	offset = min(offset, n)
	return rows[offset:min(offset+limit, n)], n, nil
}

// credentials uses current keys for an unchanged locator; historical endpoints
// retain their own encrypted configuration rather than guessing a new bucket.
func (s *Store) credentials(rev int) Config {
	c := s.data.History[rev]
	for i := s.data.Revision; i > rev; i-- {
		n := s.data.History[i]
		if location(c) == location(n) {
			return cloneConfig(n)
		}
	}
	return cloneConfig(c)
}
func (s *Store) Start(ctx context.Context) error {
	s.startOnce.Do(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed {
			s.startError = ErrClosed
			return
		}
		if e := s.cache.cleanStale(); e != nil {
			s.startError = e
			return
		}
		ctx, s.stop = context.WithCancel(ctx)
		for range 2 {
			s.workers.Add(1)
			go s.worker(ctx)
		}
	})
	return s.startError
}
func (s *Store) Close() {
	s.mu.Lock()
	s.closed = true
	s.cancelLifetime()
	if s.stop != nil {
		s.stop()
	}
	for _, cancel := range s.busy {
		cancel()
	}
	s.mu.Unlock()
	s.workers.Wait()
	s.operations.Wait()
	s.cache.close()
}

func (s *Store) holdOperation() (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	s.operations.Add(1)
	return s.operations.Done, nil
}
