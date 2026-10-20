// Package smsmfa owns browser/CLI-bound SMS factors after verified primary
// authentication. It stores code hashes only and never returns provider secrets.
package smsmfa

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
	"strings"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/cloudnotify"
	"github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

var (
	ErrInvalid     = errors.New("invalid SMS factor input")
	ErrConflict    = errors.New("SMS factor revision conflict")
	ErrDisabled    = errors.New("SMS factor disabled")
	ErrFlow        = errors.New("SMS factor invalid or expired")
	ErrRejected    = errors.New("SMS code rejected")
	ErrRate        = errors.New("SMS factor rate limit reached")
	ErrCapacity    = errors.New("SMS factor capacity reached")
	ErrUnavailable = errors.New("SMS factor unavailable")
)

const maxState = 16 << 20

var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var phonePattern = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

type Config struct {
	Enabled  bool     `json:"enabled"`
	Policy   string   `json:"policy"`
	UserIDs  []string `json:"user_ids"`
	Revision int      `json:"revision"`
}
type Input struct {
	Config
	RequestID string `json:"request_id"`
}
type Audit struct {
	At       time.Time `json:"at"`
	ActorID  string    `json:"actor_id"`
	UserID   string    `json:"user_id,omitempty"`
	Action   string    `json:"action"`
	Revision int       `json:"revision"`
}
type settingsReceipt struct {
	ActorID, RequestID, Hash string
	Result                   Config
}
type sendReceipt struct {
	At   time.Time
	Hash string
}
type flow struct {
	UserID, IdentityStamp, AuthSource, SourceIP, Phone, Proof, Kind string
	CodeHash, Nonce, Delivery, DeliveryState                        string
	Generation, Revision, TransportRevision, Attempts               int
	ExpiresAt, SentAt                                               time.Time
	Browser, Secure                                                 bool
	Requests                                                        map[string]sendReceipt
}
type state struct {
	Version  int
	Config   Config
	Flows    map[string]flow
	Rates    map[string][]time.Time
	Receipts []settingsReceipt
	Audit    []Audit
}
type envelope struct {
	Version           int `json:"version"`
	Nonce, Ciphertext []byte
}
type Transport interface {
	MFARevision() int
	SendMFA(context.Context, int, string, string, string, func() error) cloudnotify.Outcome
}
type Service struct {
	mu        sync.Mutex
	path      string
	docs      *storage.Documents
	aead      cipher.AEAD
	auth      *auth.Service
	transport Transport
	data      state
	now       func() time.Time
	life      context.Context
	cancel    context.CancelFunc
	closed    bool
	done      chan struct{}
	wg        sync.WaitGroup
	slots     chan struct{}
}

func clone[T any](v T) T     { b, _ := json.Marshal(v); var out T; _ = json.Unmarshal(b, &out); return out }
func digest(v string) string { b := sha256.Sum256([]byte(v)); return hex.EncodeToString(b[:]) }
func validHash(v string) bool {
	b, e := hex.DecodeString(v)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == v
}

type Options struct{ Now func() time.Time }

func Open(path string, key []byte, docs *storage.Documents, identities *auth.Service, transport Transport, options ...Options) (*Service, error) {
	if identities == nil || transport == nil || len(key) != 32 || len(options) > 1 {
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
	s := &Service{path: path, docs: docs, aead: a, auth: identities, transport: transport, now: time.Now, life: ctx, cancel: cancel, done: make(chan struct{}), slots: make(chan struct{}, 4), data: state{Version: 1, Config: Config{Policy: "opt_in", UserIDs: []string{}}, Flows: map[string]flow{}, Rates: map[string][]time.Time{}, Receipts: []settingsReceipt{}, Audit: []Audit{}}}
	if len(options) == 1 && options[0].Now != nil {
		s.now = options[0].Now
	}
	var raw []byte
	if docs != nil {
		raw, e = docs.LoadOrImport("sms-mfa", path)
	} else {
		var f *os.File
		f, e = os.Open(path)
		if e == nil {
			raw, e = io.ReadAll(io.LimitReader(f, 2*maxState+1))
			_ = f.Close()
		} else if errors.Is(e, os.ErrNotExist) {
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
	var env envelope
	if len(raw) > 2*maxState || json.Unmarshal(raw, &env) != nil || env.Version != 1 || len(env.Nonce) != a.NonceSize() {
		cancel()
		return nil, ErrInvalid
	}
	plain, e := a.Open(nil, env.Nonce, env.Ciphertext, []byte("jms233/sms-mfa/v1"))
	if e != nil || len(plain) > maxState || json.Unmarshal(plain, &s.data) != nil || validate(s.data) != nil {
		cancel()
		return nil, ErrInvalid
	}
	// A send interrupted by process exit is never automatically repeated. Its
	// code hash may still verify; the user can explicitly request a fresh code.
	for id, f := range s.data.Flows {
		if f.DeliveryState == "sending" {
			f.DeliveryState = "uncertain"
			s.data.Flows[id] = f
		}
	}
	return s, nil
}
func validConfig(c Config) bool {
	if c.Revision < 0 || c.Revision >= 1_000_000_000 || !slices.Contains([]string{"opt_in", "admins", "all", "selected"}, c.Policy) || len(c.UserIDs) > 10000 {
		return false
	}
	for i, id := range c.UserIDs {
		if !idPattern.MatchString(id) || i > 0 && c.UserIDs[i-1] >= id {
			return false
		}
	}
	return c.Policy == "selected" || len(c.UserIDs) == 0
}
func validate(d state) error {
	if d.Version != 1 || !validConfig(d.Config) || d.Flows == nil || d.Rates == nil || len(d.Flows) > 1000 || len(d.Rates) > 20000 || len(d.Receipts) > 2000 || len(d.Audit) > 1000 {
		return ErrInvalid
	}
	for key, f := range d.Flows {
		if !validHash(key) || !idPattern.MatchString(f.UserID) || !validHash(f.IdentityStamp) || !slices.Contains([]string{"login", "login-enroll", "enroll", "disable"}, f.Kind) || f.Revision < 1 || f.TransportRevision < 1 || f.Generation < 0 || f.Attempts < 0 || f.Attempts > 5 || f.ExpiresAt.IsZero() || len(f.Proof) > 8192 || len(f.AuthSource) > 32 || len(f.SourceIP) > 64 || len(f.Requests) > 32 || f.Phone != "" && !phonePattern.MatchString(f.Phone) || f.CodeHash != "" && !validHash(f.CodeHash) || !slices.Contains([]string{"unbound", "sending", "sent", "uncertain", "failed"}, f.DeliveryState) {
			return ErrInvalid
		}
		if f.Kind == "login" && f.Proof == "" || f.Kind == "login-enroll" && f.Proof == "" {
			return ErrInvalid
		}
		for id, receipt := range f.Requests {
			if !idPattern.MatchString(id) || receipt.At.IsZero() || !validHash(receipt.Hash) {
				return ErrInvalid
			}
		}
	}
	for key, times := range d.Rates {
		if !validHash(key) || len(times) > 120 {
			return ErrInvalid
		}
		for _, at := range times {
			if at.IsZero() {
				return ErrInvalid
			}
		}
	}
	for _, r := range d.Receipts {
		if !idPattern.MatchString(r.ActorID) || !idPattern.MatchString(r.RequestID) || !validHash(r.Hash) || !validConfig(r.Result) {
			return ErrInvalid
		}
	}
	return nil
}
func (s *Service) persist(next state) error {
	if validate(next) != nil {
		return ErrInvalid
	}
	plain, e := json.Marshal(next)
	if e != nil {
		return e
	}
	if len(plain) > maxState {
		return ErrCapacity
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	raw, e := json.Marshal(envelope{1, nonce, s.aead.Seal(nil, nonce, plain, []byte("jms233/sms-mfa/v1"))})
	if e != nil {
		return e
	}
	if s.docs != nil {
		return s.docs.Save("sms-mfa", raw)
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".sms-mfa-*")
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
func (s *Service) commit(next state) error {
	if s.closed {
		return ErrUnavailable
	}
	if e := s.persist(next); e != nil {
		return e
	}
	s.data = next
	return nil
}
func (s *Service) Snapshot() Config { s.mu.Lock(); defer s.mu.Unlock(); return clone(s.data.Config) }
func (s *Service) Audit() []Audit {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := slices.Clone(s.data.Audit)
	slices.Reverse(out)
	return out
}
func (s *Service) addAudit(next *state, actor, user, action string) {
	next.Audit = append(next.Audit, Audit{s.now().UTC(), actor, user, action, next.Config.Revision})
	if len(next.Audit) > 1000 {
		next.Audit = next.Audit[len(next.Audit)-1000:]
	}
}
func (s *Service) Save(in Input, actor string) (Config, error) {
	if !idPattern.MatchString(actor) || !idPattern.MatchString(in.RequestID) {
		return Config{}, ErrInvalid
	}
	raw, e := json.Marshal(in)
	if e != nil {
		return Config{}, ErrInvalid
	}
	hash := digest(string(raw))
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Config{}, ErrUnavailable
	}
	for _, r := range s.data.Receipts {
		if r.ActorID == actor && r.RequestID == in.RequestID {
			if r.Hash != hash {
				return Config{}, ErrConflict
			}
			return clone(r.Result), nil
		}
	}
	if in.Revision != s.data.Config.Revision {
		return Config{}, ErrConflict
	}
	if len(s.data.Receipts) >= 2000 {
		return Config{}, ErrCapacity
	}
	cfg := clone(in.Config)
	if cfg.UserIDs == nil {
		cfg.UserIDs = []string{}
	}
	slices.Sort(cfg.UserIDs)
	if !validConfig(cfg) {
		return Config{}, ErrInvalid
	}
	if cfg.Enabled && s.transport.MFARevision() == 0 {
		return Config{}, ErrUnavailable
	}
	for _, id := range cfg.UserIDs {
		if _, ok := s.auth.UserByID(id); !ok {
			return Config{}, ErrInvalid
		}
	}
	if cfg.Enabled {
		if e := s.auth.PrepareSMSFormat(); e != nil {
			return Config{}, e
		}
	}
	cfg.Revision++
	next := clone(s.data)
	next.Config = cfg
	clear(next.Flows)
	next.Receipts = append(next.Receipts, settingsReceipt{actor, in.RequestID, hash, clone(cfg)})
	s.addAudit(&next, actor, "", "settings_saved")
	if e = s.commit(next); e != nil {
		return Config{}, e
	}
	return clone(cfg), nil
}
func (s *Service) Required(u auth.User, privileged bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.data.Config
	return !s.closed && c.Enabled && (u.SMSMFAEnabled || c.Policy == "all" || c.Policy == "admins" && privileged || c.Policy == "selected" && slices.Contains(c.UserIDs, u.ID))
}
func (s *Service) Forced(u auth.User, privileged bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.data.Config
	return !s.closed && c.Enabled && (c.Policy == "all" || c.Policy == "admins" && privileged || c.Policy == "selected" && slices.Contains(c.UserIDs, u.ID))
}
func (s *Service) Available() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && s.data.Config.Enabled && s.transport.MFARevision() > 0
}
func (s *Service) stampLocked(id string) string {
	identity := s.auth.SMSIdentityStamp(id)
	rev := s.transport.MFARevision()
	if !s.data.Config.Enabled || identity == "" || rev == 0 {
		return ""
	}
	raw, _ := json.Marshal([]any{"sms-mfa", s.data.Config.Revision, rev, id, identity})
	return digest(string(raw))
}
func (s *Service) Stamp(id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ""
	}
	return s.stampLocked(id)
}
func (s *Service) ValidStamp(id, value string) bool {
	if !validHash(value) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && s.stampLocked(id) == value
}
func (s *Service) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		<-s.done
		return
	}
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	s.wg.Wait()
	close(s.done)
}
func MaskedPhone(phone string) string {
	if len(phone) < 4 {
		return ""
	}
	return "***" + phone[len(phone)-4:]
}
func text(v string, n int) bool { return len(v) <= n && !strings.ContainsAny(v, "\x00\r\n") }
