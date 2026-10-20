package enterpriselogin

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/enterpriseoauth"
	"github.com/neko233-com/jumpserver233/server/internal/core/identityscope"
	"github.com/neko233-com/jumpserver233/server/internal/core/logintickets"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
)

var (
	ErrInvalid  = errors.New("invalid enterprise login configuration")
	ErrConflict = errors.New("enterprise login revision or request conflicts")
	ErrDisabled = errors.New("enterprise login disabled")
	ErrFlow     = errors.New("enterprise login flow invalid or expired")
	ErrCapacity = errors.New("enterprise login capacity reached")
	ErrClosed   = errors.New("enterprise login closed")
)

const maxBytes = 8 << 20

var requestPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,100}$`)

type Config struct {
	enterpriseoauth.Config
	Enabled      bool `json:"enabled"`
	ProvisionNew bool `json:"provision_new"`
	Revision     int  `json:"revision"`
}
type Input struct {
	Config
	ClientSecret string `json:"client_secret"`
	ClearSecret  bool   `json:"clear_secret"`
	RequestID    string `json:"request_id,omitempty"`
}
type Snapshot struct {
	Config
	HasClientSecret bool `json:"has_client_secret"`
}
type Audit struct {
	At            time.Time `json:"at"`
	ActorID       string    `json:"actor_id"`
	Actor         string    `json:"actor"`
	Revision      int       `json:"revision"`
	SecretChanged bool      `json:"secret_changed"`
}
type receipt struct {
	ActorID, RequestID, Hash string
	Result                   Snapshot
}
type persisted struct {
	Config   Config    `json:"config"`
	Secret   string    `json:"secret"`
	Audit    []Audit   `json:"audit"`
	Receipts []receipt `json:"receipts"`
}
type envelope struct {
	Version           int `json:"version"`
	Nonce, Ciphertext []byte
}
type flow struct {
	Proof    [32]byte
	Verifier string
	Revision int
	Expires  time.Time
}
type Start struct {
	URL, Proof string
	Expires    time.Time
}
type Identity struct {
	Issuer, Subject string
	Provision       bool
	Revision        int
}
type Service struct {
	mu                            sync.Mutex
	path, publicURL, prefix, kind string
	docs                          *storage.Documents
	aead                          cipher.AEAD
	provider                      enterpriseoauth.Provider
	data                          persisted
	flows                         map[[32]byte]flow
	Tickets                       *logintickets.Store
	slots                         chan struct{}
	now                           func() time.Time
	lifetime                      context.Context
	cancel                        context.CancelFunc
	operations                    sync.WaitGroup
	closed                        bool
	closeDone                     chan struct{}
}

func clone[T any](v T) T {
	raw, _ := json.Marshal(v)
	var out T
	_ = json.Unmarshal(raw, &out)
	return out
}
func Open(kind, path string, key []byte, docs *storage.Documents, publicURL, prefix string, provider enterpriseoauth.Provider) (*Service, error) {
	if !enterpriseoauth.Kind(kind) || !identityscope.ValidPrefix(prefix) || identityscope.ID(prefix) == "" {
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
	if provider == nil {
		provider = enterpriseoauth.NewClient()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{closeDone: make(chan struct{}), path: path, publicURL: publicURL, prefix: prefix, kind: kind, docs: docs, aead: a, provider: provider, flows: map[[32]byte]flow{}, Tickets: logintickets.New(), slots: make(chan struct{}, 4), now: time.Now, lifetime: ctx, cancel: cancel, data: persisted{Config: Config{Config: enterpriseoauth.Normalize(enterpriseoauth.Config{Provider: kind})}, Audit: []Audit{}, Receipts: []receipt{}}}
	var raw []byte
	if docs != nil {
		raw, e = docs.LoadOrImport(kind+"-config", path)
	} else {
		var f *os.File
		f, e = os.Open(path)
		if e == nil {
			raw, e = io.ReadAll(io.LimitReader(f, maxBytes*2+1))
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
	if len(raw) > 2*maxBytes || json.Unmarshal(raw, &env) != nil || env.Version != 1 || len(env.Nonce) != a.NonceSize() {
		cancel()
		return nil, ErrInvalid
	}
	plain, e := a.Open(nil, env.Nonce, env.Ciphertext, []byte("jms233/enterprise-login/"+kind+"/v1"))
	if e != nil || len(plain) > maxBytes || json.Unmarshal(plain, &s.data) != nil || s.validate(s.data.Config, s.data.Secret) != nil || s.data.Config.Revision < 1 || len(s.data.Audit) > 1000 || len(s.data.Receipts) > 2000 {
		cancel()
		return nil, ErrInvalid
	}
	for _, r := range s.data.Receipts {
		if r.ActorID == "" || !requestPattern.MatchString(r.RequestID) || len(r.Hash) != 64 || r.Result.Provider != kind || r.Result.Revision < 1 {
			cancel()
			return nil, ErrInvalid
		}
	}
	return s, nil
}
func (s *Service) validate(c Config, secret string) error {
	if c.Provider != s.kind || c.Revision < 0 || c.Revision >= 1_000_000_000 || len(secret) > 4096 || strings.IndexFunc(secret, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return ErrInvalid
	}
	if !c.Enabled && c.ClientID == "" && c.CallbackURL == "" && c.TenantID == "" && c.AgentID == "" && len(c.Scopes) == 0 && c.CAPEM == "" {
		return nil
	}
	if enterpriseoauth.Validate(c.Config) != nil || c.Enabled && secret == "" {
		return ErrInvalid
	}
	u, _ := url.Parse(c.CallbackURL)
	if u.Path != s.prefix+"/api/v1/authentication/"+s.kind+"/callback" {
		return ErrInvalid
	}
	origin := u.Scheme + "://" + u.Host
	if s.publicURL != "" && origin != s.publicURL {
		return ErrInvalid
	}
	if s.publicURL == "" && u.Scheme == "https" {
		return ErrInvalid
	}
	return nil
}
func issuer(c Config) string {
	raw, _ := json.Marshal([]string{c.Provider, c.Region, c.ClientID, c.TenantID, c.AgentID})
	sum := sha256.Sum256(raw)
	return c.Provider + ":" + hex.EncodeToString(sum[:])
}
func (s *Service) Namespace() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Config.ClientID == "" {
		return ""
	}
	return issuer(s.data.Config)
}
func (s *Service) IssuerAllowed(value string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && s.data.Config.Enabled && issuer(s.data.Config) == value
}
func (s *Service) Available() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && s.data.Config.Enabled
}
func (s *Service) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Snapshot{clone(s.data.Config), s.data.Secret != ""}
}
func (s *Service) Audit() []Audit {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := slices.Clone(s.data.Audit)
	slices.Reverse(out)
	return out
}
func (s *Service) Save(in Input, actorID, actor string) (Snapshot, error) {
	if actorID == "" || len(actorID) > 128 || len(actor) > 128 || !requestPattern.MatchString(in.RequestID) || in.ClearSecret && in.ClientSecret != "" {
		return Snapshot{}, ErrInvalid
	}
	raw, _ := json.Marshal(in)
	digest := sha256.Sum256(raw)
	hash := hex.EncodeToString(digest[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Snapshot{}, ErrClosed
	}
	for _, r := range s.data.Receipts {
		if r.ActorID == actorID && r.RequestID == in.RequestID {
			if r.Hash != hash {
				return Snapshot{}, ErrConflict
			}
			return clone(r.Result), nil
		}
	}
	if in.Revision != s.data.Config.Revision {
		return Snapshot{}, ErrConflict
	}
	if len(s.data.Receipts) >= 2000 {
		return Snapshot{}, ErrCapacity
	}
	c := in.Config
	c.Config = enterpriseoauth.Normalize(c.Config)
	secret := s.data.Secret
	if in.ClearSecret {
		secret = ""
	}
	if in.ClientSecret != "" {
		secret = in.ClientSecret
	}
	if s.validate(c, secret) != nil {
		return Snapshot{}, ErrInvalid
	}
	c.Revision++
	next := clone(s.data)
	next.Config = c
	next.Secret = secret
	next.Audit = append(next.Audit, Audit{s.now().UTC(), actorID, actor, c.Revision, in.ClearSecret || in.ClientSecret != ""})
	if len(next.Audit) > 1000 {
		next.Audit = next.Audit[len(next.Audit)-1000:]
	}
	result := Snapshot{clone(c), secret != ""}
	next.Receipts = append(next.Receipts, receipt{actorID, in.RequestID, hash, result})
	if e := s.persist(next); e != nil {
		return Snapshot{}, e
	}
	s.data = next
	s.flows = map[[32]byte]flow{}
	s.Tickets.Reset()
	return clone(result), nil
}
func (s *Service) beginOperation(ctx context.Context) (context.Context, func(), error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, nil, ErrClosed
	}
	s.operations.Add(1)
	s.mu.Unlock()
	operation, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.lifetime, cancel)
	return operation, func() { stop(); cancel(); s.operations.Done() }, nil
}
func (s *Service) Check(ctx context.Context) error {
	ctx, finish, e := s.beginOperation(ctx)
	if e != nil {
		return e
	}
	defer finish()
	ctx, release, e := workgate.FromContext(ctx).Enter(ctx, "enterprise_login")
	if e != nil {
		return e
	}
	defer release()
	s.mu.Lock()
	c, secret := clone(s.data.Config), s.data.Secret
	s.mu.Unlock()
	if secret == "" || s.validate(c, secret) != nil {
		return ErrInvalid
	}
	if e = s.provider.Check(ctx, c.Config, secret); e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.data.Config.Revision != c.Revision {
		return ErrConflict
	}
	return nil
}
func randomValue() (string, error) {
	var raw [32]byte
	if _, e := rand.Read(raw[:]); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
func (s *Service) Begin() (Start, error) {
	state, e := randomValue()
	if e != nil {
		return Start{}, e
	}
	proof, e := randomValue()
	if e != nil {
		return Start{}, e
	}
	verifier, e := randomValue()
	if e != nil {
		return Start{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Start{}, ErrClosed
	}
	c := s.data.Config
	if !c.Enabled {
		return Start{}, ErrDisabled
	}
	for key, f := range s.flows {
		if !s.now().Before(f.Expires) {
			delete(s.flows, key)
		}
	}
	if len(s.flows) >= 1000 {
		return Start{}, ErrCapacity
	}
	target, e := s.provider.Begin(c.Config, state, verifier)
	if e != nil {
		return Start{}, e
	}
	expires := s.now().Add(10 * time.Minute)
	s.flows[sha256.Sum256([]byte(state))] = flow{sha256.Sum256([]byte(proof)), verifier, c.Revision, expires}
	return Start{target, proof, expires}, nil
}
func (s *Service) Finish(ctx context.Context, state, proof, code string) (Identity, error) {
	ctx, finish, e := s.beginOperation(ctx)
	if e != nil {
		return Identity{}, e
	}
	defer finish()
	ctx, release, e := workgate.FromContext(ctx).Enter(ctx, "enterprise_login")
	if e != nil {
		return Identity{}, e
	}
	defer release()
	if state == "" || len(state) > 128 || proof == "" || len(proof) > 128 {
		return Identity{}, ErrFlow
	}
	s.mu.Lock()
	key := sha256.Sum256([]byte(state))
	f, ok := s.flows[key]
	delete(s.flows, key)
	c, secret := clone(s.data.Config), s.data.Secret
	s.mu.Unlock()
	hashed := sha256.Sum256([]byte(proof))
	if !ok || !c.Enabled || f.Revision != c.Revision || !s.now().Before(f.Expires) || subtle.ConstantTimeCompare(hashed[:], f.Proof[:]) != 1 || code == "" || len(code) > 2048 {
		return Identity{}, ErrFlow
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return Identity{}, ErrCapacity
	}
	identity, e := s.provider.Exchange(ctx, c.Config, secret, code, f.Verifier)
	if e != nil {
		return Identity{}, e
	}
	if identity.Subject == "" || len(identity.Subject) > 1024 {
		return Identity{}, ErrFlow
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.data.Config.Enabled || s.data.Config.Revision != c.Revision {
		return Identity{}, ErrConflict
	}
	return Identity{issuer(c), identity.Subject, c.ProvisionNew, c.Revision}, nil
}
func (s *Service) Cancel(state, proof string) {
	if state == "" || len(state) > 128 || proof == "" || len(proof) > 128 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sha256.Sum256([]byte(state))
	f, ok := s.flows[key]
	digest := sha256.Sum256([]byte(proof))
	if ok && subtle.ConstantTimeCompare(digest[:], f.Proof[:]) == 1 {
		delete(s.flows, key)
	}
}
func (s *Service) NewPending(user string, revision, generation int) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.data.Config.Enabled || s.data.Config.Revision != revision {
		return "", ErrConflict
	}
	ticket, e := s.Tickets.Issue(user, revision)
	if e == nil {
		e = s.Tickets.BindGeneration(ticket, generation)
	}
	return ticket, e
}
func (s *Service) Pending(ticket string, attempt bool) (logintickets.Ticket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, e := s.Tickets.Read(ticket, attempt)
	if e != nil {
		return p, e
	}
	if s.closed || !s.data.Config.Enabled || s.data.Config.Revision != p.Revision {
		s.Tickets.Consume(ticket)
		return p, ErrFlow
	}
	return p, nil
}
func (s *Service) SetSetup(ticket, setup string) error { return s.Tickets.SetSetup(ticket, setup) }
func (s *Service) Consume(ticket string, revision int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ok := s.Tickets.Consume(ticket)
	return ok && !s.closed && s.data.Config.Enabled && s.data.Config.Revision == revision
}
func (s *Service) ReturnURL(path string) string {
	path = identityscope.ReturnPath(s.prefix, path)
	snapshot := s.Snapshot()
	if snapshot.CallbackURL == "" {
		return path
	}
	u, e := url.Parse(snapshot.CallbackURL)
	if e != nil {
		return path
	}
	return u.Scheme + "://" + u.Host + path
}
func (s *Service) SecureCookies() bool {
	u, e := url.Parse(s.Snapshot().CallbackURL)
	return e == nil && u.Scheme == "https"
}
func (s *Service) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		<-s.closeDone
		return
	}
	s.closed = true
	s.cancel()
	clear(s.flows)
	s.Tickets.Reset()
	s.mu.Unlock()
	s.operations.Wait()
	close(s.closeDone)
}
func (s *Service) persist(next persisted) error {
	plain, e := json.Marshal(next)
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
	raw, e := json.Marshal(envelope{1, nonce, s.aead.Seal(nil, nonce, plain, []byte("jms233/enterprise-login/"+s.kind+"/v1"))})
	if e != nil {
		return e
	}
	if s.docs != nil {
		return s.docs.Save(s.kind+"-config", raw)
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".enterprise-login-*")
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
