package caslogin

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/casclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/identityscope"
	"github.com/neko233-com/jumpserver233/server/internal/core/logintickets"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

var ErrInvalid = errors.New("invalid CAS configuration")
var ErrConflict = errors.New("CAS configuration revision changed")
var ErrDisabled = errors.New("CAS login disabled")
var ErrFlow = errors.New("CAS browser flow invalid or expired")
var ErrCapacity = errors.New("CAS flow or audit capacity reached")

const CallbackPath = "/api/v1/authentication/cas/callback"

type Config struct {
	casclient.Config
	Enabled      bool   `json:"enabled"`
	CallbackURL  string `json:"callback_url"`
	ProvisionNew bool   `json:"provision_new"`
	Revision     int    `json:"revision"`
}
type Audit struct {
	At      time.Time `json:"at"`
	ActorID string    `json:"actor_id"`
	Actor   string    `json:"actor"`
	Config  Config    `json:"config"`
}
type persisted struct {
	Config Config  `json:"config"`
	Audit  []Audit `json:"audit"`
}
type envelope struct {
	Version           int
	Nonce, Ciphertext []byte
}
type flow struct {
	Proof    [32]byte
	Service  string
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
	mu                           sync.Mutex
	path, publicURL, routePrefix string
	aead                         cipher.AEAD
	documents                    *storage.Documents
	provider                     casclient.Provider
	data                         persisted
	flows                        map[[32]byte]flow
	Tickets                      *logintickets.Store
	slots                        chan struct{}
	now                          func() time.Time
}

func Open(path string, key []byte, documents *storage.Documents, publicURL string, provider casclient.Provider, prefixes ...string) (*Service, error) {
	if len(prefixes) > 1 {
		return nil, ErrInvalid
	}
	prefix := ""
	if len(prefixes) == 1 {
		prefix = prefixes[0]
	}
	if !identityscope.ValidPrefix(prefix) {
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
	if provider == nil {
		provider = casclient.Client{}
	}
	s := &Service{path: path, publicURL: publicURL, aead: a, documents: documents, provider: provider, flows: map[[32]byte]flow{}, Tickets: logintickets.New(), slots: make(chan struct{}, 4), now: time.Now, data: persisted{Config: Config{Config: casclient.Config{Protocol: "3"}}, Audit: []Audit{}}}
	s.routePrefix = prefix
	var raw []byte
	if documents != nil {
		raw, e = documents.LoadOrImport("cas-config", path)
	} else {
		raw, e = os.ReadFile(path)
		if errors.Is(e, os.ErrNotExist) {
			e = nil
		}
	}
	if e != nil {
		return nil, e
	}
	if len(raw) == 0 {
		return s, nil
	}
	var env envelope
	if json.Unmarshal(raw, &env) != nil || env.Version != 1 || len(env.Nonce) != a.NonceSize() {
		return nil, ErrInvalid
	}
	plain, e := a.Open(nil, env.Nonce, env.Ciphertext, []byte("jms233/cas/config/v1"))
	if e != nil || json.Unmarshal(plain, &s.data) != nil || s.data.Config.Revision < 1 || len(s.data.Audit) > 1000 || s.validate(s.data.Config) != nil {
		return nil, ErrInvalid
	}
	return s, nil
}
func origin(raw string) string {
	u, e := url.Parse(raw)
	if e != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
func (s *Service) validate(c Config) error {
	if !c.Enabled && c.BaseURL == "" && c.CallbackURL == "" {
		if c.Protocol != "2" && c.Protocol != "3" {
			return ErrInvalid
		}
		return nil
	}
	if casclient.ValidateConfig(c.Config) != nil || len(c.CallbackURL) > 1900 || !casclient.Endpoint(c.CallbackURL, c.AllowLoopbackHTTP) {
		return ErrInvalid
	}
	u, _ := url.Parse(c.CallbackURL)
	if u.Path != s.routePrefix+CallbackPath || u.RawPath != "" || u.RawQuery != "" {
		return ErrInvalid
	}
	if s.publicURL != "" {
		if origin(c.CallbackURL) != s.publicURL {
			return ErrInvalid
		}
	} else if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
		return ErrInvalid
	}
	return nil
}
func (s *Service) Snapshot() Config { s.mu.Lock(); defer s.mu.Unlock(); return s.data.Config }
func (s *Service) IssuerAllowed(value string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Config.Enabled && value == s.data.Config.BaseURL
}
func (s *Service) Audit() []Audit {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]Audit{}, s.data.Audit...)
	slices.Reverse(out)
	return out
}
func (s *Service) Save(c Config, actorID, actor string) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.Revision != s.data.Config.Revision {
		return Config{}, ErrConflict
	}
	if len(s.data.Audit) >= 1000 {
		return Config{}, ErrCapacity
	}
	c.BaseURL = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	c.CallbackURL = strings.TrimSpace(c.CallbackURL)
	if s.validate(c) != nil {
		return Config{}, ErrInvalid
	}
	next := persisted{Config: c, Audit: append([]Audit{}, s.data.Audit...)}
	next.Config.Revision++
	next.Audit = append(next.Audit, Audit{At: s.now().UTC(), ActorID: actorID, Actor: actor, Config: next.Config})
	if e := s.persist(next); e != nil {
		return Config{}, e
	}
	s.data = next
	s.flows = map[[32]byte]flow{}
	s.Tickets.Reset()
	return next.Config, nil
}
func (s *Service) Check(ctx context.Context) error {
	c := s.Snapshot()
	if s.validate(c) != nil {
		return ErrInvalid
	}
	return s.provider.Check(ctx, c.Config)
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
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.data.Config
	if !c.Enabled {
		return Start{}, ErrDisabled
	}
	for k, f := range s.flows {
		if !s.now().Before(f.Expires) {
			delete(s.flows, k)
		}
	}
	if len(s.flows) >= 4096 {
		return Start{}, ErrCapacity
	}
	service := c.CallbackURL + "?" + url.Values{"state": {state}}.Encode()
	expires := s.now().Add(10 * time.Minute)
	s.flows[sha256.Sum256([]byte(state))] = flow{Proof: sha256.Sum256([]byte(proof)), Service: service, Revision: c.Revision, Expires: expires}
	return Start{URL: casclient.LoginURL(c.Config, service), Proof: proof, Expires: expires}, nil
}
func (s *Service) Finish(ctx context.Context, state, proof, ticket string) (Identity, error) {
	if state == "" || len(state) > 128 || proof == "" || len(proof) > 128 {
		return Identity{}, ErrFlow
	}
	s.mu.Lock()
	key := sha256.Sum256([]byte(state))
	f, ok := s.flows[key]
	delete(s.flows, key)
	c := s.data.Config
	s.mu.Unlock()
	hash := sha256.Sum256([]byte(proof))
	if !ok || !s.now().Before(f.Expires) || !c.Enabled || c.Revision != f.Revision || subtle.ConstantTimeCompare(hash[:], f.Proof[:]) != 1 {
		return Identity{}, ErrFlow
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return Identity{}, ErrCapacity
	}
	subject, e := s.provider.Validate(ctx, c.Config, f.Service, ticket)
	if e != nil {
		return Identity{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.data.Config.Enabled || s.data.Config.Revision != f.Revision {
		return Identity{}, ErrConflict
	}
	return Identity{Issuer: c.BaseURL, Subject: subject, Provision: c.ProvisionNew, Revision: c.Revision}, nil
}
func (s *Service) NewPending(user string, revision int, generation ...int) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.data.Config.Enabled || s.data.Config.Revision != revision {
		return "", ErrConflict
	}
	token, e := s.Tickets.Issue(user, revision)
	if e == nil && len(generation) == 1 {
		e = s.Tickets.BindGeneration(token, generation[0])
	}
	return token, e
}
func (s *Service) Pending(token string, attempt bool) (logintickets.Ticket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, e := s.Tickets.Read(token, attempt)
	if e != nil {
		return p, e
	}
	if !s.data.Config.Enabled || s.data.Config.Revision != p.Revision {
		s.Tickets.Consume(token)
		return p, ErrFlow
	}
	return p, nil
}
func (s *Service) SetSetup(token, setup string) error { return s.Tickets.SetSetup(token, setup) }
func (s *Service) Consume(token string, revision int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ok := s.Tickets.Consume(token)
	return ok && s.data.Config.Enabled && s.data.Config.Revision == revision
}
func (s *Service) ReturnURL(suffix string) string {
	suffix = identityscope.ReturnPath(s.routePrefix, suffix)
	c := s.Snapshot()
	if c.CallbackURL == "" {
		return suffix
	}
	return origin(c.CallbackURL) + suffix
}
func (s *Service) SecureCookies() bool {
	u, e := url.Parse(s.Snapshot().CallbackURL)
	return e == nil && u.Scheme == "https"
}
func (s *Service) persist(next persisted) error {
	plain, e := json.Marshal(next)
	if e != nil {
		return e
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	raw, e := json.Marshal(envelope{Version: 1, Nonce: nonce, Ciphertext: s.aead.Seal(nil, nonce, plain, []byte("jms233/cas/config/v1"))})
	if e != nil {
		return e
	}
	if s.documents != nil {
		return s.documents.Save("cas-config", raw)
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".cas-*")
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
