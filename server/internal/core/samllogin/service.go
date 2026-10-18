package samllogin

import (
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

	"github.com/neko233-com/jumpserver233/server/internal/connector/samlclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/logintickets"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

var ErrInvalid = errors.New("invalid SAML configuration")
var ErrConflict = errors.New("SAML configuration revision changed")
var ErrDisabled = errors.New("SAML login disabled")
var ErrFlow = errors.New("SAML browser flow invalid or expired")
var ErrCapacity = errors.New("SAML flow or audit capacity reached")

type Config struct {
	samlclient.Config
	Enabled        bool   `json:"enabled"`
	ProvisionNew   bool   `json:"provision_new"`
	Revision       int    `json:"revision"`
	IDPEntityID    string `json:"idp_entity_id"`
	SPFingerprint  string `json:"sp_fingerprint"`
	MetadataSHA256 string `json:"metadata_sha256"`
	RotateSP       bool   `json:"rotate_sp,omitempty"`
}
type Audit struct {
	At      time.Time `json:"at"`
	ActorID string    `json:"actor_id"`
	Actor   string    `json:"actor"`
	Config  Config    `json:"config"`
}
type persisted struct {
	Config Config
	Key    samlclient.IdentityKey
	Audit  []Audit
}
type envelope struct {
	Version           int
	Nonce, Ciphertext []byte
}
type Identity struct {
	Issuer, Subject string
	Provision       bool
	Revision        int
}
type flow struct {
	Proof     [32]byte
	RequestID string
	Revision  int
	Expires   time.Time
}
type handoff struct {
	Proof    [32]byte
	Identity Identity
	Expires  time.Time
}
type Start struct {
	URL, Proof string
	Expires    time.Time
}
type Service struct {
	mu              sync.Mutex
	path, publicURL string
	aead            cipher.AEAD
	documents       *storage.Documents
	data            persisted
	client          *samlclient.Client
	flows           map[[32]byte]flow
	handoffs        map[[32]byte]handoff
	replays         map[string]time.Time
	Tickets         *logintickets.Store
	slots           chan struct{}
	now             func() time.Time
}

func Open(path string, key []byte, documents *storage.Documents, publicURL string) (*Service, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	s := &Service{path: path, publicURL: publicURL, aead: a, documents: documents, flows: map[[32]byte]flow{}, handoffs: map[[32]byte]handoff{}, replays: map[string]time.Time{}, Tickets: logintickets.New(), slots: make(chan struct{}, 4), now: time.Now, data: persisted{Audit: []Audit{}}}
	var raw []byte
	if documents != nil {
		raw, e = documents.LoadOrImport("saml-config", path)
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
	plain, e := a.Open(nil, env.Nonce, env.Ciphertext, []byte("jms233/saml/config/v1"))
	if e != nil || json.Unmarshal(plain, &s.data) != nil || s.data.Config.Revision < 1 || len(s.data.Audit) > 1000 {
		return nil, ErrInvalid
	}
	// Disabled providers may have expired certificates. Keep the console usable
	// so an administrator can replace metadata before enabling them again.
	if s.data.Config.EntityID != "" {
		s.client, e = s.build(s.data.Config, s.data.Key)
		// Trust material can expire while the server is stopped. Fail this
		// source closed while allowing local administrators to repair it.
		if e != nil {
			s.client = nil
		}
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
func (s *Service) build(c Config, key samlclient.IdentityKey) (*samlclient.Client, error) {
	if !samlclient.Endpoint(c.ACSURL, c.AllowLoopbackHTTP) {
		return nil, ErrInvalid
	}
	u, _ := url.Parse(c.ACSURL)
	if s.publicURL != "" {
		if origin(c.ACSURL) != s.publicURL {
			return nil, ErrInvalid
		}
	} else {
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return nil, ErrInvalid
		}
	}
	cl, e := samlclient.New(c.Config, key)
	if e != nil {
		return nil, ErrInvalid
	}
	return cl, nil
}
func (s *Service) Snapshot() Config { s.mu.Lock(); defer s.mu.Unlock(); return s.data.Config }
func (s *Service) Available() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Config.Enabled && s.client != nil && s.client.Valid()
}
func (s *Service) Namespace() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return namespace(s.data.Config)
}
func namespace(c Config) string {
	h := sha256.Sum256([]byte(c.IDPEntityID + "\x00" + c.EntityID + "\x00" + samlclient.Persistent))
	return "saml:" + base64.RawURLEncoding.EncodeToString(h[:])
}
func (s *Service) IssuerAllowed(issuer string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Config.Enabled && s.client != nil && s.client.Valid() && issuer == namespace(s.data.Config)
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
	c.EntityID = strings.TrimSpace(c.EntityID)
	c.ACSURL = strings.TrimSpace(c.ACSURL)
	c.MetadataXML = strings.TrimSpace(c.MetadataXML)
	key := s.data.Key
	if c.RotateSP {
		var e error
		key, e = samlclient.GenerateKey()
		if e != nil {
			return Config{}, e
		}
	}
	var cl *samlclient.Client
	if !c.RotateSP && !c.Enabled && c.Config == s.data.Config.Config {
		c.IDPEntityID = s.data.Config.IDPEntityID
		c.SPFingerprint = s.data.Config.SPFingerprint
		cl = s.client
	} else if c.EntityID != "" || c.ACSURL != "" || c.MetadataXML != "" || c.Enabled {
		var e error
		if len(key.PrivateKey) == 0 {
			key, e = samlclient.GenerateKey()
			if e != nil {
				return Config{}, e
			}
		}
		cl, e = s.build(c, key)
		if e != nil {
			return Config{}, e
		}
		c.IDPEntityID = cl.Issuer()
		c.SPFingerprint = cl.Fingerprint()
	} else {
		c.IDPEntityID = ""
		c.SPFingerprint = ""
	}
	c.RotateSP = false
	digest := sha256.Sum256([]byte(c.MetadataXML))
	c.MetadataSHA256 = base64.RawURLEncoding.EncodeToString(digest[:])
	c.Revision++
	auditConfig := c
	auditConfig.MetadataXML = ""
	next := persisted{Config: c, Key: key, Audit: append(append([]Audit{}, s.data.Audit...), Audit{At: s.now().UTC(), ActorID: actorID, Actor: actor, Config: auditConfig})}
	if e := s.persist(next); e != nil {
		return Config{}, e
	}
	s.data = next
	s.client = cl
	s.flows = map[[32]byte]flow{}
	s.handoffs = map[[32]byte]handoff{}
	s.Tickets.Reset()
	return c, nil
}
func (s *Service) Metadata() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client == nil {
		return nil, ErrDisabled
	}
	return s.client.Metadata()
}
func randomValue() (string, error) {
	var b [32]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
func (s *Service) prune() {
	now := s.now()
	for k, f := range s.flows {
		if !now.Before(f.Expires) {
			delete(s.flows, k)
		}
	}
	for k, h := range s.handoffs {
		if !now.Before(h.Expires) {
			delete(s.handoffs, k)
		}
	}
	for k, e := range s.replays {
		if !now.Before(e) {
			delete(s.replays, k)
		}
	}
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
	if !s.data.Config.Enabled || s.client == nil || !s.client.Valid() {
		return Start{}, ErrDisabled
	}
	s.prune()
	if len(s.flows) >= 4096 {
		return Start{}, ErrCapacity
	}
	id, location, e := s.client.Begin(state)
	if e != nil {
		return Start{}, e
	}
	expires := s.now().Add(10 * time.Minute)
	s.flows[sha256.Sum256([]byte(state))] = flow{Proof: sha256.Sum256([]byte(proof)), RequestID: id, Revision: s.data.Config.Revision, Expires: expires}
	return Start{URL: location, Proof: proof, Expires: expires}, nil
}

// Accept is the cross-site POST stage. It never creates an account or a session.
// Finalize requires the Lax HttpOnly browser proof on a same-site GET.
func (s *Service) Accept(state, response string) (string, error) {
	if state == "" || len(state) > 128 {
		return "", ErrFlow
	}
	s.mu.Lock()
	k := sha256.Sum256([]byte(state))
	f, ok := s.flows[k]
	delete(s.flows, k)
	c := s.data.Config
	cl := s.client
	s.mu.Unlock()
	if !ok || !s.now().Before(f.Expires) || !c.Enabled || cl == nil || c.Revision != f.Revision {
		return "", ErrFlow
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return "", ErrCapacity
	}
	id, e := cl.Validate(response, f.RequestID)
	if e != nil {
		return "", e
	}
	code, e := randomValue()
	if e != nil {
		return "", e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	if !s.data.Config.Enabled || s.data.Config.Revision != f.Revision {
		return "", ErrConflict
	}
	if _, ok := s.replays[id.AssertionID]; ok {
		return "", ErrFlow
	}
	if len(s.replays) >= 8192 || len(s.handoffs) >= 4096 {
		return "", ErrCapacity
	}
	s.replays[id.AssertionID] = id.Expires
	s.handoffs[sha256.Sum256([]byte(code))] = handoff{Proof: f.Proof, Identity: Identity{Issuer: namespace(c), Subject: id.Subject, Provision: c.ProvisionNew, Revision: c.Revision}, Expires: s.now().Add(time.Minute)}
	return code, nil
}
func (s *Service) Finalize(code, proof string) (Identity, error) {
	if code == "" || proof == "" || len(code) > 128 || len(proof) > 128 {
		return Identity{}, ErrFlow
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := sha256.Sum256([]byte(code))
	h, ok := s.handoffs[k]
	delete(s.handoffs, k)
	p := sha256.Sum256([]byte(proof))
	if !ok || !s.now().Before(h.Expires) || !s.data.Config.Enabled || s.data.Config.Revision != h.Identity.Revision || subtle.ConstantTimeCompare(p[:], h.Proof[:]) != 1 {
		return Identity{}, ErrFlow
	}
	return h.Identity, nil
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
	return s.Tickets.Consume(token) && s.data.Config.Enabled && s.data.Config.Revision == revision
}
func (s *Service) ReturnURL(suffix string) string {
	c := s.Snapshot()
	if c.ACSURL == "" {
		return suffix
	}
	return origin(c.ACSURL) + suffix
}
func (s *Service) SecureCookies() bool {
	u, e := url.Parse(s.Snapshot().ACSURL)
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
	raw, e := json.Marshal(envelope{Version: 1, Nonce: nonce, Ciphertext: s.aead.Seal(nil, nonce, plain, []byte("jms233/saml/config/v1"))})
	if e != nil {
		return e
	}
	if s.documents != nil {
		return s.documents.Save("saml-config", raw)
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".saml-*")
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
