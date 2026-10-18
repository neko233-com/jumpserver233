package radiuslogin

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/neko233-com/jumpserver233/server/internal/connector/radiusclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/logintickets"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

var (
	ErrInvalid  = errors.New("invalid RADIUS settings")
	ErrConflict = errors.New("RADIUS configuration changed")
	ErrDisabled = errors.New("RADIUS authentication is disabled")
	ErrCapacity = errors.New("RADIUS authentication capacity reached")
	ErrFlow     = errors.New("RADIUS flow invalid or expired")
	ErrBusy     = errors.New("RADIUS flow is already being verified")
	ErrRejected = errors.New("RADIUS verification rejected")
	ErrBinding  = errors.New("RADIUS identity mapping is required")
)

const MaxFlows = 4096

type Config struct {
	Enabled       bool                `json:"enabled"`
	ProvisionNew  bool                `json:"provision_new"`
	Realm         string              `json:"realm"`
	Primary       radiusclient.Config `json:"primary"`
	Factor        radiusclient.Config `json:"factor"`
	FactorPolicy  string              `json:"factor_policy"`
	FactorUserIDs []string            `json:"factor_user_ids"`
	Bindings      map[string]string   `json:"bindings"`
	Revision      int                 `json:"revision"`
}
type EndpointSecrets struct {
	SharedSecret      string `json:"shared_secret"`
	ClientKey         string `json:"client_key"`
	ClearSharedSecret bool   `json:"clear_shared_secret"`
	ClearClientKey    bool   `json:"clear_client_key"`
}
type Input struct {
	Config
	PrimarySecrets EndpointSecrets `json:"primary_secrets"`
	FactorSecrets  EndpointSecrets `json:"factor_secrets"`
}
type Snapshot struct {
	Config
	HasPrimarySecret bool `json:"has_primary_secret"`
	HasPrimaryKey    bool `json:"has_primary_key"`
	HasFactorSecret  bool `json:"has_factor_secret"`
	HasFactorKey     bool `json:"has_factor_key"`
}
type Audit struct {
	ID       string    `json:"id"`
	At       time.Time `json:"at"`
	ActorID  string    `json:"actor_id"`
	Actor    string    `json:"actor"`
	Revision int       `json:"revision"`
	Action   string    `json:"action"`
	Digest   string    `json:"digest"`
}
type state struct {
	Config           Config               `json:"config"`
	VerifiedBindings map[string]string    `json:"verified_bindings"`
	PrimarySecrets   radiusclient.Secrets `json:"primary_secrets"`
	FactorSecrets    radiusclient.Secrets `json:"factor_secrets"`
	Audit            []Audit              `json:"audit"`
	Flows            map[string]flow      `json:"flows"`
}
type envelope struct {
	Version           int `json:"version"`
	Nonce, Ciphertext []byte
}
type pendingOrigin struct {
	Source  string
	Expires time.Time
}
type Service struct {
	mu        sync.Mutex
	path      string
	documents *storage.Documents
	aead      cipher.AEAD
	data      state
	client    radiusclient.Client
	Tickets   *logintickets.Store
	origins   map[string]pendingOrigin
	slots     chan struct{}
	now       func() time.Time
	closed    bool
	ctx       context.Context
	cancel    context.CancelFunc
}
type Identity struct {
	Issuer, Subject string
	Provision       bool
	Revision        int
}

func emptyConfig() Config {
	return Config{Realm: "default", FactorPolicy: "disabled", FactorUserIDs: []string{}, Bindings: map[string]string{}}
}
func Open(path string, key []byte, documents *storage.Documents, client radiusclient.Client) (*Service, error) {
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
	if client == nil {
		client = radiusclient.Native{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{path: path, documents: documents, aead: a, client: client, Tickets: logintickets.New(), origins: map[string]pendingOrigin{}, slots: make(chan struct{}, 8), now: time.Now, ctx: ctx, cancel: cancel, data: state{Config: emptyConfig(), Audit: []Audit{}, Flows: map[string]flow{}}}
	var raw []byte
	if documents != nil {
		raw, e = documents.LoadOrImport("radius-auth", path)
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
	if json.Unmarshal(raw, &box) != nil || box.Version != 1 || len(box.Nonce) != a.NonceSize() {
		cancel()
		return nil, ErrInvalid
	}
	plain, e := a.Open(nil, box.Nonce, box.Ciphertext, []byte("jms233/radius/auth/v1"))
	if e != nil || json.Unmarshal(plain, &s.data) != nil || s.data.Config.Revision < 1 || len(s.data.Audit) > 4000 || len(s.data.Flows) > MaxFlows || validateConfig(s.data.Config, s.data.PrimarySecrets, s.data.FactorSecrets) != nil {
		cancel()
		return nil, ErrInvalid
	}
	for id, f := range s.data.Flows {
		if len(id) != 64 || validateFlow(f) != nil {
			cancel()
			return nil, ErrInvalid
		}
		if f.State == "verifying" {
			f.State = "interrupted"
			f.Proof = ""
			f.RemoteState = nil
			s.data.Flows[id] = f
		}
	}
	if s.data.Flows == nil {
		s.data.Flows = map[string]flow{}
	}
	if s.data.VerifiedBindings == nil {
		s.data.VerifiedBindings = map[string]string{}
	}
	if len(s.data.VerifiedBindings) > 2000 {
		cancel()
		return nil, ErrInvalid
	}
	for id, name := range s.data.VerifiedBindings {
		if !validID(id) || !validRemote(name) {
			cancel()
			return nil, ErrInvalid
		}
	}
	return s, nil
}
func cloneConfig(c Config) Config {
	c.FactorUserIDs = slices.Clone(c.FactorUserIDs)
	c.Bindings = maps.Clone(c.Bindings)
	return c
}
func cloneState(st state) state {
	st.Config = cloneConfig(st.Config)
	st.VerifiedBindings = maps.Clone(st.VerifiedBindings)
	if st.VerifiedBindings == nil {
		st.VerifiedBindings = map[string]string{}
	}
	st.Audit = slices.Clone(st.Audit)
	st.Flows = maps.Clone(st.Flows)
	for id, f := range st.Flows {
		f.RemoteState = slices.Clone(f.RemoteState)
		st.Flows[id] = f
	}
	return st
}
func endpointSecrets(previous radiusclient.Secrets, in EndpointSecrets) radiusclient.Secrets {
	if in.ClearSharedSecret {
		previous.SharedSecret = ""
	}
	if in.ClearClientKey {
		previous.ClientKey = ""
	}
	if in.SharedSecret != "" {
		previous.SharedSecret = in.SharedSecret
	}
	if in.ClientKey != "" {
		previous.ClientKey = in.ClientKey
	}
	return previous
}
func validateConfig(c Config, p, f radiusclient.Secrets) error {
	for _, endpoint := range []radiusclient.Config{c.Primary, c.Factor} {
		if len(endpoint.Host) > 253 || len(endpoint.ServerName) > 253 || len(endpoint.NASIdentifier) > 253 || len(endpoint.CAPEM) > 64<<10 || len(endpoint.ClientCertificate) > 32<<10 {
			return ErrInvalid
		}
	}
	if len(c.Realm) < 1 || len(c.Realm) > 64 || strings.IndexFunc(c.Realm, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.')
	}) >= 0 || !slices.Contains([]string{"disabled", "all", "admins", "users"}, c.FactorPolicy) || len(c.FactorUserIDs) > 200 || len(c.Bindings) > 2000 {
		return ErrInvalid
	}
	for _, id := range c.FactorUserIDs {
		if !validID(id) {
			return ErrInvalid
		}
	}
	for id, remote := range c.Bindings {
		if !validID(id) || !validRemote(remote) {
			return ErrInvalid
		}
	}
	if c.FactorPolicy == "users" && len(c.FactorUserIDs) == 0 {
		return ErrInvalid
	}
	if c.FactorPolicy != "users" && len(c.FactorUserIDs) > 0 {
		return ErrInvalid
	}
	if c.Enabled || c.Primary.Host != "" {
		if radiusclient.Validate(c.Primary, p) != nil {
			return ErrInvalid
		}
	}
	if c.FactorPolicy != "disabled" || c.Factor.Host != "" {
		if radiusclient.Validate(c.Factor, f) != nil {
			return ErrInvalid
		}
	}
	if len(p.SharedSecret) > 256 || len(f.SharedSecret) > 256 || len(p.ClientKey) > 32<<10 || len(f.ClientKey) > 32<<10 {
		return ErrInvalid
	}
	return nil
}
func validID(id string) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
func validRemote(v string) bool {
	return len(v) > 0 && len(v) <= 128 && utf8.ValidString(v) && strings.IndexFunc(v, unicode.IsControl) < 0 && strings.TrimSpace(v) == v
}

func ValidSubject(v string) bool { return validRemote(v) }
func issuer(c Config) string     { return "radius:" + c.Realm }
func configDigest(c Config) string {
	raw, _ := json.Marshal(c)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func snapshot(st state) Snapshot {
	return Snapshot{Config: cloneConfig(st.Config), HasPrimarySecret: st.PrimarySecrets.SharedSecret != "", HasPrimaryKey: st.PrimarySecrets.ClientKey != "", HasFactorSecret: st.FactorSecrets.SharedSecret != "", HasFactorKey: st.FactorSecrets.ClientKey != ""}
}
func (s *Service) Snapshot() Snapshot { s.mu.Lock(); defer s.mu.Unlock(); return snapshot(s.data) }
func (s *Service) IssuerAllowed(value string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && s.data.Config.Enabled && issuer(s.data.Config) == value
}
func (s *Service) Save(in Input, actorID, actor string) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Snapshot{}, ErrDisabled
	}
	if in.Revision != s.data.Config.Revision {
		return Snapshot{}, ErrConflict
	}
	c := cloneConfig(in.Config)
	if c.Realm == "" {
		c.Realm = "default"
	}
	if c.FactorPolicy == "" {
		c.FactorPolicy = "disabled"
	}
	if c.Bindings == nil {
		c.Bindings = map[string]string{}
	}
	slices.Sort(c.FactorUserIDs)
	c.FactorUserIDs = slices.Compact(c.FactorUserIDs)
	var e error
	if c.Primary.Host != "" {
		c.Primary, e = radiusclient.Normalize(c.Primary)
		if e != nil {
			return Snapshot{}, ErrInvalid
		}
	}
	if c.Factor.Host != "" {
		c.Factor, e = radiusclient.Normalize(c.Factor)
		if e != nil {
			return Snapshot{}, ErrInvalid
		}
	}
	p := endpointSecrets(s.data.PrimarySecrets, in.PrimarySecrets)
	f := endpointSecrets(s.data.FactorSecrets, in.FactorSecrets)
	if validateConfig(c, p, f) != nil {
		return Snapshot{}, ErrInvalid
	}
	next := cloneState(s.data)
	c.Revision++
	next.Config = c
	next.PrimarySecrets = p
	next.FactorSecrets = f
	// Changing trust or policy invalidates every outstanding proof/challenge.
	next.Flows = map[string]flow{}
	event, e := newAudit(c, actorID, actor, "settings_saved", s.now())
	if e != nil {
		return Snapshot{}, e
	}
	next.Audit = retainAudit(append(next.Audit, event), s.now())
	if e = s.persist(next); e != nil {
		return Snapshot{}, e
	}
	s.data = next
	s.Tickets.Reset()
	s.origins = map[string]pendingOrigin{}
	return snapshot(next), nil
}
func newAudit(c Config, id, actor, action string, now time.Time) (Audit, error) {
	var raw [16]byte
	if _, e := rand.Read(raw[:]); e != nil {
		return Audit{}, e
	}
	return Audit{ID: "radius-event-" + hex.EncodeToString(raw[:]), At: now.UTC(), ActorID: id, Actor: actor, Revision: c.Revision, Action: action, Digest: configDigest(c)}, nil
}
func retainAudit(in []Audit, now time.Time) []Audit {
	out := slices.DeleteFunc(in, func(v Audit) bool { return v.At.Before(now.AddDate(-1, 0, 0)) })
	if len(out) > 4000 {
		out = out[len(out)-4000:]
	}
	return out
}
func (s *Service) Audit(offset, limit int) ([]Audit, int, error) {
	if offset < 0 || limit < 1 || limit > 100 {
		return nil, 0, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := slices.Clone(s.data.Audit)
	slices.Reverse(rows)
	n := len(rows)
	offset = min(offset, n)
	return rows[offset:min(offset+limit, n)], n, nil
}
func (s *Service) Required(userID string, privileged bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return required(s.data.Config, userID, privileged)
}
func required(c Config, id string, admin bool) bool {
	return c.FactorPolicy == "all" || c.FactorPolicy == "admins" && admin || c.FactorPolicy == "users" && slices.Contains(c.FactorUserIDs, id)
}
func (s *Service) ValidStamp(stamp string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && stamp != "" && stamp == policyStamp(s.data.Config)
}
func (s *Service) RemoteFor(userID, localName, source string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if remote := s.data.Config.Bindings[userID]; remote != "" {
		return remote, nil
	}
	if source == "radius" {
		if remote := s.data.VerifiedBindings[userID]; remote != "" {
			return remote, nil
		}
	}
	if source == "" && validRemote(localName) {
		return localName, nil
	}
	return "", ErrBinding
}
func (s *Service) BindVerifiedUser(id, subject string, revision int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.data.Config.Enabled || s.data.Config.Revision != revision {
		return ErrConflict
	}
	if !validID(id) || !validRemote(subject) {
		return ErrInvalid
	}
	if existing := s.data.VerifiedBindings[id]; existing != "" {
		if existing != subject {
			return ErrConflict
		}
		return nil
	}
	if len(s.data.VerifiedBindings) >= 2000 {
		return ErrCapacity
	}
	next := cloneState(s.data)
	next.VerifiedBindings[id] = subject
	// Verified primary identity mappings do not change the trust-policy revision.
	if e := s.persist(next); e != nil {
		return e
	}
	s.data = next
	return nil
}
func (s *Service) Close() { s.mu.Lock(); s.closed = true; s.cancel(); s.mu.Unlock() }
func (s *Service) exchange(ctx context.Context, c radiusclient.Config, secret radiusclient.Secrets, in radiusclient.Request) (radiusclient.Reply, error) {
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return radiusclient.Reply{}, ErrCapacity
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	return s.client.Exchange(ctx, c, secret, in)
}
func (s *Service) Probe(ctx context.Context, endpoint, username, password string) (radiusclient.Reply, error) {
	s.mu.Lock()
	c, secret := s.data.Config.Primary, s.data.PrimarySecrets
	if endpoint == "factor" {
		c, secret = s.data.Config.Factor, s.data.FactorSecrets
	} else if endpoint != "primary" {
		s.mu.Unlock()
		return radiusclient.Reply{}, ErrInvalid
	}
	s.mu.Unlock()
	return s.exchange(ctx, c, secret, radiusclient.Request{Username: username, Password: password})
}
func (s *Service) NewPending(user string, revision int, source string, generation ...int) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.data.Config.Enabled || s.data.Config.Revision != revision {
		return "", ErrConflict
	}
	for id, p := range s.origins {
		if !s.now().Before(p.Expires) {
			delete(s.origins, id)
		}
	}
	if len(s.origins) >= 4096 {
		return "", ErrCapacity
	}
	token, e := s.Tickets.Issue(user, revision)
	if e == nil && len(generation) == 1 {
		e = s.Tickets.BindGeneration(token, generation[0])
	}
	if e == nil {
		s.origins[flowHash(token)] = pendingOrigin{source, s.now().Add(5 * time.Minute)}
	}
	return token, e
}
func (s *Service) Pending(token string, attempt bool, source string) (logintickets.Ticket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	origin, ok := s.origins[flowHash(token)]
	if !ok || origin.Source != source || !s.now().Before(origin.Expires) {
		return logintickets.Ticket{}, logintickets.ErrTicket
	}
	p, e := s.Tickets.Read(token, attempt)
	if s.closed || e != nil || !s.data.Config.Enabled || s.data.Config.Revision != p.Revision {
		return p, logintickets.ErrTicket
	}
	return p, nil
}
func (s *Service) Consume(token string, revision int, source string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	origin, ok := s.origins[flowHash(token)]
	if !ok || origin.Source != source || !s.now().Before(origin.Expires) {
		return false
	}
	delete(s.origins, flowHash(token))
	return s.Tickets.Consume(token) && !s.closed && s.data.Config.Enabled && s.data.Config.Revision == revision
}
func (s *Service) SetSetup(token, setup string) error { return s.Tickets.SetSetup(token, setup) }
func (s *Service) persist(next state) error {
	if s.closed {
		return ErrDisabled
	}
	plain, e := json.Marshal(next)
	if e != nil {
		return e
	}
	if len(plain) > 16<<20 {
		return ErrCapacity
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	raw, e := json.Marshal(envelope{Version: 1, Nonce: nonce, Ciphertext: s.aead.Seal(nil, nonce, plain, []byte("jms233/radius/auth/v1"))})
	if e != nil {
		return e
	}
	if s.documents != nil {
		return s.documents.Save("radius-auth", raw)
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".radius-*")
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
