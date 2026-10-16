package ldaplogin

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/ldapclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/logintickets"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

var ErrInvalid = errors.New("invalid LDAP configuration")
var ErrConflict = errors.New("LDAP configuration revision changed")
var ErrDisabled = errors.New("LDAP login disabled")
var ErrCapacity = errors.New("LDAP audit capacity reached")

type Config struct {
	ldapclient.Config
	Enabled      bool `json:"enabled"`
	ProvisionNew bool `json:"provision_new"`
	Revision     int  `json:"revision"`
}
type Input struct {
	Config
	BindPassword  string `json:"bind_password"`
	ClearPassword bool   `json:"clear_password"`
}
type Snapshot struct {
	Config
	HasBindPassword bool `json:"has_bind_password"`
}
type Audit struct {
	At      time.Time `json:"at"`
	ActorID string    `json:"actor_id"`
	Actor   string    `json:"actor"`
	Config  Config    `json:"config"`
}
type persisted struct {
	Config   Config  `json:"config"`
	Password string  `json:"password"`
	Audit    []Audit `json:"audit"`
}
type envelope struct {
	Version           int `json:"version"`
	Nonce, Ciphertext []byte
}
type Identity struct {
	Issuer, Subject string
	Provision       bool
	Revision        int
}
type Service struct {
	mu        sync.Mutex
	path      string
	documents *storage.Documents
	aead      cipher.AEAD
	data      persisted
	directory ldapclient.Directory
	Tickets   *logintickets.Store
	slots     chan struct{}
}

func Open(path string, key []byte, documents *storage.Documents, directory ldapclient.Directory) (*Service, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	if directory == nil {
		directory = ldapclient.Client{}
	}
	s := &Service{path: path, documents: documents, aead: a, directory: directory, Tickets: logintickets.New(), slots: make(chan struct{}, 4), data: persisted{Config: Config{Config: ldapclient.Config{Filter: "(uid={username})", IdentityAttribute: "entryUUID"}}, Audit: []Audit{}}}
	var raw []byte
	if documents != nil {
		raw, e = documents.LoadOrImport("ldap-config", path)
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
	plain, e := a.Open(nil, env.Nonce, env.Ciphertext, []byte("jms233/ldap/config/v1"))
	if e != nil || json.Unmarshal(plain, &s.data) != nil || s.data.Config.Revision < 1 || len(s.data.Audit) > 1000 || validate(s.data.Config, s.data.Password) != nil {
		return nil, ErrInvalid
	}
	return s, nil
}
func validate(c Config, password string) error {
	if len(password) > 4096 {
		return ErrInvalid
	}
	if !c.Enabled && c.URL == "" && c.BaseDN == "" && c.BindDN == "" {
		return nil
	}
	if ldapclient.Validate(c.Config) != nil || (c.Enabled && password == "") {
		return ErrInvalid
	}
	return nil
}
func issuer(c Config) string {
	raw, _ := json.Marshal([]string{c.URL, c.BaseDN, c.BindDN, c.Filter, c.IdentityAttribute})
	sum := sha256.Sum256(raw)
	return "ldap:" + hex.EncodeToString(sum[:])
}
func (s *Service) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Snapshot{Config: s.data.Config, HasBindPassword: s.data.Password != ""}
}
func (s *Service) IssuerAllowed(value string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Config.Enabled && issuer(s.data.Config) == value
}
func (s *Service) Save(in Input, actorID, actor string) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.Revision != s.data.Config.Revision {
		return Snapshot{}, ErrConflict
	}
	if len(s.data.Audit) >= 1000 {
		return Snapshot{}, ErrCapacity
	}
	in.URL = strings.TrimSuffix(strings.TrimSpace(in.URL), "/")
	in.BaseDN = strings.TrimSpace(in.BaseDN)
	in.BindDN = strings.TrimSpace(in.BindDN)
	in.Filter = strings.TrimSpace(in.Filter)
	in.IdentityAttribute = strings.TrimSpace(in.IdentityAttribute)
	password := s.data.Password
	if in.ClearPassword {
		password = ""
	}
	if in.BindPassword != "" {
		password = in.BindPassword
	}
	if validate(in.Config, password) != nil {
		return Snapshot{}, ErrInvalid
	}
	next := persisted{Config: in.Config, Password: password, Audit: append([]Audit{}, s.data.Audit...)}
	next.Config.Revision++
	next.Audit = append(next.Audit, Audit{At: time.Now().UTC(), ActorID: actorID, Actor: actor, Config: next.Config})
	if e := s.persist(next); e != nil {
		return Snapshot{}, e
	}
	s.data = next
	s.Tickets.Reset()
	return Snapshot{Config: next.Config, HasBindPassword: password != ""}, nil
}
func (s *Service) Audit() []Audit {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]Audit{}, s.data.Audit...)
	slices.Reverse(out)
	return out
}
func (s *Service) current() (Config, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Config, s.data.Password
}
func (s *Service) Check(ctx context.Context) error {
	c, p := s.current()
	return s.directory.Check(ctx, c.Config, p)
}
func (s *Service) Lookup(ctx context.Context, username string) (Identity, error) {
	return s.resolve(ctx, username, "", false)
}
func (s *Service) Authenticate(ctx context.Context, username, password string) (Identity, error) {
	return s.resolve(ctx, username, password, true)
}
func (s *Service) resolve(ctx context.Context, username, password string, login bool) (Identity, error) {
	c, p := s.current()
	if login && !c.Enabled {
		return Identity{}, ErrDisabled
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return Identity{}, ErrCapacity
	}
	var id ldapclient.Identity
	var e error
	if login {
		id, e = s.directory.Authenticate(ctx, c.Config, p, username, password)
	} else {
		id, e = s.directory.Lookup(ctx, c.Config, p, username)
	}
	if e != nil {
		return Identity{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Config.Revision != c.Revision || (login && !s.data.Config.Enabled) {
		return Identity{}, ErrConflict
	}
	return Identity{Issuer: issuer(c), Subject: id.Subject, Provision: c.ProvisionNew, Revision: c.Revision}, nil
}
func (s *Service) NewPending(user string, revision int) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.data.Config.Enabled || s.data.Config.Revision != revision {
		return "", ErrConflict
	}
	return s.Tickets.Issue(user, revision)
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
		return p, logintickets.ErrTicket
	}
	return p, nil
}
func (s *Service) Consume(token string, revision int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ok := s.Tickets.Consume(token)
	return ok && s.data.Config.Enabled && s.data.Config.Revision == revision
}
func (s *Service) SetSetup(token, setup string) error { return s.Tickets.SetSetup(token, setup) }
func (s *Service) persist(next persisted) error {
	plain, e := json.Marshal(next)
	if e != nil {
		return e
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	raw, e := json.Marshal(envelope{Version: 1, Nonce: nonce, Ciphertext: s.aead.Seal(nil, nonce, plain, []byte("jms233/ldap/config/v1"))})
	if e != nil {
		return e
	}
	if s.documents != nil {
		return s.documents.Save("ldap-config", raw)
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".ldap-*")
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
