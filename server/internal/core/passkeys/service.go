package passkeys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/neko233-com/jumpserver233/server/internal/connector/passkeyclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/logintickets"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

var ErrInvalid = errors.New("invalid Passkey request or store")
var ErrDisabled = errors.New("Passkey unavailable or disabled")
var ErrFlow = errors.New("Passkey flow invalid or expired")
var ErrConflict = errors.New("Passkey state changed")
var ErrNotFound = errors.New("Passkey not found")
var ErrCapacity = errors.New("Passkey capacity reached")
var ErrClone = errors.New("Passkey signature counter warning")

type Config struct {
	Enabled   bool   `json:"enabled"`
	Revision  int    `json:"revision"`
	Available bool   `json:"available"`
	Origin    string `json:"origin"`
	RPID      string `json:"rp_id"`
}
type Metadata struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RPID       string     `json:"rp_id"`
	BackedUp   bool       `json:"backed_up"`
	Disabled   bool       `json:"disabled"`
}
type Record struct {
	Metadata
	UserID     string
	Username   string
	Credential passkeyclient.Credential
	Version    int
}
type Audit struct {
	At           time.Time `json:"at"`
	ActorID      string    `json:"actor_id"`
	Actor        string    `json:"actor"`
	Kind         string    `json:"kind"`
	CredentialID string    `json:"credential_id,omitempty"`
	Enabled      bool      `json:"enabled"`
	Revision     int       `json:"revision"`
}
type persisted struct {
	Enabled  bool
	Revision int
	Records  map[string]Record
	Audit    []Audit
}
type envelope struct {
	Version           int
	Nonce, Ciphertext []byte
}
type flow struct {
	Kind              string
	Session           passkeyclient.Session
	User              auth.User
	Bound             [32]byte
	Name              string
	Revision          int
	Expires           time.Time
	ManagementVersion string
}
type Start struct {
	Token   string
	Options any
}
type Service struct {
	mu           sync.Mutex
	path, origin string
	aead         cipher.AEAD
	documents    *storage.Documents
	client       *passkeyclient.Client
	data         persisted
	flows        map[[32]byte]flow
	Tickets      *logintickets.Store
	now          func() time.Time
	slots        chan struct{}
}

func Open(path string, key []byte, docs *storage.Documents, origin string) (*Service, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	cl, _ := passkeyclient.New(origin)
	s := &Service{path: path, origin: origin, aead: a, documents: docs, client: cl, data: persisted{Records: map[string]Record{}, Audit: []Audit{}}, flows: map[[32]byte]flow{}, Tickets: logintickets.New(), now: time.Now, slots: make(chan struct{}, 4)}
	var raw []byte
	if docs != nil {
		raw, e = docs.LoadOrImport("passkeys", path)
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
	plain, e := a.Open(nil, env.Nonce, env.Ciphertext, []byte("jms233/passkeys/v1"))
	if e != nil || json.Unmarshal(plain, &s.data) != nil || s.data.Revision < 0 || s.data.Records == nil || len(s.data.Records) > 10000 || len(s.data.Audit) > 1000 {
		return nil, ErrInvalid
	}
	seen := map[string]bool{}
	for id, r := range s.data.Records {
		if seen[keyID(r.Credential.ID)] {
			return nil, ErrInvalid
		}
		seen[keyID(r.Credential.ID)] = true
		if len(id) > 128 || r.ID != id || r.UserID == "" || r.RPID == "" || r.Version < 1 || !validName(r.Name) || len(r.Credential.ID) == 0 || len(r.Credential.ID) > 1024 || len(r.Credential.PublicKey) == 0 || len(r.Credential.PublicKey) > 8192 {
			return nil, ErrInvalid
		}
	}
	return s, nil
}
func (s *Service) available() bool { return s.data.Enabled && s.client != nil }
func (s *Service) Snapshot() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	rp := ""
	if s.client != nil {
		rp = s.client.RPID
	}
	return Config{Enabled: s.data.Enabled, Revision: s.data.Revision, Available: s.available(), Origin: s.origin, RPID: rp}
}
func event(data *persisted, at time.Time, actorID, actor, kind, id string) {
	data.Audit = append(append([]Audit{}, data.Audit...), Audit{At: at.UTC(), ActorID: actorID, Actor: actor, Kind: kind, CredentialID: id, Enabled: data.Enabled, Revision: data.Revision})
	if len(data.Audit) > 1000 {
		data.Audit = data.Audit[len(data.Audit)-1000:]
	}
}
func (s *Service) Save(c Config, actorID, actor string) (Config, error) {
	s.mu.Lock()
	if c.Revision != s.data.Revision {
		s.mu.Unlock()
		return Config{}, ErrConflict
	}
	if c.Enabled && s.client == nil {
		s.mu.Unlock()
		return Config{}, ErrDisabled
	}
	next := s.data
	next.Enabled = c.Enabled
	next.Revision++
	event(&next, s.now(), actorID, actor, "configure", "")
	if e := s.persist(next); e != nil {
		s.mu.Unlock()
		return Config{}, e
	}
	s.data = next
	s.flows = map[[32]byte]flow{}
	s.Tickets.Reset()
	rpID := ""
	if s.client != nil {
		rpID = s.client.RPID
	}
	out := Config{Enabled: next.Enabled, Revision: next.Revision, Available: s.available(), Origin: s.origin, RPID: rpID}
	s.mu.Unlock()
	return out, nil
}
func (s *Service) Audit(userID string) []Audit {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Audit{}
	for _, a := range s.data.Audit {
		if userID == "" || a.ActorID == userID {
			out = append(out, a)
		}
	}
	slices.Reverse(out)
	return out
}
func (s *Service) List(userID string) []Metadata {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Metadata{}
	for _, r := range s.data.Records {
		if r.UserID == userID {
			out = append(out, r.Metadata)
		}
	}
	slices.SortFunc(out, func(a, b Metadata) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out
}
func (s *Service) Allowed(userID, id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allowedSession(userID, id)
}
func (s *Service) allowedSession(userID, proof string) bool {
	epoch, id, ok := strings.Cut(proof, ".")
	revision, e := strconv.Atoi(epoch)
	return ok && e == nil && revision == s.data.Revision && s.allowed(userID, id)
}
func (s *Service) sessionID(id string) string { return strconv.Itoa(s.data.Revision) + "." + id }
func (s *Service) allowed(userID, id string) bool {
	r, ok := s.data.Records[id]
	return s.available() && ok && !r.Disabled && r.UserID == userID && r.RPID == s.client.RPID
}
func (s *Service) byCredentialID(id []byte) (Record, bool) {
	for _, r := range s.data.Records {
		if bytes.Equal(r.Credential.ID, id) {
			return r, true
		}
	}
	return Record{}, false
}

func keyID(id []byte) string {
	h := sha256.Sum256(id)
	return base64.RawURLEncoding.EncodeToString(h[:])
}
func validName(v string) bool {
	if v == "" || len(v) > 120 || !utf8.ValidString(v) || strings.TrimSpace(v) != v {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func randomValue() (string, error) {
	var raw [32]byte
	if _, e := rand.Read(raw[:]); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
func (s *Service) credentials(user auth.User) passkeyclient.User {
	u := passkeyclient.User{ID: user.ID, Name: user.Username, Credentials: []passkeyclient.Credential{}}
	for _, r := range s.data.Records {
		if r.UserID == user.ID && s.client != nil && r.RPID == s.client.RPID && !r.Disabled {
			u.Credentials = append(u.Credentials, r.Credential)
		}
	}
	return u
}
func (s *Service) addFlow(f flow, options any) (Start, error) {
	for k, v := range s.flows {
		if !s.now().Before(v.Expires) {
			delete(s.flows, k)
		}
	}
	if len(s.flows) >= 4096 {
		return Start{}, ErrCapacity
	}
	token, e := randomValue()
	if e != nil {
		return Start{}, e
	}
	f.Revision = s.data.Revision
	f.Expires = s.now().Add(5 * time.Minute)
	s.flows[sha256.Sum256([]byte(token))] = f
	return Start{Token: token, Options: options}, nil
}
func (s *Service) BeginRegistration(user auth.User, name, sessionToken, managementVersion string) (Start, error) {
	name = strings.TrimSpace(name)
	if !validName(name) || user.ID == "" || sessionToken == "" || managementVersion == "" || len(managementVersion) > 128 {
		return Start{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.available() {
		return Start{}, ErrDisabled
	}
	count := 0
	for _, r := range s.data.Records {
		if r.UserID == user.ID {
			count++
		}
	}
	if count >= 10 || len(s.data.Records) >= 10000 {
		return Start{}, ErrCapacity
	}
	op, session, e := s.client.BeginRegistration(s.credentials(user))
	if e != nil {
		return Start{}, e
	}
	return s.addFlow(flow{Kind: "register", Session: *session, User: user, Name: name, ManagementVersion: managementVersion, Bound: sha256.Sum256([]byte(sessionToken))}, op)
}
func (s *Service) consumeFlow(token, kind string) (flow, *passkeyclient.Client, error) {
	if token == "" || len(token) > 128 {
		return flow{}, nil, ErrFlow
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := sha256.Sum256([]byte(token))
	f, ok := s.flows[k]
	delete(s.flows, k)
	if !ok || f.Kind != kind || !s.now().Before(f.Expires) || !s.available() || f.Revision != s.data.Revision {
		return flow{}, nil, ErrFlow
	}
	return f, s.client, nil
}
func (s *Service) FinishRegistration(token, sessionToken string, user auth.User, raw []byte, managementVersion string) (Metadata, error) {
	f, cl, e := s.consumeFlow(token, "register")
	if e != nil {
		return Metadata{}, e
	}
	if f.ManagementVersion != managementVersion || f.User.ID != user.ID || f.User.Source != user.Source || f.User.MFAEnabled != user.MFAEnabled || f.Bound != sha256.Sum256([]byte(sessionToken)) {
		return Metadata{}, ErrFlow
	}
	s.mu.Lock()
	u := s.credentials(user)
	s.mu.Unlock()
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return Metadata{}, ErrCapacity
	}
	cred, e := cl.VerifyRegistration(u, f.Session, raw)
	if e != nil {
		return Metadata{}, e
	}
	encoded, e := json.Marshal(cred)
	if e != nil || len(encoded) > 32768 {
		return Metadata{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.available() || f.Revision != s.data.Revision {
		return Metadata{}, ErrConflict
	}
	id, e := randomValue()
	if e != nil {
		return Metadata{}, e
	}
	if _, ok := s.byCredentialID(cred.ID); ok {
		return Metadata{}, ErrConflict
	}
	count := 0
	for _, r := range s.data.Records {
		if r.UserID == user.ID {
			count++
		}
	}
	if count >= 10 || len(s.data.Records) >= 10000 {
		return Metadata{}, ErrCapacity
	}
	r := Record{Metadata: Metadata{ID: id, Name: f.Name, CreatedAt: s.now().UTC(), RPID: cl.RPID, BackedUp: cred.Flags.BackupState}, UserID: user.ID, Username: user.Username, Credential: *cred, Version: 1}
	next := s.data
	next.Records = copyRecords(s.data.Records)
	next.Records[id] = r
	event(&next, s.now(), user.ID, user.Username, "register", id)
	if e = s.persist(next); e != nil {
		return Metadata{}, e
	}
	s.data = next
	return r.Metadata, nil
}
func copyRecords(in map[string]Record) map[string]Record {
	out := make(map[string]Record, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
func (s *Service) BeginLogin() (Start, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.available() {
		return Start{}, ErrDisabled
	}
	op, session, e := s.client.BeginLogin()
	if e != nil {
		return Start{}, e
	}
	return s.addFlow(flow{Kind: "login", Session: *session}, op)
}
func (s *Service) FinishLogin(token string, raw []byte) (string, error) {
	f, cl, e := s.consumeFlow(token, "login")
	if e != nil {
		return "", e
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return "", ErrCapacity
	}
	var snapshot Record
	_, cred, e := cl.VerifyLogin(f.Session, raw, func(id, handle []byte) (passkeyclient.User, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		r, ok := s.byCredentialID(id)
		if !ok || !s.allowed(r.UserID, r.ID) || !bytes.Equal(passkeyclient.Handle(r.UserID), handle) || !bytes.Equal(r.Credential.ID, id) {
			return passkeyclient.User{}, ErrNotFound
		}
		snapshot = r
		return passkeyclient.User{ID: r.UserID, Name: r.Username, Credentials: []passkeyclient.Credential{r.Credential}}, nil
	})
	if e != nil {
		return "", e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.data.Records[snapshot.ID]
	if !ok || !s.allowed(current.UserID, current.ID) || current.Version != snapshot.Version || f.Revision != s.data.Revision {
		return "", ErrConflict
	}
	next := s.data
	next.Records = copyRecords(s.data.Records)
	current.Version++
	current.Credential = *cred
	now := s.now().UTC()
	current.LastUsedAt = &now
	current.BackedUp = cred.Flags.BackupState
	kind := "verify"
	if cred.Authenticator.CloneWarning {
		current.Disabled = true
		kind = "counter_warning"
	}
	next.Records[current.ID] = current
	event(&next, now, current.UserID, current.Username, kind, current.ID)
	if e = s.persist(next); e != nil {
		return "", e
	}
	s.data = next
	if current.Disabled {
		return "", ErrClone
	}
	return s.Tickets.Issue(current.UserID, s.data.Revision, s.sessionID(current.ID))
}
func (s *Service) Pending(token string, attempt bool) (logintickets.Ticket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, e := s.Tickets.Read(token, attempt)
	if e != nil {
		return p, e
	}
	if p.Revision != s.data.Revision || !s.allowedSession(p.UserID, p.CredentialID) {
		s.Tickets.Consume(token)
		return p, ErrFlow
	}
	return p, nil
}
func (s *Service) SetSetup(token, setup string) error { return s.Tickets.SetSetup(token, setup) }
func (s *Service) Consume(token string, revision int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.Tickets.Take(token)
	return ok && p.Revision == revision && revision == s.data.Revision && s.allowedSession(p.UserID, p.CredentialID)
}
func (s *Service) Delete(user auth.User, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.data.Records[id]
	if !ok || r.UserID != user.ID {
		return ErrNotFound
	}
	next := s.data
	next.Records = copyRecords(s.data.Records)
	delete(next.Records, id)
	event(&next, s.now(), user.ID, user.Username, "delete", id)
	if e := s.persist(next); e != nil {
		return e
	}
	s.data = next
	return nil
}
func (s *Service) Rename(user auth.User, id, name string) (Metadata, error) {
	name = strings.TrimSpace(name)
	if !validName(name) {
		return Metadata{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.data.Records[id]
	if !ok || r.UserID != user.ID {
		return Metadata{}, ErrNotFound
	}
	next := s.data
	next.Records = copyRecords(s.data.Records)
	r.Name = name
	next.Records[id] = r
	event(&next, s.now(), user.ID, user.Username, "rename", id)
	if e := s.persist(next); e != nil {
		return Metadata{}, e
	}
	s.data = next
	return r.Metadata, nil
}
func (s *Service) Cancel(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.flows, sha256.Sum256([]byte(token)))
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
	raw, e := json.Marshal(envelope{Version: 1, Nonce: nonce, Ciphertext: s.aead.Seal(nil, nonce, plain, []byte("jms233/passkeys/v1"))})
	if e != nil {
		return e
	}
	if s.documents != nil {
		return s.documents.Save("passkeys", raw)
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".passkeys-*")
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
