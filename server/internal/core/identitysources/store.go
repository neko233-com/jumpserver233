// Package identitysources owns the installation-wide identity-source registry.
// Provider secrets remain in independently encrypted, source-scoped documents.
package identitysources

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/neko233-com/jumpserver233/server/internal/connector/enterpriseoauth"
	"github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/caslogin"
	"github.com/neko233-com/jumpserver233/server/internal/core/enterpriselogin"
	"github.com/neko233-com/jumpserver233/server/internal/core/identityscope"
	"github.com/neko233-com/jumpserver233/server/internal/core/ldaplogin"
	"github.com/neko233-com/jumpserver233/server/internal/core/oidclogin"
	"github.com/neko233-com/jumpserver233/server/internal/core/samllogin"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

var (
	ErrInvalid  = errors.New("invalid identity source")
	ErrConflict = errors.New("identity source revision or request conflicts")
	ErrNotFound = errors.New("identity source not found")
	ErrCapacity = errors.New("identity source capacity reached")
	ErrClosed   = errors.New("identity source registry closed")
)

const maxBytes = 8 << 20

var requestPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,100}$`)

type Input struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Enabled   bool   `json:"enabled"`
	Archived  bool   `json:"archived"`
	Revision  int    `json:"revision"`
	RequestID string `json:"request_id,omitempty"`
}
type Source struct {
	Input
	Generation uint64    `json:"generation,omitempty"`
	ID         string    `json:"id"`
	UpdatedAt  time.Time `json:"updated_at"`
}
type Audit struct {
	At       time.Time `json:"at"`
	ActorID  string    `json:"actor_id"`
	SourceID string    `json:"source_id"`
	Action   string    `json:"action"`
	Revision int       `json:"revision"`
}
type receipt struct {
	ActorID, RequestID, Hash string
	Result                   Source
}
type state struct {
	Sources  map[string]Source `json:"sources"`
	Receipts []receipt         `json:"receipts"`
	Audit    []Audit           `json:"audit"`
}
type envelope struct {
	Version           int `json:"version"`
	Nonce, Ciphertext []byte
}

// Runtime is immutable after publication. Its enabled flag is checked without
// acquiring registry locks while auth holds its own credential lock.
type Runtime struct {
	Enterprise  *enterpriselogin.Service
	LDAP        *ldaplogin.Service
	OIDC        *oidclogin.Service
	CAS         *caslogin.Service
	SAML        *samllogin.Service
	enabled     atomic.Bool
	syncBlocked atomic.Bool
	generation  atomic.Uint64
	cookieKey   []byte
}

func (r *Runtime) Active() bool { return r != nil && r.enabled.Load() }
func (r *Runtime) Ready() bool {
	if !r.Active() || r.syncBlocked.Load() {
		return false
	}
	switch {
	case r.Enterprise != nil:
		return r.Enterprise.Available()
	case r.LDAP != nil:
		return r.LDAP.Snapshot().Enabled
	case r.OIDC != nil:
		return r.OIDC.Snapshot().Enabled
	case r.CAS != nil:
		return r.CAS.Snapshot().Enabled
	case r.SAML != nil:
		return r.SAML.Available()
	}
	return false
}
func (r *Runtime) allowed(issuer string) bool {
	if !r.Active() || r.syncBlocked.Load() {
		return false
	}
	switch {
	case r.Enterprise != nil:
		return r.Enterprise.IssuerAllowed(issuer)
	case r.LDAP != nil:
		return r.LDAP.IssuerAllowed(issuer)
	case r.OIDC != nil:
		return r.OIDC.IssuerAllowed(issuer)
	case r.CAS != nil:
		return r.CAS.IssuerAllowed(issuer)
	case r.SAML != nil:
		return r.SAML.IssuerAllowed(issuer)
	}
	return false
}
func (r *Runtime) SetSyncBlocked(blocked bool) { r.syncBlocked.Store(blocked) }
func (r *Runtime) Generation() uint64          { return r.generation.Load() }
func (r *Runtime) InvalidateFlows()            { r.generation.Add(1) }
func (r *Runtime) SealCookie(name, proof string, generation uint64) string {
	if proof == "" || len(proof) > 128 || generation != r.Generation() {
		return ""
	}
	body := strconv.FormatUint(generation, 10) + "." + base64.RawURLEncoding.EncodeToString([]byte(proof))
	mac := hmac.New(sha256.New, r.cookieKey)
	mac.Write([]byte(name + "\x00" + body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func (r *Runtime) OpenCookie(name, value string) string {
	if len(value) > 400 {
		return ""
	}
	generation, rest, ok := strings.Cut(value, ".")
	if !ok {
		return ""
	}
	proof, tag, ok := strings.Cut(rest, ".")
	if !ok {
		return ""
	}
	epoch, e := strconv.ParseUint(generation, 10, 64)
	if e != nil || epoch != r.Generation() || strconv.FormatUint(epoch, 10) != generation {
		return ""
	}
	mac := hmac.New(sha256.New, r.cookieKey)
	mac.Write([]byte(name + "\x00" + generation + "." + proof))
	decoded, e := base64.RawURLEncoding.DecodeString(tag)
	if e != nil || !hmac.Equal(decoded, mac.Sum(nil)) {
		return ""
	}
	raw, e := base64.RawURLEncoding.DecodeString(proof)
	if e != nil || len(raw) == 0 || len(raw) > 128 {
		return ""
	}
	return string(raw)
}

type Store struct {
	enterprise      enterpriseoauth.Provider
	closeDone       chan struct{}
	mu              sync.Mutex
	path, publicURL string
	key             []byte
	docs            *storage.Documents
	aead            cipher.AEAD
	auth            *auth.Service
	data            state
	runtimes        map[string]*Runtime
	closed          bool
}

func validText(s string, n int) bool {
	return utf8.ValidString(s) && len(s) <= n && strings.IndexFunc(s, unicode.IsControl) < 0
}
func prepare(in Input) (Input, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || !validText(in.Name, 160) || in.Revision < 0 || in.Revision >= 1_000_000_000 || in.Archived && in.Enabled {
		return in, ErrInvalid
	}
	if !identityscope.Kind(in.Kind) {
		return in, ErrInvalid
	}
	return in, nil
}
func validate(st state) error {
	if st.Sources == nil || len(st.Sources) > 100 || len(st.Receipts) > 2000 || len(st.Audit) > 2000 {
		return ErrInvalid
	}
	names := map[string]bool{}
	for id, s := range st.Sources {
		in, e := prepare(s.Input)
		if e != nil || in != s.Input || s.RequestID != "" || s.Revision < 1 || id != s.ID || !identityscope.ValidID(id) || s.UpdatedAt.IsZero() {
			return ErrInvalid
		}
		name := strings.ToLower(s.Name)
		if !s.Archived && names[name] {
			return ErrInvalid
		}
		if !s.Archived {
			names[name] = true
		}
	}
	for _, r := range st.Receipts {
		if r.ActorID == "" || !requestPattern.MatchString(r.RequestID) || len(r.Hash) != 64 || !identityscope.ValidID(r.Result.ID) {
			return ErrInvalid
		}
	}
	return nil
}

type Options struct{ EnterpriseProvider enterpriseoauth.Provider }

func Open(path string, key []byte, docs *storage.Documents, publicURL string, identities *auth.Service, options ...Options) (*Store, error) {
	if len(options) > 1 {
		return nil, ErrInvalid
	}
	var provider enterpriseoauth.Provider
	if len(options) == 1 {
		provider = options[0].EnterpriseProvider
	}
	if provider == nil {
		provider = enterpriseoauth.NewClient()
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	if identities == nil {
		return nil, ErrInvalid
	}
	s := &Store{enterprise: provider, closeDone: make(chan struct{}), path: path, publicURL: publicURL, key: slices.Clone(key), docs: docs, aead: a, auth: identities, runtimes: map[string]*Runtime{}, data: state{Sources: map[string]Source{}, Receipts: []receipt{}, Audit: []Audit{}}}
	var raw []byte
	if docs != nil {
		raw, e = docs.LoadOrImport("identity-sources", path)
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
		return nil, e
	}
	if len(raw) > 0 {
		var box envelope
		if len(raw) > 2*maxBytes || json.Unmarshal(raw, &box) != nil || box.Version != 1 || len(box.Nonce) != a.NonceSize() {
			return nil, ErrInvalid
		}
		plain, err := a.Open(nil, box.Nonce, box.Ciphertext, []byte("jms233/identity-sources/v1"))
		if err != nil || len(plain) > maxBytes || json.Unmarshal(plain, &s.data) != nil || validate(s.data) != nil {
			return nil, ErrInvalid
		}
	}
	for id, source := range s.data.Sources {
		r, err := s.openRuntime(source)
		if err != nil {
			s.Close()
			return nil, err
		}
		s.runtimes[id] = r
		r.enabled.Store(source.Enabled && !source.Archived)
		s.auth.SetNamedExternalSourceAllowed(source.Kind, id, r.allowed)
	}
	return s, nil
}
func (s *Store) openRuntime(source Source) (*Runtime, error) {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte("jms233/identity-source/v1\x00" + source.ID))
	key := mac.Sum(nil)
	var docs *storage.Documents
	var e error
	if s.docs != nil {
		docs, e = s.docs.Scoped(source.ID)
		if e != nil {
			return nil, e
		}
	}
	path := filepath.Join(filepath.Dir(s.path), "identity-sources", source.ID, source.Kind+".json")
	cookieMac := hmac.New(sha256.New, key)
	cookieMac.Write([]byte("jms233/identity-source/cookie/v1"))
	r := &Runtime{cookieKey: cookieMac.Sum(nil)}
	r.generation.Store(source.Generation)
	prefix := identityscope.Prefix(source.ID)
	switch source.Kind {
	case "ldap":
		r.LDAP, e = ldaplogin.Open(path, key, docs, nil)
	case "oidc":
		r.OIDC, e = oidclogin.Open(path, key, docs, s.publicURL, prefix)
	case "cas":
		r.CAS, e = caslogin.Open(path, key, docs, s.publicURL, nil, prefix)
	case "saml":
		r.SAML, e = samllogin.Open(path, key, docs, s.publicURL, prefix)
	case "wecom", "dingtalk", "feishu":
		r.Enterprise, e = enterpriselogin.Open(source.Kind, path, key, docs, s.publicURL, prefix, s.enterprise)
	default:
		e = ErrInvalid
	}
	return r, e
}
func clone(st state) state {
	n := state{Sources: map[string]Source{}, Receipts: slices.Clone(st.Receipts), Audit: slices.Clone(st.Audit)}
	for id, v := range st.Sources {
		n.Sources[id] = v
	}
	return n
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
	raw, e := json.Marshal(envelope{1, nonce, s.aead.Seal(nil, nonce, plain, []byte("jms233/identity-sources/v1"))})
	if e != nil {
		return e
	}
	if s.docs != nil {
		return s.docs.Save("identity-sources", raw)
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".identity-sources-*")
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
func (s *Store) Save(id, actor string, in Input) (Source, error) {
	var e error
	in, e = prepare(in)
	if e != nil || actor == "" || !validText(actor, 128) || !requestPattern.MatchString(in.RequestID) || id != "" && !identityscope.ValidID(id) {
		return Source{}, ErrInvalid
	}
	raw, _ := json.Marshal([]any{id, in})
	digest := sha256.Sum256(raw)
	hash := hex.EncodeToString(digest[:])
	request := in.RequestID
	in.RequestID = ""
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Source{}, ErrClosed
	}
	for _, r := range s.data.Receipts {
		if r.ActorID == actor && r.RequestID == request {
			if r.Hash != hash {
				return Source{}, ErrConflict
			}
			return r.Result, nil
		}
	}
	if len(s.data.Receipts) >= 2000 {
		return Source{}, ErrCapacity
	}
	old, exists := s.data.Sources[id]
	if id != "" && !exists {
		return Source{}, ErrNotFound
	}
	if in.Revision != old.Revision || exists && in.Kind != old.Kind {
		return Source{}, ErrConflict
	}
	for key, src := range s.data.Sources {
		if key != id && !src.Archived && !in.Archived && strings.EqualFold(src.Name, in.Name) {
			return Source{}, ErrConflict
		}
	}
	if !exists {
		if len(s.data.Sources) >= 100 || in.Archived {
			return Source{}, ErrCapacity
		}
		var b [16]byte
		if _, e = rand.Read(b[:]); e != nil {
			return Source{}, e
		}
		id = "idp-" + hex.EncodeToString(b[:])
	}
	result := Source{Input: in, ID: id, UpdatedAt: time.Now().UTC()}
	result.Revision++
	runtime := s.runtimes[id]
	if runtime == nil {
		runtime, e = s.openRuntime(result)
		if e != nil {
			return Source{}, e
		}
	}
	wasActive := runtime.Active()
	if exists && (old.Enabled && !in.Enabled || !old.Archived && in.Archived) {
		runtime.enabled.Store(false)
		runtime.InvalidateFlows()
		if e = s.auth.RevokeNamedExternalSource(old.Kind, id); e != nil {
			runtime.enabled.Store(wasActive)
			return Source{}, e
		}
	}
	result.Generation = runtime.Generation()
	next := clone(s.data)
	next.Sources[id] = result
	next.Receipts = append(next.Receipts, receipt{actor, request, hash, result})
	next.Audit = append(next.Audit, Audit{result.UpdatedAt, actor, id, "save", result.Revision})
	if len(next.Audit) > 2000 {
		next.Audit = next.Audit[len(next.Audit)-2000:]
	}
	if e = s.persist(next); e != nil {
		runtime.enabled.Store(wasActive)
		return Source{}, e
	}
	s.data = next
	s.runtimes[id] = runtime
	s.auth.SetNamedExternalSourceAllowed(in.Kind, id, runtime.allowed)
	runtime.enabled.Store(in.Enabled && !in.Archived)
	return result, nil
}
func (s *Store) List() []Source {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Source, 0, len(s.data.Sources))
	for _, v := range s.data.Sources {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].ID < out[j].ID
		}
		return out[i].Name < out[j].Name
	})
	return out
}
func (s *Store) Get(id string) (Source, *Runtime, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data.Sources[id]
	return v, s.runtimes[id], ok && !s.closed
}
func (s *Store) Audit() []Audit {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := slices.Clone(s.data.Audit)
	slices.Reverse(a)
	return a
}
func (s *Store) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		<-s.closeDone
		return
	}
	s.closed = true
	children := []*enterpriselogin.Service{}
	for _, r := range s.runtimes {
		r.enabled.Store(false)
		if r.Enterprise != nil {
			children = append(children, r.Enterprise)
		}
	}
	clear(s.key)
	s.mu.Unlock()
	for _, child := range children {
		child.Close()
	}
	close(s.closeDone)
}
