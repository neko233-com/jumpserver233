// Package sshcertificates owns organization-scoped SSH user CAs and account policies.
package sshcertificates

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
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

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	xssh "golang.org/x/crypto/ssh"
)

var (
	ErrInvalid     = errors.New("invalid SSH certificate policy")
	ErrNotFound    = errors.New("SSH certificate policy not found")
	ErrConflict    = errors.New("SSH certificate revision or request conflicts")
	ErrInUse       = errors.New("SSH issuer is still referenced")
	ErrUnavailable = errors.New("SSH certificate issuer unavailable")
	ErrCapacity    = errors.New("SSH certificate storage full")
	ErrClosed      = errors.New("SSH certificate store closed")
)
var idPattern = regexp.MustCompile(`^sshca-[a-f0-9]{32}$`)
var resourcePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var requestPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,100}$`)
var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

const maxState = 32 << 20

type Input struct {
	Name       string `json:"name"`
	Provider   string `json:"provider"`
	Enabled    bool   `json:"enabled"`
	TTLSeconds int    `json:"ttl_seconds"`
	Endpoint   string `json:"endpoint,omitempty"`
	Mount      string `json:"mount,omitempty"`
	Role       string `json:"role,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	RootCAPEM  string `json:"root_ca_pem,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`
	Token      string `json:"token,omitempty"`
	Revision   int    `json:"revision"`
	RequestID  string `json:"request_id,omitempty"`
}
type Issuer struct {
	Input
	PendingPublicKey string    `json:"pending_public_key,omitempty"`
	ID               string    `json:"id"`
	Fingerprint      string    `json:"fingerprint"`
	HasToken         bool      `json:"has_token"`
	TrustBundle      string    `json:"trust_bundle"`
	UpdatedAt        time.Time `json:"updated_at"`
}
type oldAuthority struct {
	PublicKey string    `json:"public_key"`
	Until     time.Time `json:"until"`
}
type authority struct {
	Input
	PendingPublicKey  string         `json:"pending_public_key,omitempty"`
	PendingPrivateKey []byte         `json:"pending_private_key,omitempty"`
	ID                string         `json:"id"`
	PrivateKey        []byte         `json:"private_key,omitempty"`
	SecretToken       string         `json:"secret_token,omitempty"`
	Previous          []oldAuthority `json:"previous"`
	UpdatedAt         time.Time      `json:"updated_at"`
}
type Target struct {
	AssetID     string `json:"asset_id"`
	ParentID    string `json:"parent_id,omitempty"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Fingerprint string `json:"fingerprint"`
	GatewayID   string `json:"gateway_id,omitempty"`
}
type BindingInput struct {
	IssuerID  string `json:"issuer_id"`
	Revision  int    `json:"revision"`
	RequestID string `json:"request_id"`
}
type Binding struct {
	AssetID      string    `json:"asset_id"`
	IssuerID     string    `json:"issuer_id"`
	EndpointHash string    `json:"endpoint_hash,omitempty"`
	Revision     int       `json:"revision"`
	UpdatedAt    time.Time `json:"updated_at,omitzero"`
}
type Audit struct {
	At          time.Time `json:"at"`
	ActorID     string    `json:"actor_id,omitempty"`
	Action      string    `json:"action"`
	IssuerID    string    `json:"issuer_id,omitempty"`
	AssetID     string    `json:"asset_id,omitempty"`
	Revision    int       `json:"revision,omitempty"`
	Serial      uint64    `json:"serial,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	ValidBefore time.Time `json:"valid_before,omitzero"`
}
type receipt struct {
	Actor   string          `json:"actor"`
	Request string          `json:"request"`
	Hash    string          `json:"hash"`
	Result  json.RawMessage `json:"result"`
}
type state struct {
	Issuers  map[string]authority `json:"issuers"`
	Bindings map[string]Binding   `json:"bindings"`
	Receipts []receipt            `json:"receipts"`
	Audit    []Audit              `json:"audit"`
	Serial   uint64               `json:"serial"`
}
type envelope struct {
	Version    int    `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}
type cached struct {
	Identity    string
	Credentials sshclient.Credentials
	Expires     time.Time
}
type issuance struct {
	done        chan struct{}
	credentials sshclient.Credentials
	err         error
}
type Store struct {
	mu      sync.Mutex
	path    string
	docs    *storage.Documents
	aead    cipher.AEAD
	hashKey []byte
	data    state
	cache   map[string]cached
	flights map[string]*issuance
	now     func() time.Time
	closed  bool
}

func text(v string, n int) bool {
	return utf8.ValidString(v) && utf8.RuneCountInString(v) <= n && strings.IndexFunc(v, unicode.IsControl) < 0
}
func ValidID(id string) bool      { return idPattern.MatchString(id) }
func ValidAssetID(id string) bool { return resourcePattern.MatchString(id) }
func ValidTarget(t Target) bool {
	return ValidAssetID(t.AssetID) && t.Host != "" && text(t.Host, 253) && t.Port > 0 && t.Port <= 65535 && t.Username != "" && text(t.Username, 128) && strings.HasPrefix(t.Fingerprint, "SHA256:") && (t.ParentID == "" || ValidAssetID(t.ParentID)) && (t.GatewayID == "" || ValidAssetID(t.GatewayID))
}
func Prepare(in Input) (Input, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Provider = strings.TrimSpace(in.Provider)
	in.Endpoint = strings.TrimRight(strings.TrimSpace(in.Endpoint), "/")
	in.Mount = strings.TrimSpace(in.Mount)
	in.Role = strings.TrimSpace(in.Role)
	in.PublicKey = strings.TrimSpace(in.PublicKey)
	in.Namespace = strings.TrimSpace(in.Namespace)
	if in.TTLSeconds == 0 {
		in.TTLSeconds = 300
	}
	if in.Name == "" || !text(in.Name, 128) || in.Revision < 0 || in.TTLSeconds < 60 || in.TTLSeconds > 600 || !text(in.Token, 8192) || !text(in.Namespace, 256) || len(in.RootCAPEM) > 65536 {
		return in, ErrInvalid
	}
	switch in.Provider {
	case "builtin":
		if in.Endpoint != "" || in.Mount != "" || in.Role != "" || in.Token != "" || in.Namespace != "" || in.RootCAPEM != "" {
			return in, ErrInvalid
		}
	case "openbao":
		if validateRemote(in) != nil {
			return in, ErrInvalid
		}
	default:
		return in, ErrInvalid
	}
	if in.PublicKey != "" {
		key, e := parseAuthority(in.PublicKey)
		if e != nil {
			return in, ErrInvalid
		}
		in.PublicKey = strings.TrimSpace(string(xssh.MarshalAuthorizedKey(key)))
	} else if in.Provider == "openbao" {
		return in, ErrInvalid
	}
	return in, nil
}
func public(a authority, now time.Time) Issuer {
	key, _ := parseAuthority(a.PublicKey)
	fingerprint := ""
	if key != nil {
		fingerprint = xssh.FingerprintSHA256(key)
	}
	bundle := a.PublicKey + "\n"
	if a.PendingPublicKey != "" {
		bundle += a.PendingPublicKey + "\n"
	}
	for _, old := range a.Previous {
		if now.Before(old.Until) {
			bundle += old.PublicKey + "\n"
		}
	}
	return Issuer{Input: a.Input, PendingPublicKey: a.PendingPublicKey, ID: a.ID, Fingerprint: fingerprint, HasToken: a.SecretToken != "", TrustBundle: bundle, UpdatedAt: a.UpdatedAt}
}
func validate(st state) error {
	if st.Issuers == nil || st.Bindings == nil || len(st.Issuers) > 100 || len(st.Bindings) > 20000 || len(st.Receipts) > 4000 || len(st.Audit) > 2000 {
		return ErrInvalid
	}
	names := map[string]bool{}
	for id, a := range st.Issuers {
		p, e := Prepare(a.Input)
		if e != nil || p != a.Input || a.ID != id || !ValidID(id) || a.RequestID != "" || a.Token != "" || a.Revision < 1 || a.UpdatedAt.IsZero() || len(a.Previous) > 10 || names[strings.ToLower(a.Name)] {
			return ErrInvalid
		}
		names[strings.ToLower(a.Name)] = true
		if a.Provider == "builtin" {
			if a.PendingPublicKey != "" {
				pending, e := xssh.ParsePrivateKey(a.PendingPrivateKey)
				if e != nil || strings.TrimSpace(string(xssh.MarshalAuthorizedKey(pending.PublicKey()))) != a.PendingPublicKey {
					return ErrInvalid
				}
			} else if len(a.PendingPrivateKey) > 0 {
				return ErrInvalid
			}
			signer, e := xssh.ParsePrivateKey(a.PrivateKey)
			if e != nil || strings.TrimSpace(string(xssh.MarshalAuthorizedKey(signer.PublicKey()))) != a.PublicKey || a.SecretToken != "" {
				return ErrInvalid
			}
		} else if len(a.PrivateKey) != 0 || a.PendingPublicKey != "" || len(a.PendingPrivateKey) > 0 || a.SecretToken == "" || !text(a.SecretToken, 8192) {
			return ErrInvalid
		}
		for _, old := range a.Previous {
			if _, e := parseAuthority(old.PublicKey); e != nil || old.Until.IsZero() {
				return ErrInvalid
			}
		}
	}
	for id, b := range st.Bindings {
		if id != b.AssetID || !ValidAssetID(id) || b.Revision < 1 || b.UpdatedAt.IsZero() {
			return ErrInvalid
		}
		if b.IssuerID != "" {
			if _, ok := st.Issuers[b.IssuerID]; !ok || !hashPattern.MatchString(b.EndpointHash) {
				return ErrInvalid
			}
		} else if b.EndpointHash != "" {
			return ErrInvalid
		}
	}
	seen := map[string]bool{}
	for _, r := range st.Receipts {
		k := r.Actor + "\x00" + r.Request
		if r.Actor == "" || !text(r.Actor, 128) || !requestPattern.MatchString(r.Request) || !hashPattern.MatchString(r.Hash) || !json.Valid(r.Result) || len(r.Result) > 1<<20 || seen[k] {
			return ErrInvalid
		}
		seen[k] = true
	}
	for _, a := range st.Audit {
		if a.At.IsZero() || a.ActorID != "" && !text(a.ActorID, 128) || a.IssuerID != "" && !ValidID(a.IssuerID) || a.AssetID != "" && !ValidAssetID(a.AssetID) {
			return ErrInvalid
		}
		switch a.Action {
		case "save", "rotate", "activate", "delete", "bind", "issue":
		default:
			return ErrInvalid
		}
	}
	return nil
}
func Open(path string, key []byte, docs *storage.Documents) (*Store, error) {
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	s := &Store{path: path, docs: docs, aead: aead, hashKey: append([]byte{}, key...), data: state{Issuers: map[string]authority{}, Bindings: map[string]Binding{}, Receipts: []receipt{}, Audit: []Audit{}}, cache: map[string]cached{}, flights: map[string]*issuance{}, now: time.Now}
	var raw []byte
	if docs != nil {
		raw, e = docs.LoadOrImport("ssh-certificates", path)
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
		return nil, e
	}
	if len(raw) == 0 {
		return s, nil
	}
	if len(raw) > 2*maxState {
		return nil, ErrInvalid
	}
	var box envelope
	if json.Unmarshal(raw, &box) != nil || box.Version != 1 || len(box.Nonce) != aead.NonceSize() {
		return nil, ErrInvalid
	}
	plain, e := aead.Open(nil, box.Nonce, box.Ciphertext, []byte("jms233/ssh-certificates/v1"))
	if e != nil || len(plain) > maxState {
		return nil, ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if dec.Decode(&s.data) != nil || dec.Decode(new(any)) != io.EOF || validate(s.data) != nil {
		return nil, ErrInvalid
	}
	return s, nil
}
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.cache = map[string]cached{}
	clear(s.hashKey)
}
func (s *Store) copy() state {
	st := state{Issuers: map[string]authority{}, Bindings: map[string]Binding{}, Receipts: append([]receipt{}, s.data.Receipts...), Audit: append([]Audit{}, s.data.Audit...), Serial: s.data.Serial}
	for id, a := range s.data.Issuers {
		a.Previous = append([]oldAuthority{}, a.Previous...)
		st.Issuers[id] = a
	}
	for id, b := range s.data.Bindings {
		st.Bindings[id] = b
	}
	return st
}
func (s *Store) persist(st state) error {
	if validate(st) != nil {
		return ErrInvalid
	}
	plain, e := json.Marshal(st)
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
	raw, e := json.Marshal(envelope{Version: 1, Nonce: nonce, Ciphertext: s.aead.Seal(nil, nonce, plain, []byte("jms233/ssh-certificates/v1"))})
	if e != nil {
		return e
	}
	if s.docs != nil {
		return s.docs.Save("ssh-certificates", raw)
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".ssh-certificates-*")
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
func digest(v any) string {
	raw, _ := json.Marshal(v)
	d := sha256.Sum256(raw)
	return hex.EncodeToString(d[:])
}
func (s *Store) requestDigest(v any) string {
	raw, _ := json.Marshal(v)
	h := hmac.New(sha256.New, s.hashKey)
	_, _ = h.Write([]byte("ssh-certificate-request/v1\x00"))
	_, _ = h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}
func (s *Store) replay(actor, request, hash string, out any) (bool, error) {
	for _, r := range s.data.Receipts {
		if r.Actor == actor && r.Request == request {
			if r.Hash != hash {
				return true, ErrConflict
			}
			if out != nil {
				return true, json.Unmarshal(r.Result, out)
			}
			return true, nil
		}
	}
	return false, nil
}
func appendAudit(st *state, a Audit) {
	st.Audit = append(st.Audit, a)
	if len(st.Audit) > 2000 {
		st.Audit = st.Audit[len(st.Audit)-2000:]
	}
}
func (s *Store) commit(st state, actor, request, hash string, result any, event Audit) error {
	if len(st.Receipts) >= 4000 {
		return ErrCapacity
	}
	raw, e := json.Marshal(result)
	if e != nil {
		return e
	}
	st.Receipts = append(st.Receipts, receipt{Actor: actor, Request: request, Hash: hash, Result: raw})
	appendAudit(&st, event)
	if e = s.persist(st); e != nil {
		return e
	}
	s.data = st
	s.cache = map[string]cached{}
	return nil
}
func validRequest(actor, request string) bool {
	return actor != "" && text(actor, 128) && requestPattern.MatchString(request)
}
func generateCA() (string, []byte, error) {
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return "", nil, e
	}
	encoded, e := xssh.MarshalPrivateKey(key, "")
	if e != nil {
		return "", nil, e
	}
	signer, e := xssh.NewSignerFromKey(key)
	if e != nil {
		return "", nil, e
	}
	return strings.TrimSpace(string(xssh.MarshalAuthorizedKey(signer.PublicKey()))), encodePEM(encoded), nil
}

func (s *Store) Save(id, actor string, in Input) (Issuer, error) {
	in, e := Prepare(in)
	if e != nil || !validRequest(actor, in.RequestID) || id != "" && !ValidID(id) {
		return Issuer{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Issuer{}, ErrClosed
	}
	hash := s.requestDigest([]any{"save", id, in})
	var result Issuer
	if yes, e := s.replay(actor, in.RequestID, hash, &result); yes {
		return result, e
	}
	st := s.copy()
	old, exists := st.Issuers[id]
	if id != "" && !exists {
		return Issuer{}, ErrNotFound
	}
	if exists && old.Revision != in.Revision || !exists && in.Revision != 0 {
		return Issuer{}, ErrConflict
	}
	if exists && old.Provider != in.Provider {
		return Issuer{}, ErrInvalid
	}
	for other, a := range st.Issuers {
		if other != id && strings.EqualFold(a.Name, in.Name) {
			return Issuer{}, ErrConflict
		}
	}
	if !exists {
		if len(st.Issuers) >= 100 {
			return Issuer{}, ErrCapacity
		}
		raw := make([]byte, 16)
		if _, e = rand.Read(raw); e != nil {
			return Issuer{}, e
		}
		id = "sshca-" + hex.EncodeToString(raw)
		if _, collision := st.Issuers[id]; collision {
			return Issuer{}, ErrConflict
		}
	}
	a := old
	a.ID = id
	a.Input = in
	a.Input.Token = ""
	a.Input.RequestID = ""
	a.Revision++
	a.UpdatedAt = s.now().UTC()
	if a.Previous == nil {
		a.Previous = []oldAuthority{}
	}
	if in.Provider == "builtin" {
		if !exists {
			if in.PublicKey != "" {
				return Issuer{}, ErrInvalid
			}
			a.PublicKey, a.PrivateKey, e = generateCA()
			if e != nil {
				return Issuer{}, e
			}
		} else {
			if in.PublicKey != "" && in.PublicKey != old.PublicKey {
				return Issuer{}, ErrInvalid
			}
			a.PublicKey = old.PublicKey
		}
	} else {
		a.SecretToken = in.Token
		if a.SecretToken == "" {
			a.SecretToken = old.SecretToken
		}
		if a.SecretToken == "" {
			return Issuer{}, ErrInvalid
		}
		if exists && old.PublicKey != a.PublicKey {
			a.Previous = retainPrevious(old, s.now())
		}
	}
	if len(a.Previous) > 10 {
		return Issuer{}, ErrCapacity
	}
	st.Issuers[id] = a
	result = public(a, s.now())
	e = s.commit(st, actor, in.RequestID, hash, result, Audit{At: s.now().UTC(), ActorID: actor, Action: "save", IssuerID: id, Revision: a.Revision})
	return result, e
}
func retainPrevious(old authority, now time.Time) []oldAuthority {
	out := []oldAuthority{}
	for _, key := range old.Previous {
		if now.Before(key.Until) {
			out = append(out, key)
		}
	}
	return append(out, oldAuthority{PublicKey: old.PublicKey, Until: now.UTC().Add(11 * time.Minute)})
}
func (s *Store) Rotate(id, actor string, revision int, request string) (Issuer, error) {
	if !ValidID(id) || revision < 1 || !validRequest(actor, request) {
		return Issuer{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Issuer{}, ErrClosed
	}
	hash := s.requestDigest([]any{"rotate", id, revision})
	var result Issuer
	if yes, e := s.replay(actor, request, hash, &result); yes {
		return result, e
	}
	st := s.copy()
	a, ok := st.Issuers[id]
	if !ok {
		return Issuer{}, ErrNotFound
	}
	if a.Revision != revision {
		return Issuer{}, ErrConflict
	}
	if a.Provider != "builtin" {
		return Issuer{}, ErrInvalid
	}
	if a.PendingPublicKey != "" {
		return Issuer{}, ErrConflict
	}
	var e error
	a.PendingPublicKey, a.PendingPrivateKey, e = generateCA()
	if e != nil {
		return Issuer{}, e
	}
	a.Revision++
	a.UpdatedAt = s.now().UTC()
	st.Issuers[id] = a
	result = public(a, s.now())
	e = s.commit(st, actor, request, hash, result, Audit{At: s.now().UTC(), ActorID: actor, Action: "rotate", IssuerID: id, Revision: a.Revision})
	return result, e
}
func (s *Store) Activate(id, actor string, revision int, request string) (Issuer, error) {
	if !ValidID(id) || revision < 1 || !validRequest(actor, request) {
		return Issuer{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Issuer{}, ErrClosed
	}
	hash := s.requestDigest([]any{"activate", id, revision})
	var result Issuer
	if yes, e := s.replay(actor, request, hash, &result); yes {
		return result, e
	}
	st := s.copy()
	a, ok := st.Issuers[id]
	if !ok {
		return Issuer{}, ErrNotFound
	}
	if a.Revision != revision {
		return Issuer{}, ErrConflict
	}
	if a.Provider != "builtin" || a.PendingPublicKey == "" {
		return Issuer{}, ErrInvalid
	}
	a.Previous = retainPrevious(a, s.now())
	if len(a.Previous) > 10 {
		return Issuer{}, ErrCapacity
	}
	a.PublicKey, a.PrivateKey = a.PendingPublicKey, a.PendingPrivateKey
	a.PendingPublicKey = ""
	a.PendingPrivateKey = nil
	a.Revision++
	a.UpdatedAt = s.now().UTC()
	st.Issuers[id] = a
	result = public(a, s.now())
	e := s.commit(st, actor, request, hash, result, Audit{At: s.now().UTC(), ActorID: actor, Action: "activate", IssuerID: id, Revision: a.Revision})
	return result, e
}
func (s *Store) Delete(id, actor string, revision int, request string, missing ...map[string]bool) error {
	if !ValidID(id) || revision < 1 || !validRequest(actor, request) {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	hash := s.requestDigest([]any{"delete", id, revision})
	if yes, e := s.replay(actor, request, hash, nil); yes {
		return e
	}
	st := s.copy()
	a, ok := st.Issuers[id]
	if !ok {
		return ErrNotFound
	}
	if a.Revision != revision {
		return ErrConflict
	}
	for assetID, b := range st.Bindings {
		if b.IssuerID == id {
			if len(missing) == 0 || !missing[0][assetID] {
				return ErrInUse
			}
			delete(st.Bindings, assetID)
		}
	}
	delete(st.Issuers, id)
	return s.commit(st, actor, request, hash, map[string]bool{"deleted": true}, Audit{At: s.now().UTC(), ActorID: actor, Action: "delete", IssuerID: id, Revision: revision})
}

// References is read before taking inventory locks; Delete then consumes only
// IDs independently proven absent, avoiding an inventory/issuer lock inversion.
func (s *Store) References(id string) ([]string, error) {
	if !ValidID(id) {
		return nil, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	ids := []string{}
	for assetID, b := range s.data.Bindings {
		if b.IssuerID == id {
			ids = append(ids, assetID)
		}
	}
	return ids, nil
}
func (s *Store) Issuers() ([]Issuer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	out := []Issuer{}
	for _, a := range s.data.Issuers {
		out = append(out, public(a, s.now()))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (s *Store) Binding(id string) (Binding, error) {
	if !ValidAssetID(id) {
		return Binding{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Binding{}, ErrClosed
	}
	b, ok := s.data.Bindings[id]
	if !ok {
		b.AssetID = id
	}
	return b, nil
}
func (s *Store) Bind(target Target, actor string, in BindingInput) (Binding, error) {
	if !ValidTarget(target) || !validRequest(actor, in.RequestID) || in.Revision < 0 || in.IssuerID != "" && !ValidID(in.IssuerID) {
		return Binding{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Binding{}, ErrClosed
	}
	hash := s.requestDigest([]any{"bind", target, in})
	var result Binding
	if yes, e := s.replay(actor, in.RequestID, hash, &result); yes {
		return result, e
	}
	st := s.copy()
	current, exists := st.Bindings[target.AssetID]
	if current.Revision != in.Revision {
		return Binding{}, ErrConflict
	}
	if !exists && len(st.Bindings) >= 20000 {
		return Binding{}, ErrCapacity
	}
	if in.IssuerID != "" {
		if a, ok := st.Issuers[in.IssuerID]; !ok || !a.Enabled {
			return Binding{}, ErrUnavailable
		}
	}
	result = Binding{AssetID: target.AssetID, IssuerID: in.IssuerID, Revision: current.Revision + 1, UpdatedAt: s.now().UTC()}
	if in.IssuerID != "" {
		result.EndpointHash = digest(target)
	}
	st.Bindings[target.AssetID] = result
	e := s.commit(st, actor, in.RequestID, hash, result, Audit{At: s.now().UTC(), ActorID: actor, Action: "bind", IssuerID: in.IssuerID, AssetID: target.AssetID, Revision: result.Revision})
	return result, e
}
func (s *Store) identity(id string) string {
	b, exists := s.data.Bindings[id]
	if !exists {
		return ""
	}
	a := s.data.Issuers[b.IssuerID]
	return digest([]any{b, a.Revision, a.Enabled, a.PublicKey})
}
func (s *Store) ConnectionIdentity(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", ErrClosed
	}
	return s.identity(id), nil
}
func (s *Store) Required(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed || s.data.Bindings[id].IssuerID != ""
}
func (s *Store) Audit(offset, limit int) ([]Audit, int, error) {
	if offset < 0 || limit < 1 || limit > 100 {
		return nil, 0, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, 0, ErrClosed
	}
	rows := append([]Audit{}, s.data.Audit...)
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	total := len(rows)
	offset = min(offset, total)
	return rows[offset:min(offset+limit, total)], total, nil
}
