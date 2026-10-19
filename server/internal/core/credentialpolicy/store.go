package credentialpolicy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Settings struct {
	Rules
	Revision int `json:"revision"`
}
type Input struct {
	RequestID string   `json:"request_id"`
	Policy    Settings `json:"policy"`
}
type Audit struct {
	At      time.Time `json:"at"`
	ActorID string    `json:"actor_id"`
	Actor   string    `json:"actor"`
	Before  Settings  `json:"before"`
	After   Settings  `json:"after"`
}
type receipt struct {
	Input   Input  `json:"input"`
	ActorID string `json:"actor_id"`
}
type state struct {
	Version  int       `json:"version"`
	Policy   Settings  `json:"policy"`
	Audit    []Audit   `json:"audit"`
	Receipts []receipt `json:"receipts"`
}
type envelope struct {
	Version    int    `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}
type Store struct {
	mu   sync.RWMutex
	path string
	docs *storage.Documents
	aead cipher.AEAD
	data state
}

var requestID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func Open(path string, key []byte, docs *storage.Documents) (*Store, error) {
	if len(key) != 32 {
		return nil, ErrInvalid
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	s := &Store{path: path, docs: docs, aead: aead, data: state{Version: 1, Policy: Settings{Rules: Defaults(), Revision: 1}, Audit: []Audit{}, Receipts: []receipt{}}}
	var body []byte
	if docs != nil {
		body, e = docs.LoadOrImport("ssh-password-policy", path)
	} else {
		body, e = os.ReadFile(path)
		if errors.Is(e, os.ErrNotExist) {
			e = nil
		}
	}
	if e != nil {
		return nil, e
	}
	if len(body) == 0 {
		return s, nil
	}
	var box envelope
	if len(body) > 2<<20 || json.Unmarshal(body, &box) != nil || box.Version != 1 || len(box.Nonce) != aead.NonceSize() {
		return nil, ErrInvalid
	}
	plain, e := aead.Open(nil, box.Nonce, box.Ciphertext, []byte("ssh-password-policy/v1"))
	if e != nil {
		return nil, ErrInvalid
	}
	if json.Unmarshal(plain, &s.data) != nil || s.data.Version != 1 || !s.data.Policy.Rules.Valid() || s.data.Policy.Revision < 1 || len(s.data.Audit) > 200 || len(s.data.Receipts) > 100 {
		return nil, ErrInvalid
	}
	ids := map[string]bool{}
	for _, v := range s.data.Receipts {
		if !requestID.MatchString(v.Input.RequestID) || v.ActorID == "" || !v.Input.Policy.Rules.Valid() || v.Input.Policy.Revision < 1 || ids[v.Input.RequestID] {
			return nil, ErrInvalid
		}
		ids[v.Input.RequestID] = true
	}
	for _, a := range s.data.Audit {
		if a.At.IsZero() || a.ActorID == "" || !a.Before.Rules.Valid() || !a.After.Rules.Valid() || a.After.Revision != a.Before.Revision+1 {
			return nil, ErrInvalid
		}
	}
	return s, nil
}
func (s *Store) Snapshot() Settings { s.mu.RLock(); defer s.mu.RUnlock(); return s.data.Policy }
func (s *Store) Audit() []Audit {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Audit{}, s.data.Audit...)
}
func (s *Store) Save(in Input, actorID, actor string) (Settings, error) {
	if !requestID.MatchString(in.RequestID) || !in.Policy.Rules.Valid() || in.Policy.Revision < 1 || strings.TrimSpace(actorID) == "" || len(actorID) > 128 || len(actor) > 128 {
		return Settings{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.data.Receipts {
		if r.Input.RequestID == in.RequestID {
			if r.ActorID != actorID || !reflect.DeepEqual(r.Input, in) {
				return Settings{}, ErrConflict
			}
			return s.data.Policy, nil
		}
	}
	if in.Policy.Revision != s.data.Policy.Revision {
		return Settings{}, ErrConflict
	}
	next := s.data
	next.Audit = append([]Audit{}, s.data.Audit...)
	next.Receipts = append([]receipt{}, s.data.Receipts...)
	if in.Policy.Rules != next.Policy.Rules {
		before := next.Policy
		next.Policy = in.Policy
		next.Policy.Revision++
		next.Audit = append(next.Audit, Audit{At: time.Now().UTC(), ActorID: actorID, Actor: actor, Before: before, After: next.Policy})
	}
	next.Receipts = append(next.Receipts, receipt{Input: in, ActorID: actorID})
	if len(next.Audit) > 200 {
		next.Audit = next.Audit[len(next.Audit)-200:]
	}
	if len(next.Receipts) > 100 {
		next.Receipts = next.Receipts[len(next.Receipts)-100:]
	}
	plain, e := json.Marshal(next)
	if e != nil {
		return Settings{}, e
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return Settings{}, e
	}
	body, e := json.Marshal(envelope{Version: 1, Nonce: nonce, Ciphertext: s.aead.Seal(nil, nonce, plain, []byte("ssh-password-policy/v1"))})
	if e != nil {
		return Settings{}, e
	}
	if s.docs != nil {
		e = s.docs.Save("ssh-password-policy", body)
	} else {
		e = atomicWrite(s.path, body)
	}
	if e != nil {
		return Settings{}, e
	}
	s.data = next
	return next.Policy, nil
}
func atomicWrite(path string, body []byte) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".ssh-password-policy-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(body)
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
	return os.Rename(f.Name(), path)
}
