// Package passwordvault provides encrypted private and organization-shared logins.
package passwordvault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

var ErrInvalid = errors.New("invalid vault request")
var ErrNotFound = errors.New("vault item not found")
var ErrDenied = errors.New("vault access denied")
var ErrConflict = errors.New("vault revision conflict")

type Item struct {
	ID               string `json:"id"`
	Owner            string `json:"-"`
	Kind             string `json:"kind"`
	Title            string `json:"title"`
	Site             string `json:"site"`
	Username         string `json:"username"`
	Shared           bool   `json:"shared"`
	CanManageSharing bool   `json:"can_manage_sharing,omitempty"`
	Password         string `json:"-"`
	Revision         int    `json:"revision"`
}

// record is private persistence data; Item's JSON form never contains a password.
type record struct {
	Item     Item   `json:"item"`
	Owner    string `json:"owner"`
	Password string `json:"password"`
}
type grant struct {
	ID, Owner, ItemID, Hash string
	Request, Token          string
	Revision                int
	Expires                 time.Time
}
type Audit struct {
	At      time.Time `json:"at"`
	Owner   string    `json:"owner"`
	ItemID  string    `json:"item_id"`
	Action  string    `json:"action"`
	GrantID string    `json:"grant_id,omitempty"`
}
type GrantView struct {
	ID      string    `json:"id"`
	ItemID  string    `json:"item_id"`
	Expires time.Time `json:"expires"`
}
type state struct {
	Version       int
	Items         map[string]record
	Grants        map[string]grant
	Audit         []Audit
	Receipts      map[string]receipt
	GrantReceipts map[string]grantReceipt
}
type receipt struct {
	Digest string
	Item   Item
}
type grantReceipt struct {
	ID, ItemID string
	Revision   int
}
type envelope struct {
	Version     int
	Nonce, Data []byte
}
type Store struct {
	mu      sync.Mutex
	path    string
	docs    *storage.Documents
	aead    cipher.AEAD
	hashKey []byte
	data    state
}

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
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("jms233/password-vault/requests/v1"))
	s := &Store{path: path, docs: docs, aead: aead, hashKey: mac.Sum(nil), data: state{Version: 1, Items: map[string]record{}, Grants: map[string]grant{}, Receipts: map[string]receipt{}, GrantReceipts: map[string]grantReceipt{}}}
	var raw []byte
	if docs != nil {
		raw, e = docs.LoadOrImport("password-vault", path)
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
	if len(raw) > 16<<20 {
		return nil, ErrInvalid
	}
	var box envelope
	if json.Unmarshal(raw, &box) != nil || box.Version != 1 || len(box.Nonce) != aead.NonceSize() {
		return nil, ErrInvalid
	}
	plain, e := aead.Open(nil, box.Nonce, box.Data, []byte("jms233/password-vault/v1"))
	if e != nil {
		return nil, ErrInvalid
	}
	if json.Unmarshal(plain, &s.data) != nil || s.data.Version != 1 || s.data.Items == nil || s.data.Grants == nil {
		return nil, ErrInvalid
	}
	if s.data.Receipts == nil {
		s.data.Receipts = map[string]receipt{}
	}
	if s.data.GrantReceipts == nil {
		s.data.GrantReceipts = map[string]grantReceipt{}
	}
	// Capabilities are process-bound: restoring an older snapshot or restarting
	// must never revive a grant that may already have been consumed or revoked.
	// Keep receipts to reject replay, but do not mutate storage during preflight.
	s.data.Grants = map[string]grant{}
	return s, nil
}
func random(n int) (string, error) {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return hex.EncodeToString(b), nil
}
func (s *Store) save(st state) error {
	plain, e := json.Marshal(st)
	if e != nil {
		return e
	}
	if len(plain) > 8<<20 {
		return ErrInvalid
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	raw, e := json.Marshal(envelope{1, nonce, s.aead.Seal(nil, nonce, plain, []byte("jms233/password-vault/v1"))})
	if e != nil {
		return e
	}
	if s.docs != nil {
		e = s.docs.Save("password-vault", raw)
	} else {
		e = atomicWrite(s.path, raw)
	}
	if e == nil {
		s.data = st
	}
	return e
}
func atomicWrite(path string, raw []byte) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".password-vault-*")
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
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}
func clone(st state) state {
	out := state{Version: 1, Items: make(map[string]record, len(st.Items)), Grants: make(map[string]grant, len(st.Grants)), Receipts: make(map[string]receipt, len(st.Receipts)), GrantReceipts: make(map[string]grantReceipt, len(st.GrantReceipts)), Audit: append([]Audit(nil), st.Audit...)}
	for k, v := range st.Items {
		out.Items[k] = v
	}
	for k, v := range st.Grants {
		out.Grants[k] = v
	}
	for k, v := range st.Receipts {
		out.Receipts[k] = v
	}
	for k, v := range st.GrantReceipts {
		out.GrantReceipts[k] = v
	}
	return out
}
func valid(i Item, password string) bool {
	return (i.Kind == "website" || i.Kind == "game" || i.Kind == "service") && len(strings.TrimSpace(i.Title)) > 0 && len(i.Title) <= 256 && len(i.Site) <= 2048 && len(i.Username) <= 512 && len(password) > 0 && len(password) <= 4096
}

// Create makes a retry with the same request ID return the original result;
// a different payload under that ID is rejected without saving another secret.
func (s *Store) Create(owner, requestID string, in Item, password string) (Item, error) {
	return s.CreateFor(owner, owner, requestID, in, password)
}

// CreateFor preserves the actual audit actor during an authorized local import.
func (s *Store) CreateFor(actor, owner, requestID string, in Item, password string) (Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	decoded, e := hex.DecodeString(requestID)
	if actor == "" || owner == "" || e != nil || len(decoded) != 16 || !valid(in, password) || in.ID != "" || in.Revision != 0 {
		return Item{}, ErrInvalid
	}
	mac := hmac.New(sha256.New, s.hashKey)
	mac.Write([]byte(owner))
	mac.Write([]byte{0})
	mac.Write([]byte(requestID))
	key := hex.EncodeToString(mac.Sum(nil))
	raw, e := json.Marshal(struct {
		Item     Item
		Password string
	}{in, password})
	if e != nil {
		return Item{}, e
	}
	mac = hmac.New(sha256.New, s.hashKey)
	mac.Write(raw)
	digest := hex.EncodeToString(mac.Sum(nil))
	if prior, ok := s.data.Receipts[key]; ok {
		if !hmac.Equal([]byte(prior.Digest), []byte(digest)) {
			return Item{}, ErrConflict
		}
		return prior.Item, nil
	}
	if len(s.data.Items) >= 10000 || len(s.data.Receipts) >= 10000 {
		return Item{}, ErrInvalid
	}
	id, e := random(16)
	if e != nil {
		return Item{}, e
	}
	in.ID = "pv-" + id
	in.Revision = 1
	in.Owner = ""
	in.Password = ""
	in.CanManageSharing = false
	st := clone(s.data)
	st.Items[in.ID] = record{Item: in, Owner: owner, Password: password}
	st.Receipts[key] = receipt{Digest: digest, Item: in}
	st.Audit = append(st.Audit, Audit{At: time.Now().UTC(), Owner: actor, ItemID: in.ID, Action: "save"})
	if e = s.save(st); e != nil {
		return Item{}, e
	}
	return in, nil
}
func (s *Store) List(owner string) []Item {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Item{}
	for _, r := range s.data.Items {
		if r.Owner == owner || r.Item.Shared {
			item := r.Item
			item.CanManageSharing = r.Owner == owner
			out = append(out, item)
		}
	}
	return out
}

// Reveal records a human's access before disclosing a saved password.
func (s *Store) Reveal(owner, id string) (Item, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.data.Items[id]
	if !ok || r.Owner != owner && !r.Item.Shared {
		return Item{}, "", ErrNotFound
	}
	st := clone(s.data)
	st.Audit = append(st.Audit, Audit{At: time.Now().UTC(), Owner: owner, ItemID: id, Action: "reveal"})
	if e := s.save(st); e != nil {
		return Item{}, "", e
	}
	return r.Item, r.Password, nil
}

// AuditFor returns only the requesting owner's events.
func (s *Store) AuditFor(owner string) []Audit {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Audit{}
	for i := len(s.data.Audit) - 1; i >= 0 && len(out) < 100; i-- {
		entry := s.data.Audit[i]
		r, exists := s.data.Items[entry.ItemID]
		if entry.Owner == owner || exists && (r.Owner == owner || r.Item.Shared) {
			out = append(out, s.data.Audit[i])
		}
	}
	return out
}

func (s *Store) GrantsFor(owner string) []GrantView {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []GrantView{}
	for _, g := range s.data.Grants {
		r, ok := s.data.Items[g.ItemID]
		if g.Owner == owner && ok && r.Item.Revision == g.Revision && time.Now().Before(g.Expires) {
			out = append(out, GrantView{ID: g.ID, ItemID: g.ItemID, Expires: g.Expires})
		}
	}
	return out
}
func (s *Store) Put(owner string, in Item, password string) (Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if owner == "" || !valid(in, password) {
		return Item{}, ErrInvalid
	}
	st := clone(s.data)
	if in.ID == "" {
		if len(st.Items) >= 10000 {
			return Item{}, ErrInvalid
		}
		id, e := random(16)
		if e != nil {
			return Item{}, e
		}
		in.ID = "pv-" + id
		in.Revision = 1
	} else {
		old, ok := st.Items[in.ID]
		if !ok || old.Owner != owner && !old.Item.Shared {
			return Item{}, ErrNotFound
		}
		if old.Owner != owner && old.Item.Shared != in.Shared {
			return Item{}, ErrDenied
		}
		if old.Item.Revision != in.Revision {
			return Item{}, ErrConflict
		}
		in.Revision++
	}
	in.Owner = ""
	in.Password = ""
	in.CanManageSharing = false
	itemOwner := owner
	if old, ok := st.Items[in.ID]; ok {
		itemOwner = old.Owner
	}
	st.Items[in.ID] = record{Item: in, Owner: itemOwner, Password: password}
	st.Audit = append(st.Audit, Audit{At: time.Now().UTC(), Owner: owner, ItemID: in.ID, Action: "save"})
	if e := s.save(st); e != nil {
		return Item{}, e
	}
	return in, nil
}
func (s *Store) Delete(owner, id string, revision int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.data.Items[id]
	if !ok || r.Owner != owner && !r.Item.Shared {
		return ErrNotFound
	}
	if r.Item.Revision != revision {
		return ErrConflict
	}
	st := clone(s.data)
	delete(st.Items, id)
	for k, g := range st.Grants {
		if g.ItemID == id {
			delete(st.Grants, k)
		}
	}
	st.Audit = append(st.Audit, Audit{At: time.Now().UTC(), Owner: owner, ItemID: id, Action: "delete"})
	return s.save(st)
}

// Grant creates a single-use capability bound to exactly one existing item.
func (s *Store) Grant(owner, id, requestID string, ttl time.Duration) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	requestBytes, requestErr := hex.DecodeString(requestID)
	if requestErr != nil || len(requestBytes) != 16 {
		return "", "", ErrInvalid
	}
	r, ok := s.data.Items[id]
	if !ok || r.Owner != owner && !r.Item.Shared {
		return "", "", ErrNotFound
	}
	if ttl <= 0 || ttl > time.Hour {
		return "", "", ErrInvalid
	}
	mac := hmac.New(sha256.New, s.hashKey)
	mac.Write([]byte("grant\x00" + owner + "\x00" + requestID))
	receiptKey := hex.EncodeToString(mac.Sum(nil))
	if previous, exists := s.data.GrantReceipts[receiptKey]; exists {
		if previous.ItemID != id || previous.Revision != r.Item.Revision {
			return "", "", ErrConflict
		}
		existing, alive := s.data.Grants[previous.ID]
		if !alive || !time.Now().Before(existing.Expires) {
			return "", "", ErrDenied
		}
		return existing.ID, existing.Token, nil
	}
	if len(s.data.GrantReceipts) >= 10000 {
		return "", "", ErrInvalid
	}
	token, e := random(32)
	if e != nil {
		return "", "", e
	}
	gid, e := random(16)
	if e != nil {
		return "", "", e
	}
	sum := sha256.Sum256([]byte(token))
	st := clone(s.data)
	for key, existing := range st.Grants {
		if !time.Now().Before(existing.Expires) {
			delete(st.Grants, key)
		}
	}
	if len(st.Grants) >= 10000 {
		return "", "", ErrInvalid
	}
	st.Grants[gid] = grant{ID: gid, Owner: owner, ItemID: id, Hash: hex.EncodeToString(sum[:]), Request: requestID, Token: token, Revision: r.Item.Revision, Expires: time.Now().UTC().Add(ttl)}
	st.GrantReceipts[receiptKey] = grantReceipt{ID: gid, ItemID: id, Revision: r.Item.Revision}
	st.Audit = append(st.Audit, Audit{At: time.Now().UTC(), Owner: owner, ItemID: id, Action: "grant", GrantID: gid})
	if e = s.save(st); e != nil {
		return "", "", e
	}
	return gid, token, nil
}
func (s *Store) Revoke(owner, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.data.Grants[id]
	if !ok || g.Owner != owner {
		return ErrNotFound
	}
	st := clone(s.data)
	delete(st.Grants, id)
	st.Audit = append(st.Audit, Audit{At: time.Now().UTC(), Owner: owner, ItemID: g.ItemID, Action: "revoke", GrantID: id})
	return s.save(st)
}

// Consume persists the audit and consumes the capability before returning a secret.
func (s *Store) Consume(owner, id, token string) (Item, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.data.Grants[id]
	sum := sha256.Sum256([]byte(token))
	expected, e := hex.DecodeString(g.Hash)
	if !ok || g.Owner != owner || e != nil || subtle.ConstantTimeCompare(sum[:], expected) != 1 || !time.Now().Before(g.Expires) {
		return Item{}, "", ErrDenied
	}
	r, ok := s.data.Items[g.ItemID]
	if !ok || r.Owner != g.Owner && !r.Item.Shared || r.Item.Revision != g.Revision {
		return Item{}, "", ErrDenied
	}
	st := clone(s.data)
	delete(st.Grants, id)
	st.Audit = append(st.Audit, Audit{At: time.Now().UTC(), Owner: g.Owner, ItemID: g.ItemID, Action: "consume", GrantID: id})
	if e = s.save(st); e != nil {
		return Item{}, "", e
	}
	return r.Item, r.Password, nil
}
