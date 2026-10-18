package reporting

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

var ErrClosed = errors.New("report export ledger closed")

const MaxReceipts = 2000
const MaxCSVBytes = 4 << 20

type ReceiptSource struct {
	ID     string `json:"id"`
	Scope  string `json:"scope"`
	Status string `json:"status"`
}
type Receipt struct {
	ID      string          `json:"id"`
	OwnerID string          `json:"owner_id"`
	At      time.Time       `json:"at"`
	Query   Query           `json:"query"`
	Sources []ReceiptSource `json:"sources"`
	Partial bool            `json:"partial"`
	SHA256  string          `json:"sha256"`
	Bytes   int             `json:"bytes"`
}
type receiptState struct {
	Version  int
	Receipts []Receipt
}
type ledgerEnvelope struct {
	Version     int
	Nonce, Data []byte
}
type Store struct {
	mu       sync.Mutex
	path     string
	docs     *storage.Documents
	aead     cipher.AEAD
	data     receiptState
	closed   bool
	saveHook func([]byte) error
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
	s := &Store{path: path, docs: docs, aead: aead, data: receiptState{Version: 1, Receipts: []Receipt{}}}
	var raw []byte
	if docs != nil {
		raw, e = docs.LoadOrImport("report-exports", path)
	} else {
		raw, e = os.ReadFile(path)
		if errors.Is(e, os.ErrNotExist) {
			e = nil
		}
	}
	if e != nil {
		return nil, e
	}
	if len(raw) > 0 {
		var box ledgerEnvelope
		if len(raw) > 8<<20 || strict(raw, &box) != nil || box.Version != 1 || len(box.Nonce) != aead.NonceSize() {
			return nil, ErrInvalid
		}
		plain, e := aead.Open(nil, box.Nonce, box.Data, []byte("jms233/report-exports/v1"))
		if e != nil || len(plain) > 4<<20 || strict(plain, &s.data) != nil || s.data.Version != 1 || len(s.data.Receipts) > MaxReceipts {
			return nil, ErrInvalid
		}
		seen := map[string]bool{}
		for _, r := range s.data.Receipts {
			if !validReceipt(r) || seen[r.ID] {
				return nil, ErrInvalid
			}
			seen[r.ID] = true
		}
	}
	return s, nil
}
func strict(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func validReceipt(r Receipt) bool {
	validID := func(s string) bool { return len(s) > 0 && len(s) <= 128 && regexpID(s) }
	if !validID(r.ID) || !validID(r.OwnerID) || r.At.IsZero() || Validate(r.Query, r.At) != nil || r.Bytes < 1 || r.Bytes > MaxCSVBytes || len(r.Sources) > MaxSources {
		return false
	}
	b, e := hex.DecodeString(r.SHA256)
	if e != nil || len(b) != 32 {
		return false
	}
	for _, s := range r.Sources {
		if !code.MatchString(s.ID) || !slices.Contains([]string{"mine", "visible", "all", "platform_mine", "platform_all"}, s.Scope) || !slices.Contains([]string{"ok", "limited", "denied", "unavailable"}, s.Status) {
			return false
		}
	}
	return true
}
func regexpID(v string) bool {
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
func cloneReceipt(r Receipt) Receipt {
	r.Sources = slices.Clone(r.Sources)
	r.Query.Sources = slices.Clone(r.Query.Sources)
	return r
}
func (s *Store) Commit(owner string, r Report, csv []byte) (Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Receipt{}, ErrClosed
	}
	var id [16]byte
	if _, e := rand.Read(id[:]); e != nil {
		return Receipt{}, e
	}
	sum := sha256.Sum256(csv)
	out := Receipt{ID: "report-export-" + hex.EncodeToString(id[:]), OwnerID: owner, At: time.Now().UTC(), Query: r.Query, Sources: []ReceiptSource{}, Partial: r.Partial, SHA256: hex.EncodeToString(sum[:]), Bytes: len(csv)}
	for _, v := range r.Sources {
		out.Sources = append(out.Sources, ReceiptSource{v.ID, v.Scope, v.Status})
	}
	out = cloneReceipt(out)
	if !validReceipt(out) {
		return Receipt{}, ErrInvalid
	}
	next := receiptState{Version: 1, Receipts: make([]Receipt, 0, min(MaxReceipts, len(s.data.Receipts)+1))}
	for _, v := range s.data.Receipts {
		if v.At.After(out.At.Add(-365 * 24 * time.Hour)) {
			next.Receipts = append(next.Receipts, v)
		}
	}
	if len(next.Receipts) >= MaxReceipts {
		next.Receipts = next.Receipts[len(next.Receipts)-MaxReceipts+1:]
	}
	next.Receipts = append(next.Receipts, out)
	raw, e := json.Marshal(next)
	for e == nil && len(raw) > 4<<20 && len(next.Receipts) > 1 {
		next.Receipts = next.Receipts[max(1, len(next.Receipts)/10):]
		raw, e = json.Marshal(next)
	}
	if e != nil || len(raw) > 4<<20 {
		return Receipt{}, ErrLimit
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return Receipt{}, e
	}
	raw, e = json.Marshal(ledgerEnvelope{1, nonce, s.aead.Seal(nil, nonce, raw, []byte("jms233/report-exports/v1"))})
	if e != nil {
		return Receipt{}, e
	}
	if s.saveHook != nil {
		if e = s.saveHook(raw); e != nil {
			return Receipt{}, e
		}
	}
	if s.docs != nil {
		e = s.docs.Save("report-exports", raw)
	} else {
		e = writeAtomic(s.path, raw)
	}
	if e != nil {
		return Receipt{}, e
	}
	s.data = next
	return cloneReceipt(out), nil
}
func writeAtomic(path string, raw []byte) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".report-*")
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
	closed := f.Close()
	if e != nil {
		return e
	}
	if closed != nil {
		return closed
	}
	return os.Rename(f.Name(), path)
}
func (s *Store) List(owner string, all bool, offset, limit int) ([]Receipt, int, error) {
	if offset < 0 || limit < 1 || limit > 100 || owner == "" {
		return nil, 0, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, 0, ErrClosed
	}
	out := []Receipt{}
	total := 0
	for i := len(s.data.Receipts) - 1; i >= 0; i-- {
		v := s.data.Receipts[i]
		if (!all && v.OwnerID != owner) || v.At.Before(time.Now().Add(-365*24*time.Hour)) {
			continue
		}
		if total >= offset && len(out) < limit {
			out = append(out, cloneReceipt(v))
		}
		total++
	}
	return out, total, nil
}
func (s *Store) Close() { s.mu.Lock(); s.closed = true; s.mu.Unlock() }
