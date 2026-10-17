// Package commandalerts stores durable metadata for filtered terminal input.
// Command text and terminal output never enter this store.
package commandalerts

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sync"
	"time"
)

var ErrInvalid = errors.New("invalid command alert")
var ErrNotFound = errors.New("command alert not found")
var ErrClosed = errors.New("command alert store closed")

const MaxRecords = 20000
const maxBytes = 32 << 20

var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type Record struct {
	ID        string    `json:"id"`
	SessionID string    `json:"session_id"`
	ReviewID  string    `json:"review_id,omitempty"`
	AssetID   string    `json:"asset_id"`
	AssetName string    `json:"asset_name"`
	Account   string    `json:"account"`
	OwnerID   string    `json:"owner_id"`
	ActorID   string    `json:"actor_id"`
	Actor     string    `json:"actor"`
	State     string    `json:"state"`
	Rule      string    `json:"rule"`
	At        time.Time `json:"at"`
}
type state struct {
	Version int
	Records []Record
}
type envelope struct {
	Version int    `json:"version"`
	Nonce   []byte `json:"nonce"`
	Data    []byte `json:"data"`
}
type Store struct {
	mu       sync.Mutex
	path     string
	docs     *storage.Documents
	aead     cipher.AEAD
	data     state
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
	a, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	s := &Store{path: path, docs: docs, aead: a, data: state{Version: 1, Records: []Record{}}}
	var raw []byte
	if docs != nil {
		raw, e = docs.LoadOrImport("command-alerts", path)
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
		var box envelope
		if len(raw) > maxBytes*2 || decode(raw, &box) != nil || box.Version != 1 || len(box.Nonce) != a.NonceSize() {
			return nil, ErrInvalid
		}
		plain, e := a.Open(nil, box.Nonce, box.Data, []byte("jms233/command-alerts/v1"))
		if e != nil || len(plain) > maxBytes || decode(plain, &s.data) != nil {
			return nil, ErrInvalid
		}
	}
	if s.data.Version != 1 || len(s.data.Records) > MaxRecords {
		return nil, ErrInvalid
	}
	ids := map[string]bool{}
	for _, r := range s.data.Records {
		if !valid(r) || ids[r.ID] {
			return nil, ErrInvalid
		}
		ids[r.ID] = true
	}
	if len(raw) == 0 {
		if e := s.persist(s.data); e != nil {
			return nil, e
		}
	}
	return s, nil
}
func decode(raw []byte, v any) error {
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
func valid(r Record) bool {
	if !idPattern.MatchString(r.ID) || !idPattern.MatchString(r.SessionID) || !idPattern.MatchString(r.AssetID) || !idPattern.MatchString(r.OwnerID) || !idPattern.MatchString(r.ActorID) || r.ReviewID != "" && !idPattern.MatchString(r.ReviewID) || r.At.IsZero() {
		return false
	}
	for _, p := range []struct {
		v string
		n int
	}{{r.AssetName, 480}, {r.Actor, 128}, {r.Account, 128}, {r.Rule, 80}} {
		if eventfeed.MetadataText(p.v, p.n) != p.v {
			return false
		}
	}
	return slices.Contains([]string{"command_denied", "command_input_blocked", "command_review_pending", "command_review_approved", "command_review_denied", "command_review_expired", "command_review_cancelled"}, r.State)
}
func (s *Store) persist(d state) error {
	raw, e := json.Marshal(d)
	if e != nil || len(raw) > maxBytes {
		return ErrInvalid
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	raw, e = json.Marshal(envelope{1, nonce, s.aead.Seal(nil, nonce, raw, []byte("jms233/command-alerts/v1"))})
	if e != nil {
		return e
	}
	if s.saveHook != nil {
		if e := s.saveHook(raw); e != nil {
			return e
		}
	}
	if s.docs != nil {
		return s.docs.Save("command-alerts", raw)
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".command-alerts-*")
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
func (s *Store) Publish(r Record) error {
	if !valid(r) {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	for _, old := range s.data.Records {
		if old.ID == r.ID {
			if reflect.DeepEqual(old, r) {
				return nil
			}
			return ErrInvalid
		}
	}
	next := state{Version: 1, Records: slices.Clone(s.data.Records)}
	cutoff := time.Now().Add(-30 * 24 * time.Hour)
	next.Records = slices.DeleteFunc(next.Records, func(v Record) bool { return v.At.Before(cutoff) })
	if len(next.Records) >= MaxRecords {
		next.Records = slices.Clone(next.Records[len(next.Records)-MaxRecords+1:])
	}
	next.Records = append(next.Records, r)
	if e := s.persist(next); e != nil {
		return e
	}
	s.data = next
	return nil
}
func (s *Store) Get(id string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Record{}, ErrClosed
	}
	for _, r := range s.data.Records {
		if r.ID == id {
			return r, nil
		}
	}
	return Record{}, ErrNotFound
}
func (s *Store) NotificationFeed(ctx context.Context, after string, since time.Time, limit int) (eventfeed.Batch, error) {
	if ctx.Err() != nil {
		return eventfeed.Batch{}, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return eventfeed.Batch{}, ErrClosed
	}
	list := s.data.Records
	if len(list) > 0 && eventfeed.Digest(list[len(list)-1].ID) == after {
		return eventfeed.Batch{Events: []eventfeed.Event{}, Cursor: after}, nil
	}
	rows := make([]eventfeed.Event, 0, len(list))
	for _, r := range list {
		rows = append(rows, eventfeed.Event{ID: eventfeed.Digest(r.ID), Kind: "command-alerts", ResourceID: r.ID, OwnerID: r.OwnerID, ActorID: r.ActorID, Name: r.AssetName, State: r.State, At: r.At})
	}
	return eventfeed.Read(rows, after, since, limit), nil
}
func (s *Store) Close() { s.mu.Lock(); s.closed = true; s.mu.Unlock() }
