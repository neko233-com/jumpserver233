package loginaudit

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

type index struct {
	Version              int
	Total, Floor, GCNext uint64
	ReviewCursor         string
	ReviewGap            bool
}
type envelope struct {
	Version     int
	Nonce, Data []byte
}
type lastSource struct {
	IP       string
	Sequence uint64
}
type failures struct {
	At       []time.Time
	Notified time.Time
}
type Store struct {
	mu        sync.Mutex
	dir       string
	docs      *storage.Documents
	aead      cipher.AEAD
	data      index
	rows      []Record
	byID      map[string]Record
	lastIP    map[string]lastSource
	failures  map[string]failures
	events    []eventfeed.Event
	health    Health
	now       func() time.Time
	saveHook  func(string, []byte) error
	closed    bool
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	started   bool
	lastPrune time.Time
}

func Open(dir string, key []byte, docs *storage.Documents) (*Store, error) {
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
	ctx, cancel := context.WithCancel(context.Background())
	s := &Store{dir: dir, docs: docs, aead: aead, data: index{Version: 1, Floor: 1}, rows: []Record{}, byID: map[string]Record{}, lastIP: map[string]lastSource{}, failures: map[string]failures{}, events: []eventfeed.Event{}, now: time.Now, ctx: ctx, cancel: cancel}
	if e = s.load("index", &s.data); e != nil {
		cancel()
		return nil, e
	}
	d := s.data
	if d.Version != 1 || d.Floor < 1 || d.Floor > d.Total+1 || d.Total-d.Floor+1 > MaxRecords || d.Total > 1<<60 || d.GCNext > (d.Floor-1)/SegmentSize || (d.Floor-1)%SegmentSize != 0 || !optionalID(d.ReviewCursor) {
		cancel()
		return nil, ErrInvalid
	}
	if d.Total >= d.Floor {
		for n := (d.Floor - 1) / SegmentSize; n <= (d.Total-1)/SegmentSize; n++ {
			rows, e := s.segment(n)
			if e != nil {
				cancel()
				return nil, e
			}
			for _, r := range rows {
				if r.Sequence < d.Floor {
					continue
				}
				if _, ok := s.byID[r.ID]; ok {
					cancel()
					return nil, ErrInvalid
				}
				s.rows = append(s.rows, r)
				s.publish(r)
			}
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
func (s *Store) key(key string) string { return "login-audit-" + key }
func (s *Store) load(key string, out any) error {
	var raw []byte
	var e error
	if s.docs != nil {
		raw, e = s.docs.LoadOrImport(s.key(key), filepath.Join(s.dir, key+".json"))
	} else {
		raw, e = os.ReadFile(filepath.Join(s.dir, key+".json"))
		if errors.Is(e, os.ErrNotExist) {
			e = nil
		}
	}
	if e != nil {
		return e
	}
	if len(raw) == 0 {
		if key == "index" {
			return nil
		}
		return ErrInvalid
	}
	if len(raw) > 2<<20 {
		return ErrInvalid
	}
	var box envelope
	if decode(raw, &box) != nil || box.Version != 1 || len(box.Nonce) != s.aead.NonceSize() {
		return ErrInvalid
	}
	plain, e := s.aead.Open(nil, box.Nonce, box.Data, []byte("jms233/login-audit/v1/"+key))
	if e != nil || len(plain) > 1<<20 || decode(plain, out) != nil {
		return ErrInvalid
	}
	return nil
}
func (s *Store) save(key string, value any) error {
	raw, e := json.Marshal(value)
	if e != nil {
		return e
	}
	if len(raw) > 1<<20 {
		return ErrInvalid
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	raw, e = json.Marshal(envelope{1, nonce, s.aead.Seal(nil, nonce, raw, []byte("jms233/login-audit/v1/"+key))})
	if e != nil {
		return e
	}
	if s.saveHook != nil {
		if e = s.saveHook(key, raw); e != nil {
			return e
		}
	}
	if s.docs != nil {
		return s.docs.Save(s.key(key), raw)
	}
	if e = os.MkdirAll(s.dir, 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(s.dir, ".login-audit-*")
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
	return os.Rename(f.Name(), filepath.Join(s.dir, key+".json"))
}
func (s *Store) segment(n uint64) ([]Record, error) {
	var rows []Record
	if e := s.load(fmt.Sprintf("segment-%012d", n), &rows); e != nil {
		return nil, e
	}
	committed := min(uint64(SegmentSize), s.data.Total-n*SegmentSize)
	if len(rows) < int(committed) || len(rows) > SegmentSize {
		return nil, ErrInvalid
	}
	rows = rows[:committed]
	for i, r := range rows {
		if r.Sequence != n*SegmentSize+uint64(i)+1 || !valid(r) {
			return nil, ErrInvalid
		}
	}
	return rows, nil
}
func (s *Store) publish(r Record) {
	s.byID[r.ID] = r
	if r.Outcome == "succeeded" {
		s.lastIP[r.UserID] = lastSource{r.SourceIP, r.Sequence}
	}
	if r.At.After(s.now().Add(-15*time.Minute)) && (r.Outcome == "failed" || r.Outcome == "denied" || r.Outcome == "throttled") {
		b, known := s.failures[r.SourceIP]
		if known || len(s.failures) < 8192 {
			b.At = append(b.At, r.At)
			if len(b.At) > 5 {
				b.At = slices.Clone(b.At[len(b.At)-5:])
			}
			if r.Notification == "platform_login_failures" {
				b.Notified = r.At
			}
			s.failures[r.SourceIP] = b
		} else {
			s.health.AggregationLimited = true
		}
	}
	if r.Notification != "" {
		s.events = append(s.events, eventfeed.Event{ID: eventfeed.Digest(r.ID), Kind: "platform-logins", ResourceID: r.ID, OwnerID: r.UserID, ActorID: r.ActorID, Name: "", State: r.Notification, At: r.At})
	}
}
func (s *Store) Append(in Input) (out Record, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return out, ErrClosed
	}
	defer func() {
		if err != nil {
			s.health.ErrorCode = "unavailable"
			s.health.LastFailure = s.now().UTC()
		} else {
			s.health.ErrorCode = ""
		}
	}()
	if in.ID != "" {
		if r, ok := s.byID[in.ID]; ok {
			return r, nil
		}
	}
	if s.data.Total >= 1<<60 {
		return out, ErrInvalid
	}
	if in.ID == "" {
		var raw [16]byte
		if _, e := rand.Read(raw[:]); e != nil {
			return out, e
		}
		in.ID = "login-" + hex.EncodeToString(raw[:])
	}
	if in.At.IsZero() {
		in.At = s.now().UTC()
	}
	if in.Client == "" {
		in.Client = "unknown"
	}
	out = Record{ID: in.ID, Sequence: s.data.Total + 1, At: in.At.UTC(), Method: in.Method, Stage: in.Stage, Outcome: in.Outcome, Reason: in.Reason, UserID: in.UserID, Username: in.Username, ActorID: in.ActorID, Actor: in.Actor, AttemptedName: in.AttemptedName, SourceIP: in.SourceIP, Client: in.Client, ReviewID: in.ReviewID}
	if !valid(out) {
		return Record{}, ErrInvalid
	}
	if out.Outcome == "succeeded" {
		out.Notification = "platform_login_succeeded"
		if old, ok := s.lastIP[out.UserID]; ok && old.IP != "unknown" && out.SourceIP != "unknown" && old.IP != out.SourceIP {
			out.Notification = "platform_login_new_source"
		}
	} else if out.Stage == "review" {
		if slices.Contains([]string{"review_pending", "review_approved", "review_denied", "review_expired", "review_cancelled", "review_consumed", "review_invalidated"}, out.Outcome) {
			out.Notification = "platform_" + out.Outcome
		}
		if out.Outcome == "policy_notified" {
			out.Notification = "platform_policy_notified"
		}
	} else if slices.Contains([]string{"failed", "denied", "throttled"}, out.Outcome) {
		b := s.failures[out.SourceIP]
		count := 1
		for _, at := range b.At {
			if at.After(out.At.Add(-5 * time.Minute)) {
				count++
			}
		}
		if count >= 5 && (b.Notified.IsZero() || out.At.Sub(b.Notified) >= 15*time.Minute) {
			out.Notification = "platform_login_failures"
		}
	}
	if e := s.commitRows([]Record{out}, nil); e != nil {
		return Record{}, e
	}
	return out, nil
}

func (s *Store) gc() {
	through := (s.data.Floor - 1) / SegmentSize
	for i := 0; i < 8 && s.data.GCNext < through; i++ {
		key := fmt.Sprintf("segment-%012d", s.data.GCNext)
		var e error
		if s.docs != nil {
			e = s.docs.Delete(s.key(key))
		} else {
			e = os.Remove(filepath.Join(s.dir, key+".json"))
			if errors.Is(e, os.ErrNotExist) {
				e = nil
			}
		}
		if e != nil {
			s.health.PrunePending = true
			return
		}
		s.data.GCNext++
	}
	s.health.PrunePending = s.data.GCNext < through
}
func (s *Store) Close() { s.cancel(); s.mu.Lock(); s.closed = true; s.mu.Unlock(); s.wg.Wait() }

// Start ingests the durable native review metadata stream.
func (s *Store) Start(owner context.Context, source Source) { s.startSource(owner, source) }
