// Package agentevents stores host-reported repair events separately from
// authenticated operator actions. Segments grow without exhausting hot job slots.
package agentevents

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

var ErrInvalid = errors.New("invalid agent event history")
var ErrConflict = errors.New("agent event cursor conflict")
var ErrClosed = errors.New("agent event store closed")

const segmentSize = 128
const maxSources = 5000
const maxCollectors = 1000

type Source struct {
	AssetID   string `json:"asset_id"`
	AssetName string `json:"asset_name"`
	Account   string `json:"account"`
}
type Collector struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	JobID string `json:"job_id"`
}
type Receipt struct {
	PlanID   string          `json:"plan_id"`
	Sequence uint64          `json:"sequence"`
	RunID    string          `json:"run_id"`
	JobID    string          `json:"job_id,omitempty"`
	OwnerID  string          `json:"owner_id"`
	State    string          `json:"state"`
	Run      json.RawMessage `json:"run"`
	Job      json.RawMessage `json:"job,omitempty"`
}
type Record struct {
	Index      uint64           `json:"index"`
	Kind       string           `json:"kind"`
	Source     Source           `json:"source"`
	Collector  Collector        `json:"collector"`
	ObservedAt time.Time        `json:"observed_at"`
	Stream     string           `json:"stream,omitempty"`
	Event      *hostagent.Event `json:"event,omitempty"`
	From       uint64           `json:"from,omitempty"`
	To         uint64           `json:"to,omitempty"`
	Receipt    *Receipt         `json:"receipt,omitempty"`
}
type SourceState struct {
	Source     Source                `json:"source"`
	Cursor     hostagent.EventCursor `json:"cursor"`
	Missing    bool                  `json:"missing"`
	ObservedAt time.Time             `json:"observed_at"`
	Records    uint64                `json:"records"`
}
type index struct {
	Total      uint64                 `json:"total"`
	Sources    map[string]SourceState `json:"sources"`
	Collectors map[string]Record      `json:"collectors"`
}
type envelope struct {
	Version int    `json:"version"`
	Nonce   []byte `json:"nonce"`
	Data    []byte `json:"data"`
}
type Store struct {
	namespace string
	mu        sync.Mutex
	dir       string
	docs      *storage.Documents
	aead      cipher.AEAD
	data      index
	ctx       context.Context
	closed    bool
	saveHook  func(string, []byte) error
}

func Open(dir string, key []byte, docs *storage.Documents) (*Store, error) {
	return OpenNamespace(dir, key, docs, "agent-events")
}

// OpenNamespace keeps collection receipts in an independently authenticated
// document namespace while preserving the original event-store format.
func OpenNamespace(dir string, key []byte, docs *storage.Documents, namespace string) (*Store, error) {
	if namespace != "agent-events" && namespace != "account-collections" {
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
	s := &Store{namespace: namespace, dir: dir, docs: docs, aead: a, ctx: context.Background(), data: index{Sources: map[string]SourceState{}, Collectors: map[string]Record{}}}
	e = s.load("index", &s.data)
	if errors.Is(e, os.ErrNotExist) || errors.Is(e, storage.ErrDocumentNotFound) {
		e = nil
	}
	if e != nil {
		return nil, e
	}
	if s.data.Sources == nil || s.data.Collectors == nil || len(s.data.Sources) > maxSources || len(s.data.Collectors) > maxCollectors || s.data.Total > hostagent.MaxSequence {
		return nil, ErrInvalid
	}
	for k, v := range s.data.Sources {
		if k != sourceKey(v.Source) || !hostagent.ValidCursor(v.Cursor) {
			return nil, ErrInvalid
		}
	}
	for k, r := range s.data.Collectors {
		if r.Receipt == nil || r.Receipt.PlanID != k || r.Kind != "collection_run" || r.Index == 0 || r.Index > s.data.Total {
			return nil, ErrInvalid
		}
	}
	if s.data.Total > 0 {
		if _, e = s.segment((s.data.Total - 1) / segmentSize); e != nil {
			return nil, e
		}
	}
	return s, nil
}
func (s *Store) BindOwner(ctx context.Context) { s.mu.Lock(); defer s.mu.Unlock(); s.ctx = ctx }
func (s *Store) Close()                        { s.mu.Lock(); s.closed = true; s.mu.Unlock() }
func (s *Store) Abandon()                      { s.Close() }
func (s *Store) active() error {
	if s.closed || s.ctx.Err() != nil {
		return ErrClosed
	}
	return nil
}
func sourceKey(v Source) string {
	h := sha256.Sum256([]byte(v.AssetID + "\x00" + v.Account))
	return hex.EncodeToString(h[:])
}
func validSource(v Source) bool {
	return v.AssetID != "" && len(v.AssetID) <= 128 && len(v.AssetName) <= 256 && v.Account != "" && len(v.Account) <= 128
}
func (s *Store) Cursor(v Source) (hostagent.EventCursor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.active(); e != nil {
		return hostagent.EventCursor{}, e
	}
	if !validSource(v) {
		return hostagent.EventCursor{}, ErrInvalid
	}
	return s.data.Sources[sourceKey(v)].Cursor, nil
}
func (s *Store) load(key string, v any) error {
	var raw []byte
	var e error
	if s.docs != nil {
		raw, e = s.docs.LoadOrImport(s.namespace+"-"+key, filepath.Join(s.dir, key+".json"))
	} else {
		raw, e = os.ReadFile(filepath.Join(s.dir, key+".json"))
	}
	if e != nil {
		return e
	}
	if len(raw) == 0 {
		return os.ErrNotExist
	}
	if len(raw) > 16<<20 {
		return ErrInvalid
	}
	var box envelope
	if json.Unmarshal(raw, &box) != nil || box.Version != 1 || len(box.Nonce) != s.aead.NonceSize() {
		return ErrInvalid
	}
	plain, e := s.aead.Open(nil, box.Nonce, box.Data, []byte("jms233/"+s.namespace+"/v1/"+key))
	if e != nil {
		return ErrInvalid
	}
	if json.Unmarshal(plain, v) != nil {
		return ErrInvalid
	}
	return nil
}
func (s *Store) save(key string, v any) error {
	if e := s.active(); e != nil {
		return e
	}
	plain, e := json.Marshal(v)
	if e != nil {
		return e
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	raw, e := json.Marshal(envelope{1, nonce, s.aead.Seal(nil, nonce, plain, []byte("jms233/"+s.namespace+"/v1/"+key))})
	if e != nil {
		return e
	}
	if s.saveHook != nil {
		if e = s.saveHook(key, raw); e != nil {
			return e
		}
	}
	if s.docs != nil {
		return s.docs.Save(s.namespace+"-"+key, raw)
	}
	if e = os.MkdirAll(s.dir, 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(s.dir, ".agent-events-*")
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
	return os.Rename(f.Name(), filepath.Join(s.dir, key+".json"))
}
func (s *Store) segment(n uint64) ([]Record, error) {
	var rows []Record
	e := s.load(fmt.Sprintf("segment-%012d", n), &rows)
	if e != nil {
		return nil, e
	}
	committed := min(uint64(segmentSize), s.data.Total-n*segmentSize)
	if len(rows) < int(committed) || len(rows) > segmentSize {
		return nil, ErrInvalid
	}
	rows = rows[:committed]
	for i, r := range rows {
		if r.Index != n*segmentSize+uint64(i)+1 || !validSource(r.Source) || r.ObservedAt.IsZero() {
			return nil, ErrInvalid
		}
	}
	return rows, nil
}
func copyIndex(v index) index {
	out := index{Total: v.Total, Sources: map[string]SourceState{}, Collectors: map[string]Record{}}
	for k, x := range v.Sources {
		out.Sources[k] = x
	}
	for k, x := range v.Collectors {
		out.Collectors[k] = x
	}
	return out
}

// Commit the segment prefix before publishing index/cursors. An uncommitted
// tail is ignored after a crash and is safely overwritten on retry.
func (s *Store) commit(next index, rows []Record) error {
	total := s.data.Total
	var tail []Record
	var n uint64
	for i := 0; i < len(rows); {
		n = total / segmentSize
		tail = nil
		if total%segmentSize != 0 {
			var e error
			tail, e = s.segment(n)
			if e != nil {
				return e
			}
		}
		for i < len(rows) && len(tail) < segmentSize {
			r := rows[i]
			total++
			r.Index = total
			tail = append(tail, r)
			i++
		}
		if e := s.save(fmt.Sprintf("segment-%012d", n), tail); e != nil {
			return e
		}
	}
	next.Total = total
	if e := s.save("index", next); e != nil {
		return e
	}
	s.data = next
	return nil
}
func (s *Store) Import(src Source, col Collector, requested hostagent.EventCursor, snapshot hostagent.EventSnapshot) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.active(); e != nil {
		return 0, e
	}
	if !validSource(src) || col.ID == "" || col.JobID == "" || !hostagent.ValidCursor(requested) || snapshot.Requested != requested {
		return 0, ErrInvalid
	}
	raw, e := json.Marshal(snapshot)
	if e != nil {
		return 0, ErrInvalid
	}
	snapshot, e = hostagent.DecodeEventSnapshot(raw)
	if e != nil {
		return 0, e
	}
	key := sourceKey(src)
	current, exists := s.data.Sources[key]
	if !exists && len(s.data.Sources) >= maxSources {
		return 0, ErrInvalid
	}
	now := time.Now().UTC()
	rows := []Record{}
	add := func(kind string, from, to uint64, event *hostagent.Event) {
		rows = append(rows, Record{Kind: kind, Source: src, Collector: col, ObservedAt: now, Stream: snapshot.Stream, Event: event, From: from, To: to})
	}
	next := copyIndex(s.data)
	current.Source = src
	current.ObservedAt = now
	if snapshot.Missing {
		if current.Cursor.Stream != "" && !current.Missing {
			add("journal_missing", current.Cursor.Sequence+1, 0, nil)
		}
		current.Missing = true
	} else {
		if requested.Stream == snapshot.Stream && snapshot.LastSequence < requested.Sequence {
			return 0, ErrConflict
		}
		// Another completed read may have advanced this source. Never let an older
		// in-flight read switch the persisted stream back to an earlier journal.
		if current.Cursor.Stream != "" && current.Cursor.Stream != snapshot.Stream && current.Cursor != requested {
			return 0, ErrConflict
		}
		if current.Cursor.Stream != snapshot.Stream {
			if current.Cursor.Stream != "" {
				add("stream_changed", current.Cursor.Sequence, snapshot.FirstSequence, nil)
			}
			current.Cursor = hostagent.EventCursor{Stream: snapshot.Stream, Sequence: snapshot.FirstSequence - 1, Hash: snapshot.AnchorHash}
			if snapshot.FirstSequence > 1 {
				add("history_gap", 1, snapshot.FirstSequence-1, nil)
			}
		}
		current.Missing = false
		if current.Cursor.Sequence > snapshot.LastSequence {
			return 0, ErrConflict
		}
		for i := range snapshot.Events {
			event := snapshot.Events[i]
			if event.Sequence <= current.Cursor.Sequence {
				if event.Sequence == current.Cursor.Sequence && event.Hash != current.Cursor.Hash {
					return 0, ErrConflict
				}
				continue
			}
			if event.Sequence != current.Cursor.Sequence+1 {
				if event.Sequence != snapshot.FirstSequence || event.Sequence <= current.Cursor.Sequence {
					return 0, ErrConflict
				}
				add("history_gap", current.Cursor.Sequence+1, event.Sequence-1, nil)
				current.Cursor.Sequence = event.Sequence - 1
				current.Cursor.Hash = snapshot.AnchorHash
			}
			if event.PreviousHash != current.Cursor.Hash {
				return 0, ErrConflict
			}
			add("host_event", 0, 0, &event)
			current.Cursor = hostagent.EventCursor{Stream: snapshot.Stream, Sequence: event.Sequence, Hash: event.Hash}
		}
		if len(snapshot.Events) == 0 && (snapshot.More || snapshot.LastSequence > current.Cursor.Sequence || snapshot.AnchorHash != current.Cursor.Hash) {
			return 0, ErrConflict
		}
	}
	current.Records += uint64(len(rows))
	next.Sources[key] = current
	if e = s.commit(next, rows); e != nil {
		return 0, e
	}
	return len(rows), nil
}
func (s *Store) Archive(src Source, col Collector, r Receipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.active(); e != nil {
		return e
	}
	if !validSource(src) || r.PlanID == "" || r.Sequence == 0 || r.RunID == "" || r.OwnerID == "" || !json.Valid(r.Run) || len(r.Run) > 128<<10 || len(r.Job) > 256<<10 || len(r.Job) > 0 && !json.Valid(r.Job) {
		return ErrInvalid
	}
	prior, ok := s.data.Collectors[r.PlanID]
	if ok && prior.Receipt.Sequence >= r.Sequence {
		if prior.Receipt.Sequence == r.Sequence && prior.Receipt.RunID != r.RunID {
			return ErrConflict
		}
		return nil
	}
	if !ok && len(s.data.Collectors) >= maxCollectors {
		return ErrInvalid
	}
	r.Run = append(json.RawMessage(nil), r.Run...)
	r.Job = append(json.RawMessage(nil), r.Job...)
	row := Record{Index: s.data.Total + 1, Kind: "collection_run", Source: src, Collector: col, ObservedAt: time.Now().UTC(), Receipt: &r}
	next := copyIndex(s.data)
	next.Collectors[r.PlanID] = row
	return s.commit(next, []Record{row})
}
func (s *Store) LatestReceipt(id string) (Receipt, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.data.Collectors {
		if v.Receipt.RunID == id || v.Receipt.JobID != "" && v.Receipt.JobID == id {
			r := *v.Receipt
			r.Run = append(json.RawMessage(nil), r.Run...)
			r.Job = append(json.RawMessage(nil), r.Job...)
			return r, true
		}
	}
	return Receipt{}, false
}

type Page struct {
	Results    []Record `json:"results"`
	NextBefore uint64   `json:"next_before"`
}

func (s *Store) List(before uint64, limit int, allow func(Source) bool, kinds ...string) (Page, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := Page{Results: []Record{}}
	if e := s.active(); e != nil {
		return out, e
	}
	kind := "all"
	if len(kinds) > 1 {
		return out, ErrInvalid
	}
	if len(kinds) == 1 {
		kind = kinds[0]
	}
	if kind != "all" && kind != "host" && kind != "collection" {
		return out, ErrInvalid
	}
	if limit < 1 || limit > 100 || allow == nil {
		return out, ErrInvalid
	}
	if before == 0 || before > s.data.Total+1 {
		before = s.data.Total + 1
	}
	cursor := before - 1
	for scanned := 0; cursor > 0 && len(out.Results) < limit && scanned < 64; scanned++ {
		n := (cursor - 1) / segmentSize
		rows, e := s.segment(n)
		if e != nil {
			return out, e
		}
		for i := int((cursor - 1) % segmentSize); i >= 0; i-- {
			r := rows[i]
			cursor = r.Index - 1
			if allow(r.Source) && (kind == "all" || kind == "host" && r.Kind != "collection_run" || kind == "collection" && r.Kind == "collection_run") {
				out.Results = append(out.Results, r)
			}
			if len(out.Results) == limit {
				break
			}
		}
	}
	if cursor > 0 {
		out.NextBefore = cursor + 1
	}
	return out, nil
}
