// Package executionhistory preserves immutable execution evidence independently
// of bounded runnable state. Payloads, summaries and request identities remain
// private to the organization's existing encryption key.
package executionhistory

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

var ErrInvalid = errors.New("invalid execution history")
var ErrUnavailable = errors.New("execution history unavailable")
var ErrNotFound = storage.ErrHistoryMissing
var ErrConflict = storage.ErrHistoryConflict

const MaxPayload = 16 << 20

type Record struct {
	Kind, ID, Owner, RequestOwner, RequestID string
	CreatedAt                                time.Time
	Summary, Payload                         json.RawMessage
}
type Query struct {
	Kind, Owner   string
	Offset, Limit int
	Exclude       []string
}
type Store struct {
	index *storage.HistoryIndex
	aead  cipher.AEAD
	key   []byte
}
type Health struct {
	Records, Bytes int64
	ErrorCode      string `json:"error_code,omitempty"`
}
type packed struct {
	Version                                  int `json:"version"`
	Kind, ID, Owner, RequestOwner, RequestID string
	CreatedAt                                time.Time
	Value                                    json.RawMessage
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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var index *storage.HistoryIndex
	if docs == nil {
		index, e = storage.OpenLocalHistory(ctx, path)
	} else {
		index, e = docs.OpenHistory(ctx)
	}
	if e != nil {
		return nil, ErrUnavailable
	}
	s := &Store{index: index, aead: aead, key: append([]byte(nil), key...)}
	version, proof, e := index.Meta(ctx)
	if errors.Is(e, storage.ErrHistoryMissing) {
		stats, se := index.Stats(ctx)
		if se != nil || stats.Records != 0 {
			_ = index.Close()
			return nil, ErrInvalid
		}
		proof, e = s.seal([]byte(`{"format":1}`), "meta")
		if e == nil {
			e = index.CreateMeta(ctx, 1, proof)
		}
		if e == nil {
			version, proof, e = index.Meta(ctx)
		}
	}
	if e == nil && version == 1 {
		var raw []byte
		raw, e = s.open(proof, "meta")
		if e == nil && !bytes.Equal(raw, []byte(`{"format":1}`)) {
			e = ErrInvalid
		}
	} else if e == nil {
		e = ErrInvalid
	}
	if e != nil {
		_ = index.Close()
		return nil, ErrInvalid
	}
	return s, nil
}
func (s *Store) tag(parts ...string) string {
	h := hmac.New(sha256.New, s.key)
	h.Write([]byte("jms233/execution-history/index/v1\x00"))
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
func (s *Store) receipt(kind, actor, request string) string {
	if request == "" {
		return ""
	}
	return s.tag("receipt", kind, actor, request)
}
func (s *Store) seal(raw []byte, aad string) ([]byte, error) {
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	if _, e := z.Write(raw); e != nil {
		return nil, e
	}
	if e := z.Close(); e != nil {
		return nil, e
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, e := rand.Read(nonce); e != nil {
		return nil, e
	}
	return s.aead.Seal(nonce, nonce, b.Bytes(), []byte("jms233/execution-history/v1/"+aad)), nil
}
func (s *Store) open(raw []byte, aad string) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(raw) < n+s.aead.Overhead() {
		return nil, ErrInvalid
	}
	plain, e := s.aead.Open(nil, raw[:n], raw[n:], []byte("jms233/execution-history/v1/"+aad))
	if e != nil {
		return nil, ErrInvalid
	}
	reader, e := gzip.NewReader(bytes.NewReader(plain))
	if e != nil {
		return nil, ErrInvalid
	}
	defer reader.Close()
	out, e := io.ReadAll(io.LimitReader(reader, MaxPayload+4097))
	if e != nil || len(out) > MaxPayload+4096 {
		return nil, ErrInvalid
	}
	return out, nil
}
func (s *Store) row(r Record) (storage.HistoryRow, error) {
	if r.CreatedAt.IsZero() || r.CreatedAt.UnixNano() <= 0 || r.Owner == "" || len(r.Owner) > 128 || len(r.RequestOwner) > 128 || len(r.RequestID) > 128 || !json.Valid(r.Payload) || !json.Valid(r.Summary) || len(r.Payload) > MaxPayload || len(r.Summary) > 512<<10 {
		return storage.HistoryRow{}, ErrInvalid
	}
	if r.RequestID != "" && r.RequestOwner == "" {
		return storage.HistoryRow{}, ErrInvalid
	}
	full := packed{1, r.Kind, r.ID, r.Owner, r.RequestOwner, r.RequestID, r.CreatedAt.UTC(), r.Payload}
	summary := full
	summary.Value = r.Summary
	body, e := json.Marshal(full)
	if e != nil {
		return storage.HistoryRow{}, e
	}
	rawSummary, e := json.Marshal(summary)
	if e != nil {
		return storage.HistoryRow{}, e
	}
	digest := s.tag("record", string(body))
	encrypted, e := s.seal(body, r.Kind+"/"+r.ID+"/body")
	if e != nil {
		return storage.HistoryRow{}, e
	}
	sealedSummary, e := s.seal(rawSummary, r.Kind+"/"+r.ID+"/summary")
	if e != nil {
		return storage.HistoryRow{}, e
	}
	return storage.HistoryRow{Kind: r.Kind, ID: r.ID, Owner: s.tag("owner", r.Owner), Receipt: s.receipt(r.Kind, r.RequestOwner, r.RequestID), Digest: digest, Created: r.CreatedAt.UnixNano(), Summary: sealedSummary, Body: encrypted}, nil
}
func (s *Store) Put(ctx context.Context, records ...Record) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	rows := make([]storage.HistoryRow, 0, len(records))
	for _, r := range records {
		row, e := s.row(r)
		if e != nil {
			return e
		}
		rows = append(rows, row)
	}
	return s.index.Put(ctx, rows)
}
func (s *Store) decode(row storage.HistoryRow, full bool) (Record, error) {
	raw := row.Summary
	aad := row.Kind + "/" + row.ID + "/summary"
	if full {
		raw = row.Body
		aad = row.Kind + "/" + row.ID + "/body"
	}
	plain, e := s.open(raw, aad)
	if e != nil {
		return Record{}, e
	}
	var value packed
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if d.Decode(&value) != nil || d.Decode(new(any)) != io.EOF || value.Version != 1 || value.Kind != row.Kind || value.ID != row.ID || s.tag("owner", value.Owner) != row.Owner || s.receipt(value.Kind, value.RequestOwner, value.RequestID) != row.Receipt || value.CreatedAt.UnixNano() != row.Created || !json.Valid(value.Value) {
		return Record{}, ErrInvalid
	}
	if full && !hmac.Equal([]byte(row.Digest), []byte(s.tag("record", string(plain)))) {
		return Record{}, ErrInvalid
	}
	result := Record{Kind: value.Kind, ID: value.ID, Owner: value.Owner, RequestOwner: value.RequestOwner, RequestID: value.RequestID, CreatedAt: value.CreatedAt, Summary: value.Value}
	if full {
		result.Payload = value.Value
	}
	return result, nil
}
func (s *Store) Get(ctx context.Context, kind, id string) (Record, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	row, e := s.index.Get(ctx, kind, id)
	if e != nil {
		return Record{}, e
	}
	return s.decode(row, true)
}
func (s *Store) FindRequest(ctx context.Context, kind, actor, request string) (Record, error) {
	if actor == "" || request == "" {
		return Record{}, ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	row, e := s.index.FindReceipt(ctx, kind, s.receipt(kind, actor, request))
	if e != nil {
		return Record{}, e
	}
	return s.decode(row, true)
}
func (s *Store) Query(ctx context.Context, q Query) ([]Record, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	owner := ""
	if q.Owner != "" {
		owner = s.tag("owner", q.Owner)
	}
	rows, count, e := s.index.Query(ctx, storage.HistoryQuery{Kind: q.Kind, Owner: owner, Offset: q.Offset, Limit: q.Limit, Exclude: q.Exclude})
	if e != nil {
		return nil, 0, e
	}
	out := make([]Record, 0, len(rows))
	for _, row := range rows {
		v, e := s.decode(row, false)
		if e != nil {
			return nil, 0, e
		}
		out = append(out, v)
	}
	return out, count, nil
}
func (s *Store) Health() Health {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stats, e := s.index.Stats(ctx)
	out := Health{Records: stats.Records, Bytes: stats.Bytes}
	if e != nil {
		out.ErrorCode = "history_unavailable"
	}
	return out
}
func (s *Store) Close() error { return s.index.Close() }
