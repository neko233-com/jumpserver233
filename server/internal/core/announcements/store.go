// Package announcements owns platform-wide notices and per-revision reading receipts.
package announcements

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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

	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

var (
	ErrInvalid  = errors.New("invalid announcement")
	ErrConflict = errors.New("announcement revision or request conflicts")
	ErrNotFound = errors.New("announcement not found")
	ErrCapacity = errors.New("announcement capacity reached")
	ErrClosed   = errors.New("announcement store closed")
)

const maxBytes = 16 << 20

var noticeID = regexp.MustCompile(`^notice-[a-f0-9]{32}$`)
var requestID = regexp.MustCompile(`^[A-Za-z0-9_-]{8,100}$`)
var requestHash = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Text struct {
	English string `json:"en"`
	Chinese string `json:"zh-CN"`
}
type Input struct {
	Title     Text      `json:"title"`
	Body      Text      `json:"body"`
	Severity  string    `json:"severity"`
	Published bool      `json:"published"`
	Pinned    bool      `json:"pinned"`
	StartsAt  time.Time `json:"starts_at,omitzero"`
	EndsAt    time.Time `json:"ends_at,omitzero"`
	Revision  int       `json:"revision"`
	RequestID string    `json:"request_id,omitempty"`
}
type Notice struct {
	Input
	ID        string    `json:"id"`
	UpdatedAt time.Time `json:"updated_at"`
}
type Reading struct {
	UserID   string    `json:"user_id"`
	NoticeID string    `json:"notice_id"`
	Revision int       `json:"revision"`
	At       time.Time `json:"at"`
}
type View struct {
	Notice
	Read bool `json:"read"`
}
type Audit struct {
	At       time.Time `json:"at"`
	ActorID  string    `json:"actor_id"`
	Action   string    `json:"action"`
	NoticeID string    `json:"notice_id"`
	Revision int       `json:"revision"`
}
type receipt struct {
	ActorID   string `json:"actor_id"`
	RequestID string `json:"request_id"`
	Hash      string `json:"hash"`
	Result    Notice `json:"result"`
}
type state struct {
	Notices  map[string]Notice  `json:"notices"`
	Readings map[string]Reading `json:"readings"`
	Receipts []receipt          `json:"receipts"`
	Audit    []Audit            `json:"audit"`
}
type envelope struct {
	Version    int    `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}
type Store struct {
	mu     sync.Mutex
	path   string
	docs   *storage.Documents
	aead   cipher.AEAD
	data   state
	now    func() time.Time
	closed bool
}

func safeText(v string, limit int, multiline bool) bool {
	return utf8.ValidString(v) && utf8.RuneCountInString(v) <= limit && strings.IndexFunc(v, func(r rune) bool { return unicode.IsControl(r) && (!multiline || r != '\n' && r != '\t') }) < 0
}
func Prepare(in Input) (Input, error) {
	in.Title.English, in.Title.Chinese = strings.TrimSpace(in.Title.English), strings.TrimSpace(in.Title.Chinese)
	in.Body.English, in.Body.Chinese = strings.TrimSpace(in.Body.English), strings.TrimSpace(in.Body.Chinese)
	in.Body.English, in.Body.Chinese = strings.ReplaceAll(in.Body.English, "\r\n", "\n"), strings.ReplaceAll(in.Body.Chinese, "\r\n", "\n")
	if in.Severity == "" {
		in.Severity = "info"
	}
	if (in.Title.English == "" || in.Body.English == "") && (in.Title.Chinese == "" || in.Body.Chinese == "") || !safeText(in.Title.English, 200, false) || !safeText(in.Title.Chinese, 200, false) || !safeText(in.Body.English, 16000, true) || !safeText(in.Body.Chinese, 16000, true) || in.Revision < 0 || in.Severity != "info" && in.Severity != "maintenance" && in.Severity != "security" || !in.EndsAt.IsZero() && !in.StartsAt.IsZero() && !in.EndsAt.After(in.StartsAt) {
		return in, ErrInvalid
	}
	in.StartsAt, in.EndsAt = in.StartsAt.UTC(), in.EndsAt.UTC()
	return in, nil
}
func validActor(actor string) bool { return actor != "" && safeText(actor, 128, false) }
func validNotice(n Notice) bool {
	normalized, e := Prepare(n.Input)
	return e == nil && noticeID.MatchString(n.ID) && n.Revision > 0 && !n.UpdatedAt.IsZero() && n.RequestID == "" && normalized == n.Input
}
func (s *Store) validate(st state) error {
	if st.Notices == nil || st.Readings == nil || len(st.Notices) > 500 || len(st.Readings) > 20000 || len(st.Receipts) > 4000 || len(st.Audit) > 1000 {
		return ErrInvalid
	}
	for id, n := range st.Notices {
		if id != n.ID || !validNotice(n) {
			return ErrInvalid
		}
	}
	for key, r := range st.Readings {
		n, ok := st.Notices[r.NoticeID]
		if !ok || !validActor(r.UserID) || key != r.UserID+"\x00"+r.NoticeID || r.Revision != n.Revision || r.At.IsZero() {
			return ErrInvalid
		}
	}
	seen := map[string]bool{}
	for _, r := range st.Receipts {
		key := r.ActorID + "\x00" + r.RequestID
		if !validActor(r.ActorID) || !requestID.MatchString(r.RequestID) || seen[key] || !requestHash.MatchString(r.Hash) || !validNotice(r.Result) {
			return ErrInvalid
		}
		seen[key] = true
	}
	for _, a := range st.Audit {
		if !validActor(a.ActorID) || !noticeID.MatchString(a.NoticeID) || a.Revision < 1 || a.At.IsZero() || a.Action != "save" && a.Action != "delete" {
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
	s := &Store{path: path, docs: docs, aead: aead, now: time.Now, data: state{Notices: map[string]Notice{}, Readings: map[string]Reading{}, Receipts: []receipt{}, Audit: []Audit{}}}
	var raw []byte
	if docs != nil {
		raw, e = docs.LoadOrImport("announcements", path)
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
	if len(raw) == 0 {
		return s, nil
	}
	if len(raw) > 2*maxBytes {
		return nil, ErrInvalid
	}
	var box envelope
	if json.Unmarshal(raw, &box) != nil || box.Version != 1 || len(box.Nonce) != aead.NonceSize() {
		return nil, ErrInvalid
	}
	plain, e := aead.Open(nil, box.Nonce, box.Ciphertext, []byte("jms233/announcements/v1"))
	if e != nil {
		return nil, ErrInvalid
	}
	if len(plain) > maxBytes {
		return nil, ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if dec.Decode(&s.data) != nil || dec.Decode(new(any)) != io.EOF || s.validate(s.data) != nil {
		return nil, ErrInvalid
	}
	return s, nil
}
func (s *Store) Close() { s.mu.Lock(); defer s.mu.Unlock(); s.closed = true }
func (s *Store) persist(st state) error {
	if e := s.validate(st); e != nil {
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
	raw, e := json.Marshal(envelope{Version: 1, Nonce: nonce, Ciphertext: s.aead.Seal(nil, nonce, plain, []byte("jms233/announcements/v1"))})
	if e != nil {
		return e
	}
	if s.docs != nil {
		return s.docs.Save("announcements", raw)
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".announcements-*")
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
	return os.Rename(f.Name(), s.path)
}
func clone(st state) state {
	out := state{Notices: map[string]Notice{}, Readings: map[string]Reading{}, Receipts: append([]receipt{}, st.Receipts...), Audit: append([]Audit{}, st.Audit...)}
	for k, v := range st.Notices {
		out.Notices[k] = v
	}
	for k, v := range st.Readings {
		out.Readings[k] = v
	}
	return out
}
func (s *Store) active(n Notice) bool {
	now := s.now()
	return n.Published && (n.StartsAt.IsZero() || !now.Before(n.StartsAt)) && (n.EndsAt.IsZero() || now.Before(n.EndsAt))
}
func (s *Store) Page(user string, manage bool, offset, limit int) ([]View, int, int, error) {
	if !validActor(user) || offset < 0 || limit < 1 || limit > 100 {
		return nil, 0, 0, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, 0, 0, ErrClosed
	}
	rows := []View{}
	unread := 0
	for _, n := range s.data.Notices {
		if !manage && !s.active(n) {
			continue
		}
		read := s.data.Readings[user+"\x00"+n.ID].Revision == n.Revision
		rows = append(rows, View{Notice: n, Read: read})
		if s.active(n) && !read {
			unread++
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Pinned != rows[j].Pinned {
			return rows[i].Pinned
		}
		if !rows[i].UpdatedAt.Equal(rows[j].UpdatedAt) {
			return rows[i].UpdatedAt.After(rows[j].UpdatedAt)
		}
		return rows[i].ID < rows[j].ID
	})
	total := len(rows)
	offset = min(offset, total)
	return rows[offset:min(offset+limit, total)], total, unread, nil
}
func digest(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func prior(st state, actor, request, hash string) (Notice, bool, error) {
	for _, r := range st.Receipts {
		if r.ActorID == actor && r.RequestID == request {
			if r.Hash != hash {
				return Notice{}, true, ErrConflict
			}
			return r.Result, true, nil
		}
	}
	return Notice{}, false, nil
}
func (s *Store) saveResult(st state, n Notice, actor, request, hash, action string) error {
	if len(st.Receipts) >= 4000 {
		return ErrCapacity
	}
	st.Receipts = append(st.Receipts, receipt{ActorID: actor, RequestID: request, Hash: hash, Result: n})
	st.Audit = append(st.Audit, Audit{At: s.now().UTC(), ActorID: actor, Action: action, NoticeID: n.ID, Revision: n.Revision})
	if len(st.Audit) > 1000 {
		st.Audit = st.Audit[len(st.Audit)-1000:]
	}
	if e := s.persist(st); e != nil {
		return e
	}
	s.data = st
	return nil
}
func (s *Store) Save(id, actor string, in Input) (Notice, error) {
	in, e := Prepare(in)
	if e != nil || !validActor(actor) || !requestID.MatchString(in.RequestID) || id != "" && !noticeID.MatchString(id) {
		return Notice{}, ErrInvalid
	}
	hash := digest([]any{"save", id, in})
	request := in.RequestID
	in.RequestID = ""
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Notice{}, ErrClosed
	}
	if n, found, e := prior(s.data, actor, request, hash); found {
		return n, e
	}
	st := clone(s.data)
	current, exists := st.Notices[id]
	if id != "" && !exists {
		return Notice{}, ErrNotFound
	}
	if exists && current.Revision != in.Revision || !exists && in.Revision != 0 {
		return Notice{}, ErrConflict
	}
	if !exists {
		if len(st.Notices) >= 500 {
			return Notice{}, ErrCapacity
		}
		random := make([]byte, 16)
		if _, e = rand.Read(random); e != nil {
			return Notice{}, e
		}
		id = "notice-" + hex.EncodeToString(random)
		if _, collision := st.Notices[id]; collision {
			return Notice{}, ErrConflict
		}
	}
	in.Revision++
	n := Notice{ID: id, Input: in, UpdatedAt: s.now().UTC()}
	st.Notices[id] = n
	for k, r := range st.Readings {
		if r.NoticeID == id {
			delete(st.Readings, k)
		}
	}
	if e = s.saveResult(st, n, actor, request, hash, "save"); e != nil {
		return Notice{}, e
	}
	return n, nil
}
func (s *Store) Delete(id, actor string, revision int, request string) error {
	if !noticeID.MatchString(id) || !validActor(actor) || revision < 1 || !requestID.MatchString(request) {
		return ErrInvalid
	}
	hash := digest([]any{"delete", id, revision})
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if _, found, e := prior(s.data, actor, request, hash); found {
		return e
	}
	st := clone(s.data)
	n, ok := st.Notices[id]
	if !ok {
		return ErrNotFound
	}
	if n.Revision != revision {
		return ErrConflict
	}
	delete(st.Notices, id)
	for k, r := range st.Readings {
		if r.NoticeID == id {
			delete(st.Readings, k)
		}
	}
	return s.saveResult(st, n, actor, request, hash, "delete")
}
func (s *Store) Acknowledge(id, user string, revision int) (Reading, error) {
	if !noticeID.MatchString(id) || !validActor(user) || revision < 1 {
		return Reading{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Reading{}, ErrClosed
	}
	n, ok := s.data.Notices[id]
	if !ok || !s.active(n) {
		return Reading{}, ErrNotFound
	}
	if revision != n.Revision {
		return Reading{}, ErrConflict
	}
	key := user + "\x00" + id
	if r, ok := s.data.Readings[key]; ok {
		return r, nil
	}
	if len(s.data.Readings) >= 20000 {
		return Reading{}, ErrCapacity
	}
	st := clone(s.data)
	r := Reading{UserID: user, NoticeID: id, Revision: revision, At: s.now().UTC()}
	st.Readings[key] = r
	if e := s.persist(st); e != nil {
		return Reading{}, e
	}
	s.data = st
	return r, nil
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
