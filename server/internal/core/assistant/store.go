package assistant

import (
	"bytes"
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
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/aichat"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
)

const maxStateBytes = 16 << 20

type configuration struct {
	SettingsView
	Secret string `json:"secret"`
}
type receipt struct {
	Actor, Request, Hash, Kind string
	ConversationID, TurnID     string
	Settings                   SettingsView
	Revision                   int
	At                         time.Time
}
type state struct {
	Version       int
	Settings      configuration
	Conversations map[string]Conversation
	Receipts      []receipt
	Audit         []Audit
}
type envelope struct {
	Version     int
	Nonce, Data []byte
}
type Service struct {
	mu       sync.Mutex
	path     string
	docs     *storage.Documents
	aead     cipher.AEAD
	hashKey  []byte
	data     state
	ctx      context.Context
	cancel   context.CancelFunc
	closed   bool
	wg       sync.WaitGroup
	calls    map[string]context.CancelFunc
	gate     *workgate.Gate
	now      func() time.Time
	complete func(context.Context, aichat.Settings, string, []aichat.Message) (aichat.Result, error)
	saveHook func([]byte) error
}

func Open(path string, key []byte, docs *storage.Documents) (*Service, error) {
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
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("jms233/assistant/request-key/v1"))
	s := &Service{path: path, docs: docs, aead: aead, hashKey: mac.Sum(nil), ctx: ctx, cancel: cancel, calls: map[string]context.CancelFunc{}, now: time.Now, complete: aichat.Complete, data: state{Version: 1, Settings: configuration{SettingsView: SettingsView{Settings: aichat.Settings{MaxTokens: 1024}}}, Conversations: map[string]Conversation{}, Receipts: []receipt{}, Audit: []Audit{}}}
	var raw []byte
	if docs != nil {
		raw, e = docs.LoadOrImport("assistant", path)
	} else {
		var f *os.File
		f, e = os.Open(path)
		if e == nil {
			raw, e = io.ReadAll(io.LimitReader(f, 2*maxStateBytes+1))
			_ = f.Close()
		} else if errors.Is(e, os.ErrNotExist) {
			e = nil
		}
	}
	if e != nil {
		cancel()
		return nil, e
	}
	if len(raw) > 0 {
		var box envelope
		if len(raw) > 2*maxStateBytes || strict(raw, &box) != nil || box.Version != 1 || len(box.Nonce) != aead.NonceSize() {
			cancel()
			return nil, ErrInvalid
		}
		plain, e := aead.Open(nil, box.Nonce, box.Data, []byte("jms233/assistant/v1"))
		if e != nil || len(plain) > maxStateBytes || strict(plain, &s.data) != nil || validateState(s.data) != nil {
			cancel()
			return nil, ErrInvalid
		}
	}
	return s, nil
}
func strict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func validateState(st state) error {
	if st.Version != 1 || st.Conversations == nil || len(st.Conversations) > 256 || len(st.Receipts) > 4000 || len(st.Audit) > 4000 || st.Settings.Revision < 0 {
		return ErrInvalid
	}
	if st.Settings.Revision > 0 && (aichat.Validate(st.Settings.Settings) != nil || st.Settings.Configured != aichat.ValidSecret(st.Settings.Secret) || st.Settings.Enabled && !st.Settings.Configured) {
		return ErrInvalid
	}
	seenTurn := map[string]bool{}
	for id, c := range st.Conversations {
		if id != c.ID || !conversationID.MatchString(id) || !identifier.MatchString(c.OwnerID) || !aichat.Text(c.Title, 320) || c.Revision < 1 || c.CreatedAt.IsZero() || c.UpdatedAt.Before(c.CreatedAt) || len(c.Turns) == 0 || len(c.Turns) > 32 {
			return ErrInvalid
		}
		for _, t := range c.Turns {
			if !turnID.MatchString(t.ID) || seenTurn[t.ID] || t.ConversationID != id || !requestID.MatchString(t.RequestID) || !aichat.Text(t.Message, 12000) || !aichat.Text(t.Model, 128) || t.SettingsRevision < 1 || t.At.IsZero() || t.PromptTokens < 0 || t.CompletionTokens < 0 || !slices.Contains([]string{"pending", "completed", "failed", "uncertain", "revoked"}, t.Status) || t.Status == "pending" && !t.FinishedAt.IsZero() || t.Status != "pending" && (t.FinishedAt.IsZero() || t.FinishedAt.Before(t.At)) || t.Status == "completed" && !aichat.Text(t.Reply, 32768) || t.Status != "completed" && t.Reply != "" {
				return ErrInvalid
			}
			seenTurn[t.ID] = true
		}
	}
	seen := map[string]bool{}
	for _, r := range st.Receipts {
		key := r.Actor + "\x00" + r.Request
		h, e := hex.DecodeString(r.Hash)
		if !identifier.MatchString(r.Actor) || !requestID.MatchString(r.Request) || seen[key] || e != nil || len(h) != 32 || r.At.IsZero() || !slices.Contains([]string{"turn", "settings", "archive"}, r.Kind) {
			return ErrInvalid
		}
		if r.Kind == "turn" && (!conversationID.MatchString(r.ConversationID) || !turnID.MatchString(r.TurnID)) || r.Kind == "archive" && (!conversationID.MatchString(r.ConversationID) || r.Revision < 1) || r.Kind == "settings" && (r.Settings.Revision < 1 || aichat.Validate(r.Settings.Settings) != nil) {
			return ErrInvalid
		}
		seen[key] = true
	}
	for _, a := range st.Audit {
		if a.At.IsZero() || !identifier.MatchString(a.ActorID) || !slices.Contains([]string{"settings", "submitted", "completed", "failed", "uncertain", "revoked", "archive"}, a.Action) || a.Revision < 1 || a.ConversationID != "" && !conversationID.MatchString(a.ConversationID) || a.TurnID != "" && !turnID.MatchString(a.TurnID) {
			return ErrInvalid
		}
	}
	return nil
}
func clone(st state) state {
	out := st
	out.Conversations = map[string]Conversation{}
	for id, c := range st.Conversations {
		c.Turns = append([]Turn{}, c.Turns...)
		out.Conversations[id] = c
	}
	out.Receipts = append([]receipt{}, st.Receipts...)
	out.Audit = append([]Audit{}, st.Audit...)
	return out
}
func (s *Service) commit(st state) error {
	if e := validateState(st); e != nil {
		return e
	}
	plain, e := json.Marshal(st)
	if e != nil {
		return e
	}
	if len(plain) > maxStateBytes {
		return ErrCapacity
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	raw, e := json.Marshal(envelope{Version: 1, Nonce: nonce, Data: s.aead.Seal(nil, nonce, plain, []byte("jms233/assistant/v1"))})
	if e != nil {
		return e
	}
	if s.saveHook != nil {
		if e = s.saveHook(raw); e != nil {
			return e
		}
	}
	if s.docs != nil {
		e = s.docs.Save("assistant", raw)
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
	f, e := os.CreateTemp(filepath.Dir(path), ".assistant-*")
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
	return os.Rename(f.Name(), path)
}
func (s *Service) hash(v any) string {
	raw, _ := json.Marshal(v)
	h := hmac.New(sha256.New, s.hashKey)
	h.Write([]byte("assistant/request/v1\x00"))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}
func id(prefix string) (string, error) {
	raw := make([]byte, 16)
	if _, e := rand.Read(raw); e != nil {
		return "", e
	}
	return prefix + hex.EncodeToString(raw), nil
}
func (s *Service) prior(actor, request, hash, kind string) (receipt, bool, error) {
	for _, r := range s.data.Receipts {
		if r.Actor == actor && r.Request == request {
			if r.Hash != hash || r.Kind != kind {
				return receipt{}, true, ErrConflict
			}
			return r, true, nil
		}
	}
	return receipt{}, false, nil
}
func (s *Service) prune(st *state) {
	now := s.now()
	st.Receipts = slices.DeleteFunc(st.Receipts, func(r receipt) bool { return r.At.Before(now.AddDate(0, 0, -365)) })
	for k, c := range st.Conversations {
		if c.UpdatedAt.Before(now.AddDate(0, 0, -90)) {
			delete(st.Conversations, k)
		}
	}
	st.Audit = slices.DeleteFunc(st.Audit, func(a Audit) bool { return a.At.Before(now.AddDate(0, 0, -365)) })
}
func addAudit(st *state, a Audit) {
	st.Audit = append(st.Audit, a)
	if len(st.Audit) > 4000 {
		st.Audit = st.Audit[len(st.Audit)-4000:]
	}
}
func (s *Service) recoverPending(st *state) bool {
	changed := false
	now := s.now().UTC()
	for id, c := range st.Conversations {
		for i, t := range c.Turns {
			if t.Status == "pending" && s.calls[t.ID] == nil {
				t.Status = "uncertain"
				t.FinishedAt = now
				c.Turns[i] = t
				c.Revision++
				c.UpdatedAt = now
				changed = true
				addAudit(st, Audit{At: now, ActorID: c.OwnerID, Action: "uncertain", ConversationID: id, TurnID: t.ID, Revision: c.Revision})
			}
		}
		st.Conversations[id] = c
	}
	return changed
}
func (s *Service) BindOwner(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil || ctx.Err() != nil {
		return ErrBusy
	}
	st := clone(s.data)
	if s.recoverPending(&st) {
		if e := s.commit(st); e != nil {
			return e
		}
	}
	context.AfterFunc(ctx, s.cancel)
	return nil
}
func (s *Service) SetAdmissionGate(g *workgate.Gate) { s.mu.Lock(); defer s.mu.Unlock(); s.gate = g }
func (s *Service) Close() {
	s.mu.Lock()
	s.closed = true
	s.cancel()
	for _, cancel := range s.calls {
		cancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
}
