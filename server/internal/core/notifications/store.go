package notifications

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/connector/cloudnotify"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

type challenge struct {
	Hash, Nonce string
	Expires     time.Time
	Attempts    int
}
type profile struct {
	Preferences
	EmailCode, PhoneCode challenge
	Requests, Tests      []time.Time
}
type config struct {
	Settings
	SMTPPassword, WebhookBearer, WebhookSecret, SMSBearer, SMSSecret string
}
type settingsReceipt struct {
	ActorID, RequestID, Hash string
	Result                   Settings
}

func (c config) Validate() error {
	if c.Settings.Validate() != nil {
		return ErrInvalid
	}
	if c.Webhook.Enabled && cloudnotify.ChatKind(c.Webhook.Provider) && (!botTokenValid(c.WebhookBearer) || c.Webhook.Provider == "dingtalk" && c.WebhookSecret == "") {
		return ErrInvalid
	}
	if c.SMS.Enabled && cloudnotify.SMSKind(c.SMS.Provider) && (c.SMSSecret == "" || !validText(c.SMSSecret, 4096)) {
		return ErrInvalid
	}
	return nil
}
func botTokenValid(v string) bool {
	if len(v) < 8 || len(v) > 256 {
		return false
	}
	for _, r := range v {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

type delivery struct {
	Delivery
	Address, Code, ChallengeHash string
	Message                      Message
}
type cursor struct {
	Anchor string
	Gap    bool
	At     time.Time
}
type state struct {
	SettingsReceipts []settingsReceipt
	Version          int
	CreatedAt        time.Time
	Config           config
	Profiles         map[string]profile
	Messages         map[string]Message
	Deliveries       map[string]delivery
	Cursors          map[string]cursor
	Audit            []Audit
}
type envelope struct {
	Version    int    `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}
type Service struct {
	mu              sync.Mutex
	op              sync.Mutex
	closeOnce       sync.Once
	wg              sync.WaitGroup
	path            string
	docs            *storage.Documents
	aead            cipher.AEAD
	data            state
	runner          Runner
	ctx             context.Context
	cancel          context.CancelFunc
	started, closed bool
	now             func() time.Time
	saveHook        func([]byte) error
	active          map[string]bool
	lastMaintenance time.Time
	sourceErrors    map[string]bool
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
	s := &Service{path: path, docs: docs, aead: aead, ctx: ctx, cancel: cancel, now: time.Now, active: map[string]bool{}, data: state{Version: 1, CreatedAt: time.Now().UTC(), Config: config{Settings: Settings{Revision: 1, SMTP: SMTP{Port: 587, Mode: "starttls", SubjectPrefix: "[JumpServer233]"}}}, Profiles: map[string]profile{}, Messages: map[string]Message{}, Deliveries: map[string]delivery{}, Cursors: map[string]cursor{}, Audit: []Audit{}}}
	var raw []byte
	if docs != nil {
		raw, e = docs.LoadOrImport("notifications", path)
	} else {
		raw, e = os.ReadFile(path)
		if errors.Is(e, os.ErrNotExist) {
			e = nil
		}
	}
	if e != nil {
		cancel()
		return nil, e
	}
	if len(raw) > 0 {
		var box envelope
		if len(raw) > MaxState*2 || strict(raw, &box) != nil || box.Version != 1 || len(box.Nonce) != aead.NonceSize() {
			cancel()
			return nil, ErrInvalid
		}
		plain, e := aead.Open(nil, box.Nonce, box.Ciphertext, []byte("jms233/notifications/v1"))
		if e != nil || len(plain) > MaxState || strict(plain, &s.data) != nil || validate(s.data) != nil {
			cancel()
			return nil, ErrInvalid
		}
	}
	// The start boundary is durable before business events can arrive. Sending
	// records recovered without a committed outcome are never replayed silently.
	next := clone(s.data)
	changed := len(raw) == 0
	for id, v := range next.Deliveries {
		if v.State == "sending" {
			v.State = "uncertain"
			v.ErrorCode = "interrupted"
			v.Code = ""
			v.UpdatedAt = s.now().UTC()
			v.Revision++
			next.Deliveries[id] = v
			changed = true
		}
	}
	if changed {
		if e = s.persist(next); e != nil {
			cancel()
			return nil, e
		}
		s.data = next
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
func cloneProfile(p profile) profile {
	p.Topics = cloneTopics(p.Topics)
	p.Requests = slices.Clone(p.Requests)
	p.Tests = slices.Clone(p.Tests)
	return p
}
func cloneTopics(rows map[string][]string) map[string][]string {
	out := map[string][]string{}
	for k, v := range rows {
		out[k] = slices.Clone(v)
	}
	return out
}
func cloneMessage(m Message) Message {
	if m.ReadAt != nil {
		v := *m.ReadAt
		m.ReadAt = &v
	}
	return m
}
func clone(d state) state {
	v := d
	v.Config.Settings = cloneSettings(d.Config.Settings)
	v.SettingsReceipts = slices.Clone(d.SettingsReceipts)
	for i := range v.SettingsReceipts {
		v.SettingsReceipts[i].Result = cloneSettings(v.SettingsReceipts[i].Result)
	}
	v.Profiles = map[string]profile{}
	for k, p := range d.Profiles {
		v.Profiles[k] = cloneProfile(p)
	}
	v.Messages = map[string]Message{}
	for k, m := range d.Messages {
		v.Messages[k] = cloneMessage(m)
	}
	v.Deliveries = map[string]delivery{}
	for k, e := range d.Deliveries {
		e.Message = cloneMessage(e.Message)
		v.Deliveries[k] = e
	}
	v.Cursors = map[string]cursor{}
	for k, c := range d.Cursors {
		v.Cursors[k] = c
	}
	v.Audit = slices.Clone(d.Audit)
	return v
}
func defaultProfile() profile {
	topics := map[string][]string{}
	for _, topic := range Topics {
		topics[topic] = []string{"inbox"}
	}
	return profile{Preferences: Preferences{Revision: 1, Language: "auto", DetectedLanguage: "en", Topics: topics}}
}
func profileFor(d state, id string) profile {
	if p, ok := d.Profiles[id]; ok {
		return cloneProfile(p)
	}
	return defaultProfile()
}
func validLink(v string) bool {
	return len(v) <= 2048 && strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "//") && validText(v, 2048) && !strings.Contains(v, "\\")
}
func validate(d state) error {
	if len(d.SettingsReceipts) > 2000 {
		return ErrInvalid
	}
	for _, r := range d.SettingsReceipts {
		if !idPattern.MatchString(r.ActorID) || !idPattern.MatchString(r.RequestID) || !validHash(r.Hash) || r.Result.Validate() != nil {
			return ErrInvalid
		}
	}
	if d.Version != 1 || d.CreatedAt.IsZero() || d.Config.Revision < 1 || d.Config.Validate() != nil || d.Profiles == nil || d.Messages == nil || d.Deliveries == nil || d.Cursors == nil || len(d.Messages) > MaxMessages || len(d.Deliveries) > MaxDeliveries || len(d.Audit) > MaxAudit || len(d.Cursors) > 16 || len(d.Profiles) > 20000 {
		return ErrInvalid
	}
	for id, p := range d.Profiles {
		in := PreferencesInput{Revision: p.Revision, Language: p.Language, Email: p.Email, Phone: p.Phone, Topics: p.Topics}
		if !idPattern.MatchString(id) || in.Validate() != nil || p.DetectedLanguage != "en" && p.DetectedLanguage != "zh-CN" || p.EmailVerified && p.Email == "" || p.PhoneVerified && p.Phone == "" || len(p.Requests) > 12 || len(p.Tests) > 12 {
			return ErrInvalid
		}
		for _, c := range []challenge{p.EmailCode, p.PhoneCode} {
			if c.Hash != "" && (!validHash(c.Hash) || c.Nonce == "" || c.Expires.IsZero()) || c.Attempts < 0 || c.Attempts > 8 {
				return ErrInvalid
			}
		}
	}
	for id, m := range d.Messages {
		if id != m.ID || !idPattern.MatchString(id) || !idPattern.MatchString(m.UserID) || !slices.Contains(Topics, m.Topic) || m.At.IsZero() || !validText(m.Name, 480) || !validText(m.State, 64) || !validLink(m.Link) || !validText(m.Actor, 128) || m.Source.Kind == "" || !idPattern.MatchString(m.Source.ID) || !validHash(m.Source.EventID) || !validText(m.Source.Action, 64) {
			return ErrInvalid
		}
	}
	for id, v := range d.Deliveries {
		if id != v.ID || !idPattern.MatchString(id) || !idPattern.MatchString(v.UserID) || !slices.Contains([]string{"email", "sms", "webhook"}, v.Channel) || v.Revision < 1 || v.ConfigRevision < 1 || v.Attempts < 0 || v.Attempts > 5 || v.CreatedAt.IsZero() || v.UpdatedAt.IsZero() || !validText(v.ErrorCode, 64) || !validText(v.Receipt, 128) {
			return ErrInvalid
		}
		switch v.State {
		case "queued", "sending", "retry", "sent", "failed", "uncertain", "suppressed":
		default:
			return ErrInvalid
		}
		if v.ChallengeHash != "" {
			if v.Code != "" && len(v.Code) != 6 || !validHash(v.ChallengeHash) || v.Message.Source.Kind != "verification" {
				return ErrInvalid
			}
		} else if m, ok := d.Messages[v.MessageID]; !ok || m.UserID != v.UserID || v.Message.ID != m.ID || v.Message.UserID != m.UserID || v.Message.Source != m.Source || v.Message.Topic != m.Topic {
			return ErrInvalid
		}
	}
	for name, c := range d.Cursors {
		if !idPattern.MatchString(name) || c.Anchor != "" && !validHash(c.Anchor) {
			return ErrInvalid
		}
	}
	return nil
}
func validHash(v string) bool {
	raw, e := hex.DecodeString(v)
	return e == nil && len(raw) == 32 && hex.EncodeToString(raw) == v
}
func newID(prefix string) (string, error) {
	var v [16]byte
	if _, e := rand.Read(v[:]); e != nil {
		return "", e
	}
	return prefix + hex.EncodeToString(v[:]), nil
}
func (s *Service) persist(d state) error {
	if s.closed || s.ctx.Err() != nil {
		return ErrUnavailable
	}
	if e := validate(d); e != nil {
		return e
	}
	plain, e := json.Marshal(d)
	if e != nil {
		return e
	}
	if len(plain) > MaxState {
		return ErrCapacity
	}
	n := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return e
	}
	raw, e := json.Marshal(envelope{1, n, s.aead.Seal(nil, n, plain, []byte("jms233/notifications/v1"))})
	if e != nil {
		return e
	}
	if s.saveHook != nil {
		if e = s.saveHook(raw); e != nil {
			return e
		}
	}
	if s.docs != nil {
		return s.docs.Save("notifications", raw)
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".notifications-*")
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
func (s *Service) mutate(fn func(*state) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrUnavailable
	}
	next := clone(s.data)
	if e := fn(&next); e != nil {
		return e
	}
	if reflect.DeepEqual(next, s.data) {
		return nil
	}
	if e := s.persist(next); e != nil {
		return e
	}
	s.data = next
	return nil
}
func audit(d *state, a Audit) {
	if len(d.Audit) >= MaxAudit {
		d.Audit = slices.Delete(d.Audit, 0, len(d.Audit)-MaxAudit+1)
	}
	d.Audit = append(d.Audit, a)
}
func (s *Service) SetRunner(r Runner)     { s.mu.Lock(); defer s.mu.Unlock(); s.runner = r }
func (s *Service) snapshotRunner() Runner { s.mu.Lock(); defer s.mu.Unlock(); return s.runner }
func (s *Service) principal(ctx context.Context, id string) (Principal, error) {
	if s.ctx.Err() != nil {
		return Principal{}, ErrUnavailable
	}
	r := s.snapshotRunner()
	if r.Principal == nil {
		return Principal{}, ErrUnavailable
	}
	p, e := r.Principal(ctx, id)
	if e != nil && !errors.Is(e, ErrDenied) && !errors.Is(e, ErrNotFound) {
		return Principal{}, ErrUnavailable
	}
	if e != nil || p.ID != id || !validActor(p.Actor) {
		return Principal{}, ErrDenied
	}
	return p, nil
}
func (s *Service) allowed(ctx context.Context, user string, m Message) (bool, error) {
	if m.At.Before(s.now().Add(-30 * 24 * time.Hour)) {
		return false, nil
	}
	if _, e := s.principal(ctx, user); e != nil {
		if errors.Is(e, ErrDenied) || errors.Is(e, ErrNotFound) {
			return false, nil
		}
		return false, e
	}
	if m.Source.Kind == "test" {
		return m.UserID == user, nil
	}
	for _, feed := range s.snapshotRunner().Feeds {
		if feed.Name == m.Source.Kind && feed.Allowed != nil {
			return feed.Allowed(ctx, user, m.Source)
		}
	}
	return false, nil
}
func messageID(source Source, topic, user string) string {
	return "message-" + eventfeed.Digest([]string{source.Kind, source.EventID, topic, user})
}
func deliveryID(message, channel string) string {
	return "delivery-" + eventfeed.Digest([]string{message, channel})
}
