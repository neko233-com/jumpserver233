// Package loginreviews holds encrypted, source-bound platform sign-in reviews.
// Approval never issues a session; only the original one-use ticket can finish.
package loginreviews

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

var (
	ErrInvalid     = errors.New("invalid platform login review")
	ErrNotFound    = errors.New("platform login review not found")
	ErrState       = errors.New("platform login review is not in the required state")
	ErrReviewer    = errors.New("platform login reviewer is not allowed")
	ErrCapacity    = errors.New("platform login review capacity reached")
	ErrInvalidated = errors.New("platform login proof or policy changed")
)

const (
	Pending     = "pending"
	Approved    = "approved"
	Denied      = "denied"
	Expired     = "expired"
	Cancelled   = "cancelled"
	Consumed    = "consumed"
	Invalidated = "invalidated"
	Notified    = "notified"
	MaxRecords  = 5000
	MaxAudit    = 10000
	MaxPending  = 4096
	Retention   = 7 * 24 * time.Hour
)

type Review struct {
	ID               string     `json:"id"`
	UserID           string     `json:"user_id"`
	Username         string     `json:"username"`
	SourceIP         string     `json:"source_ip"`
	AuthSource       string     `json:"auth_source"`
	RuleID           string     `json:"rule_id"`
	RuleName         string     `json:"rule_name"`
	RuleRevision     int        `json:"rule_revision"`
	ApproverIDs      []string   `json:"approver_ids"`
	ApproverGroupIDs []string   `json:"approver_group_ids"`
	State            string     `json:"state"`
	CreatedAt        time.Time  `json:"created_at"`
	ExpiresAt        time.Time  `json:"expires_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	ReviewedBy       string     `json:"reviewed_by,omitempty"`
	ReviewedAt       *time.Time `json:"reviewed_at,omitempty"`
}
type Audit struct {
	ID       string    `json:"id"`
	ReviewID string    `json:"review_id"`
	UserID   string    `json:"user_id"`
	Username string    `json:"username"`
	SourceIP string    `json:"source_ip"`
	RuleID   string    `json:"rule_id"`
	Action   string    `json:"action"`
	ActorID  string    `json:"actor_id"`
	At       time.Time `json:"at"`
}

// Input and Payload are internal only. In particular, Proof and ticket hashes
// must never be included in an HTTP response, audit event or diagnostic.
type Input struct {
	UserID, Username, SourceIP, AuthSource, RuleID, RuleName string
	RuleRevision                                             int
	ApproverIDs, ApproverGroupIDs                            []string
	Proof                                                    string
	ExpiresAt                                                time.Time
	Browser, Secure                                          bool
}
type Payload struct {
	Review
	Proof           string
	Browser, Secure bool
}
type record struct {
	Review
	Proof                string     `json:"proof,omitempty"`
	TicketHash           []byte     `json:"ticket_hash,omitempty"`
	CompletedSessionHash []byte     `json:"completed_session_hash,omitempty"`
	Browser              bool       `json:"browser"`
	Secure               bool       `json:"secure"`
	PermitExpiresAt      *time.Time `json:"permit_expires_at,omitempty"`
}
type state struct {
	Records map[string]record `json:"records"`
	Audit   []Audit           `json:"audit"`
}
type envelope struct {
	Version    int    `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}
type Store struct {
	mu        sync.Mutex
	path      string
	documents *storage.Documents
	aead      cipher.AEAD
	data      state
	tickets   map[[32]byte]string
	now       func() time.Time
}
type Completion struct {
	Session         coreauth.LoginSession
	Browser, Secure bool
}

func Open(path string, key []byte, documents *storage.Documents) (*Store, error) {
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
	s := &Store{path: path, documents: documents, aead: aead, now: time.Now, tickets: map[[32]byte]string{}, data: state{Records: map[string]record{}, Audit: []Audit{}}}
	var raw []byte
	if documents != nil {
		raw, e = documents.LoadOrImport("platform-login-reviews", path)
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
	var sealed envelope
	if json.Unmarshal(raw, &sealed) != nil || sealed.Version != 1 || len(sealed.Nonce) != aead.NonceSize() {
		return nil, ErrInvalid
	}
	plain, e := aead.Open(nil, sealed.Nonce, sealed.Ciphertext, []byte("jms233/platform-login-reviews/v1"))
	if e != nil {
		return nil, ErrInvalid
	}
	if json.Unmarshal(plain, &s.data) != nil || s.data.Records == nil || len(s.data.Records) > MaxRecords || len(s.data.Audit) > MaxAudit {
		return nil, ErrInvalid
	}
	seen := map[string]bool{}
	for id, r := range s.data.Records {
		if id != r.ID || !validReview(r.Review) || len(r.TicketHash) != 0 && len(r.TicketHash) != 32 || len(r.Proof) > 8192 || len(r.CompletedSessionHash) != 0 && len(r.CompletedSessionHash) != 32 || live(r.State) && len(r.CompletedSessionHash) > 0 {
			return nil, ErrInvalid
		}
		if live(r.State) && (len(r.TicketHash) != 32 || r.Proof == "") {
			return nil, ErrInvalid
		}
		if !live(r.State) && r.Proof != "" {
			return nil, ErrInvalid
		}
		if r.State == Approved && (r.PermitExpiresAt == nil || r.ReviewedAt == nil || r.ReviewedBy == "" || r.ReviewedBy == r.UserID) {
			return nil, ErrInvalid
		}
		if len(r.TicketHash) > 0 {
			digest := hex.EncodeToString(r.TicketHash)
			if seen[digest] {
				return nil, ErrInvalid
			}
			seen[digest] = true
		}
	}
	for _, a := range s.data.Audit {
		if a.ID == "" || a.ReviewID == "" || a.UserID == "" || a.ActorID == "" || a.At.IsZero() || !validState(a.Action) {
			return nil, ErrInvalid
		}
	}
	s.rebuildTicketsLocked()
	return s, nil
}
func validState(state string) bool {
	return slices.Contains([]string{Pending, Approved, Denied, Expired, Cancelled, Consumed, Invalidated, Notified}, state)
}
func live(state string) bool { return state == Pending || state == Approved }
func validText(value string, max int) bool {
	return len(value) <= max && strings.IndexFunc(value, unicode.IsControl) < 0
}
func validReview(r Review) bool {
	if !strings.HasPrefix(r.ID, "lrv-") || len(r.ID) != 36 || r.UserID == "" || r.Username == "" || r.RuleID == "" || r.RuleRevision < 1 || r.CreatedAt.IsZero() || r.ExpiresAt.Before(r.CreatedAt) || r.UpdatedAt.Before(r.CreatedAt) || !validState(r.State) || len(r.ApproverIDs) > 50 || len(r.ApproverGroupIDs) > 50 {
		return false
	}
	if _, e := hex.DecodeString(r.ID[4:]); e != nil {
		return false
	}
	for _, v := range []string{r.UserID, r.Username, r.RuleID, r.AuthSource} {
		if !validText(v, 128) {
			return false
		}
	}
	return validText(r.SourceIP, 64) && validText(r.RuleName, 100)
}
func randomID(prefix string) (string, error) {
	var raw [16]byte
	if _, e := rand.Read(raw[:]); e != nil {
		return "", e
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}
func clone[T any](in T) T {
	raw, _ := json.Marshal(in)
	var out T
	_ = json.Unmarshal(raw, &out)
	return out
}
func audit(data *state, r record, action, actor string, now time.Time) error {
	id, e := randomID("lra-")
	if e != nil {
		return e
	}
	if len(data.Audit) >= MaxAudit {
		data.Audit = append([]Audit{}, data.Audit[len(data.Audit)-MaxAudit+1:]...)
	}
	data.Audit = append(data.Audit, Audit{ID: id, ReviewID: r.ID, UserID: r.UserID, Username: r.Username, SourceIP: r.SourceIP, RuleID: r.RuleID, Action: action, ActorID: actor, At: now})
	return nil
}
func expire(data *state, now time.Time) (bool, error) {
	changed := false
	for id, r := range data.Records {
		deadline := r.ExpiresAt
		if r.State == Approved && r.PermitExpiresAt != nil && r.PermitExpiresAt.Before(deadline) {
			deadline = *r.PermitExpiresAt
		}
		if live(r.State) && !now.Before(deadline) {
			r.State = Expired
			r.UpdatedAt = deadline
			r.Proof = ""
			data.Records[id] = r
			if e := audit(data, r, Expired, "system/login-review-expiry", now); e != nil {
				return false, e
			}
			changed = true
		}
		if !live(r.State) && now.Sub(r.UpdatedAt) > Retention {
			delete(data.Records, id)
			changed = true
		}
	}
	return changed, nil
}
func room(data *state) bool {
	if len(data.Records) < MaxRecords {
		return true
	}
	oldest := ""
	for id, r := range data.Records {
		if live(r.State) {
			continue
		}
		if oldest == "" || r.UpdatedAt.Before(data.Records[oldest].UpdatedAt) {
			oldest = id
		}
	}
	if oldest == "" {
		return false
	}
	delete(data.Records, oldest)
	return true
}
func payload(r record) Payload {
	return Payload{Review: clone(r.Review), Proof: r.Proof, Browser: r.Browser, Secure: r.Secure}
}
func (s *Store) rebuildTicketsLocked() {
	s.tickets = map[[32]byte]string{}
	for id, r := range s.data.Records {
		if len(r.TicketHash) == 32 {
			var hash [32]byte
			copy(hash[:], r.TicketHash)
			s.tickets[hash] = id
		}
	}
}
func (s *Store) mutate(fn func(*state, time.Time) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mutateLocked(fn)
}
func (s *Store) mutateLocked(fn func(*state, time.Time) error) error {
	next := clone(s.data)
	now := s.now().UTC()
	if _, e := expire(&next, now); e != nil {
		return e
	}
	if e := fn(&next, now); e != nil {
		return e
	}
	if e := s.persist(next); e != nil {
		return e
	}
	s.data = next
	s.rebuildTicketsLocked()
	return nil
}
func (s *Store) Begin(in Input) (Review, string, error) {
	var result Review
	var ticket string
	e := s.mutate(func(data *state, now time.Time) error {
		if in.Proof == "" || len(in.Proof) > 8192 || !now.Before(in.ExpiresAt) || in.ExpiresAt.After(now.Add(5*time.Minute)) || !room(data) {
			return ErrInvalid
		}
		pending, total := 0, 0
		for _, r := range data.Records {
			if live(r.State) {
				total++
				if r.UserID == in.UserID {
					pending++
				}
			}
		}
		if pending >= 5 || total >= MaxPending {
			return ErrCapacity
		}
		id, e := randomID("lrv-")
		if e != nil {
			return e
		}
		var raw [32]byte
		if _, e = rand.Read(raw[:]); e != nil {
			return e
		}
		ticket = base64.RawURLEncoding.EncodeToString(raw[:])
		hash := sha256.Sum256([]byte(ticket))
		r := record{Review: Review{ID: id, UserID: in.UserID, Username: in.Username, SourceIP: in.SourceIP, AuthSource: in.AuthSource, RuleID: in.RuleID, RuleName: in.RuleName, RuleRevision: in.RuleRevision, ApproverIDs: append([]string{}, in.ApproverIDs...), ApproverGroupIDs: append([]string{}, in.ApproverGroupIDs...), State: Pending, CreatedAt: now, UpdatedAt: now, ExpiresAt: in.ExpiresAt}, Proof: in.Proof, TicketHash: hash[:], Browser: in.Browser, Secure: in.Secure}
		if !validReview(r.Review) {
			return ErrInvalid
		}
		data.Records[id] = r
		if e = audit(data, r, Pending, in.UserID, now); e != nil {
			return e
		}
		result = clone(r.Review)
		return nil
	})
	if e != nil {
		return Review{}, "", e
	}
	return result, ticket, nil
}
func (s *Store) Notify(in Input) error {
	return s.mutate(func(data *state, now time.Time) error {
		if !room(data) {
			return ErrCapacity
		}
		id, e := randomID("lrv-")
		if e != nil {
			return e
		}
		r := record{Review: Review{ID: id, UserID: in.UserID, Username: in.Username, SourceIP: in.SourceIP, AuthSource: in.AuthSource, RuleID: in.RuleID, RuleName: in.RuleName, RuleRevision: in.RuleRevision, State: Notified, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(Retention), ApproverIDs: []string{}, ApproverGroupIDs: []string{}}}
		if !validReview(r.Review) {
			return ErrInvalid
		}
		data.Records[id] = r
		return audit(data, r, Notified, in.UserID, now)
	})
}
func (s *Store) refreshLocked() error {
	now := s.now().UTC()
	needed := false
	for _, r := range s.data.Records {
		deadline := r.ExpiresAt
		if r.State == Approved && r.PermitExpiresAt != nil && r.PermitExpiresAt.Before(deadline) {
			deadline = *r.PermitExpiresAt
		}
		if live(r.State) && !now.Before(deadline) || !live(r.State) && now.Sub(r.UpdatedAt) > Retention {
			needed = true
			break
		}
	}
	if !needed {
		return nil
	}
	next := clone(s.data)
	changed, e := expire(&next, s.now().UTC())
	if e != nil {
		return e
	}
	if changed {
		if e = s.persist(next); e != nil {
			return e
		}
		s.data = next
		s.rebuildTicketsLocked()
	}
	return nil
}
func (s *Store) Get(id string) (Review, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.refreshLocked(); e != nil {
		return Review{}, e
	}
	r, ok := s.data.Records[id]
	if !ok {
		return Review{}, ErrNotFound
	}
	return clone(r.Review), nil
}
func (s *Store) findTicket(data state, ticket, source string) (string, record, bool) {
	if len(ticket) != 43 {
		return "", record{}, false
	}
	hash := sha256.Sum256([]byte(ticket))
	id, known := s.tickets[hash]
	if !known {
		return "", record{}, false
	}
	r, ok := data.Records[id]
	if !ok || r.SourceIP != source || subtle.ConstantTimeCompare(hash[:], r.TicketHash) != 1 {
		return "", record{}, false
	}
	return id, r, true
}
func (s *Store) Status(ticket, source string) (Review, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, _, ok := s.findTicket(s.data, ticket, source); !ok {
		return Review{}, ErrNotFound
	}
	if e := s.refreshLocked(); e != nil {
		return Review{}, e
	}
	_, r, ok := s.findTicket(s.data, ticket, source)
	if !ok {
		return Review{}, ErrNotFound
	}
	return clone(r.Review), nil
}
func ReviewerAllowed(r Review, actor string, groups []string) bool {
	if actor == "" || actor == r.UserID {
		return false
	}
	if len(r.ApproverIDs) == 0 && len(r.ApproverGroupIDs) == 0 {
		return true
	}
	if slices.Contains(r.ApproverIDs, actor) {
		return true
	}
	for _, id := range groups {
		if slices.Contains(r.ApproverGroupIDs, id) {
			return true
		}
	}
	return false
}
func (s *Store) Resolve(id, actor string, groups []string, approve bool, check func(Payload) error) error {
	invalidated := false
	err := s.mutate(func(data *state, now time.Time) error {
		r, ok := data.Records[id]
		if !ok {
			return ErrNotFound
		}
		if r.State != Pending {
			return ErrState
		}
		if !ReviewerAllowed(r.Review, actor, groups) {
			return ErrReviewer
		}
		if approve {
			if check == nil {
				return ErrInvalid
			}
			if e := check(payload(r)); e != nil {
				if !errors.Is(e, ErrInvalidated) {
					return e
				}
				r.State = Invalidated
				r.Proof = ""
				invalidated = true
			} else {
				r.State = Approved
				deadline := now.Add(time.Minute)
				if r.ExpiresAt.Before(deadline) {
					deadline = r.ExpiresAt
				}
				r.PermitExpiresAt = &deadline
			}
		} else {
			r.State = Denied
			r.Proof = ""
		}
		r.ReviewedBy = actor
		r.ReviewedAt = &now
		r.UpdatedAt = now
		data.Records[id] = r
		return audit(data, r, r.State, actor, now)
	})
	if err == nil && invalidated {
		return ErrInvalidated
	}
	return err
}
func (s *Store) Cancel(ticket, source string, revoke ...func([]byte) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, _, ok := s.findTicket(s.data, ticket, source); !ok {
		return ErrNotFound
	}
	return s.mutateLocked(func(data *state, now time.Time) error {
		id, r, ok := s.findTicket(*data, ticket, source)
		if !ok {
			return ErrNotFound
		}
		if r.State == Consumed && now.Before(r.ExpiresAt) && len(r.CompletedSessionHash) == 32 && len(revoke) == 1 && revoke[0] != nil {
			if e := revoke[0](r.CompletedSessionHash); e != nil {
				return e
			}
		} else if !live(r.State) {
			return ErrState
		}
		r.State = Cancelled
		r.Proof = ""
		r.CompletedSessionHash = nil
		r.UpdatedAt = now
		data.Records[id] = r
		return audit(data, r, Cancelled, r.UserID, now)
	})
}
func (s *Store) Complete(ticket, source string, finish func(Payload) (coreauth.LoginSession, error), rollback func(string) error) (Completion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, _, known := s.findTicket(s.data, ticket, source); !known {
		return Completion{}, ErrNotFound
	}
	next := clone(s.data)
	now := s.now().UTC()
	if _, e := expire(&next, now); e != nil {
		return Completion{}, e
	}
	id, r, ok := s.findTicket(next, ticket, source)
	if !ok {
		return Completion{}, ErrNotFound
	}
	if r.State != Approved {
		return Completion{}, ErrState
	}
	if finish == nil || rollback == nil {
		return Completion{}, ErrInvalid
	}
	session, e := finish(payload(r))
	if e != nil {
		if errors.Is(e, ErrInvalidated) {
			r.State = Invalidated
			r.Proof = ""
			r.UpdatedAt = now
			next.Records[id] = r
			if auditError := audit(&next, r, Invalidated, r.UserID, now); auditError != nil {
				return Completion{}, auditError
			}
			if saveError := s.persist(next); saveError != nil {
				return Completion{}, saveError
			}
			s.data = next
			s.rebuildTicketsLocked()
		}
		return Completion{}, e
	}
	if session.AccessToken == "" || session.User.ID != r.UserID {
		if session.AccessToken != "" {
			_ = rollback(session.AccessToken)
		}
		return Completion{}, ErrInvalid
	}
	completedHash := sha256.Sum256([]byte(session.AccessToken))
	r.CompletedSessionHash = completedHash[:]
	r.State = Consumed
	r.Proof = ""
	r.UpdatedAt = now
	next.Records[id] = r
	if e = audit(&next, r, Consumed, r.UserID, now); e == nil {
		e = s.persist(next)
	}
	if e != nil {
		return Completion{}, errors.Join(e, rollback(session.AccessToken))
	}
	s.data = next
	s.rebuildTicketsLocked()
	return Completion{Session: session, Browser: r.Browser, Secure: r.Secure}, nil
}
func (s *Store) List(filter string, offset, limit int) ([]Review, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.refreshLocked(); e != nil {
		return nil, 0, e
	}
	items := []Review{}
	for _, r := range s.data.Records {
		if filter == "" || r.State == filter {
			items = append(items, clone(r.Review))
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].ID < items[j].ID
		}
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	total := len(items)
	offset = min(max(offset, 0), total)
	limit = min(max(limit, 1), 200)
	return items[offset:min(total, offset+limit)], total, nil
}
func (s *Store) Audit(offset, limit int) ([]Audit, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := len(s.data.Audit)
	result := []Audit{}
	for i := total - 1 - max(offset, 0); i >= 0 && len(result) < min(max(limit, 1), 200); i-- {
		result = append(result, s.data.Audit[i])
	}
	return clone(result), total
}
func (s *Store) persist(data state) error {
	plain, e := json.Marshal(data)
	if e != nil {
		return e
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	sealed := envelope{Version: 1, Nonce: nonce, Ciphertext: s.aead.Seal(nil, nonce, plain, []byte("jms233/platform-login-reviews/v1"))}
	raw, e := json.Marshal(sealed)
	if e != nil {
		return e
	}
	if s.documents != nil {
		return s.documents.Save("platform-login-reviews", raw)
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	file, e := os.CreateTemp(filepath.Dir(s.path), ".login-reviews-*.tmp")
	if e != nil {
		return e
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if e = file.Chmod(0600); e != nil {
		return e
	}
	if _, e = file.Write(raw); e != nil {
		return e
	}
	if e = file.Sync(); e != nil {
		return e
	}
	if e = file.Close(); e != nil {
		return e
	}
	return os.Rename(file.Name(), s.path)
}
