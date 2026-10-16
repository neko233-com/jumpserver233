// Package organizations owns organization identities, membership and their
// revisioned audit. Resource stores are opened separately for each organization.
package organizations

import (
	"crypto/rand"
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

	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

// DefaultID matches JumpServer's default organization. GLOBAL is a virtual
// administration scope upstream; it must never silently select resource data.
const DefaultID = "00000000-0000-0000-0000-000000000002"
const MaxOrganizations = 100

var (
	ErrInvalid   = errors.New("invalid organization or membership")
	ErrNotFound  = errors.New("organization not found")
	ErrConflict  = errors.New("organization revision or name conflicts")
	ErrProtected = errors.New("default organization is protected")
	ErrCapacity  = errors.New("organization capacity reached")
)

type Input struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Revision    int    `json:"revision"`
}
type Organization struct {
	ID string `json:"id"`
	Input
	Builtin    bool       `json:"builtin"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	ArchivedAt *time.Time `json:"archived_at,omitempty"`
}

// role=none is a durable exclusion, including from implicit default membership.
type MemberInput struct {
	UserID   string `json:"user_id"`
	Role     string `json:"role"`
	Revision int    `json:"revision"`
}
type Member struct {
	MemberInput
	UpdatedAt time.Time `json:"updated_at"`
}
type Audit struct {
	ID             string          `json:"id"`
	OrganizationID string          `json:"organization_id"`
	At             time.Time       `json:"at"`
	ActorID        string          `json:"actor_id"`
	Action         string          `json:"action"`
	UserID         string          `json:"user_id,omitempty"`
	Before         json.RawMessage `json:"before,omitempty"`
	After          json.RawMessage `json:"after,omitempty"`
}
type state struct {
	Organizations map[string]Organization      `json:"organizations"`
	Members       map[string]map[string]Member `json:"members"`
	Audit         []Audit                      `json:"audit"`
}
type Store struct {
	mu        sync.RWMutex
	path      string
	documents *storage.Documents
	data      state
}

func ValidID(id string) bool {
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' || strings.ToLower(id) != id {
		return false
	}
	raw, e := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	if e != nil || len(raw) != 16 {
		return false
	}
	return id != "00000000-0000-0000-0000-000000000000" && id != "00000000-0000-0000-0000-000000000004"
}
func validText(v string, n int) bool {
	return len(v) <= n && strings.IndexFunc(v, unicode.IsControl) < 0
}
func validInput(in Input) bool {
	return in.Name != "" && strings.TrimSpace(in.Name) == in.Name && validText(in.Name, 128) && validText(in.Description, 500) && in.Revision >= 0 && in.Revision <= 1_000_000_000
}
func validMember(in MemberInput) bool {
	return in.UserID != "" && validText(in.UserID, 128) && strings.TrimSpace(in.UserID) == in.UserID && slices.Contains([]string{"admin", "auditor", "member", "none"}, in.Role) && in.Revision >= 0 && in.Revision <= 1_000_000_000
}
func Open(path string, documents *storage.Documents) (*Store, error) {
	s := &Store{path: path, documents: documents, data: state{Organizations: map[string]Organization{}, Members: map[string]map[string]Member{}, Audit: []Audit{}}}
	var raw []byte
	var e error
	if documents != nil {
		raw, e = documents.LoadOrImport("organizations", path)
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
		if json.Unmarshal(raw, &s.data) != nil || s.data.Organizations == nil || s.data.Members == nil || len(s.data.Organizations) > MaxOrganizations || len(s.data.Audit) > 10000 {
			return nil, ErrInvalid
		}
		for id, o := range s.data.Organizations {
			if !ValidID(id) || id != o.ID || !validInput(o.Input) || o.Revision < 1 || o.CreatedAt.IsZero() || o.UpdatedAt.Before(o.CreatedAt) || o.Builtin != (id == DefaultID) {
				return nil, ErrInvalid
			}
			if o.Builtin && (!o.Enabled || o.ArchivedAt != nil) {
				return nil, ErrInvalid
			}
		}
		for id, members := range s.data.Members {
			if _, ok := s.data.Organizations[id]; !ok || len(members) > 10000 {
				return nil, ErrInvalid
			}
			for user, m := range members {
				if user != m.UserID || !validMember(m.MemberInput) || m.Revision < 1 || m.UpdatedAt.IsZero() {
					return nil, ErrInvalid
				}
			}
		}
		for _, a := range s.data.Audit {
			if !ValidID(a.OrganizationID) || a.ActorID == "" || a.ID == "" || a.At.IsZero() {
				return nil, ErrInvalid
			}
		}
	}
	if _, ok := s.data.Organizations[DefaultID]; !ok {
		if len(raw) > 0 {
			return nil, ErrInvalid
		}
		now := time.Now().UTC()
		s.data.Organizations[DefaultID] = Organization{ID: DefaultID, Input: Input{Name: "Default", Enabled: true, Revision: 1}, Builtin: true, CreatedAt: now, UpdatedAt: now}
		if e = s.persist(s.data); e != nil {
			return nil, e
		}
	}
	return s, nil
}
func clone[T any](in T) T {
	raw, _ := json.Marshal(in)
	var out T
	_ = json.Unmarshal(raw, &out)
	return out
}
func newID() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}
func (s *Store) mutate(org, actor, action, user string, fn func(*state, time.Time) (any, any, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if actor == "" || !validText(actor, 128) {
		return ErrInvalid
	}
	next := clone(s.data)
	now := time.Now().UTC()
	before, after, e := fn(&next, now)
	if e != nil {
		return e
	}
	id, e := newID()
	if e != nil {
		return e
	}
	a := Audit{ID: id, OrganizationID: org, ActorID: actor, Action: action, UserID: user, At: now}
	if before != nil {
		a.Before, _ = json.Marshal(before)
	}
	if after != nil {
		a.After, _ = json.Marshal(after)
	}
	if len(next.Audit) >= 10000 {
		next.Audit = append([]Audit{}, next.Audit[len(next.Audit)-9999:]...)
	}
	next.Audit = append(next.Audit, a)
	if e = s.persist(next); e != nil {
		return e
	}
	s.data = next
	return nil
}
func (s *Store) Save(id string, in Input, actor string) (Organization, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Description = strings.TrimSpace(in.Description)
	if !validInput(in) {
		return Organization{}, ErrInvalid
	}
	creating := id == ""
	var e error
	if creating {
		id, e = newID()
		if e != nil {
			return Organization{}, e
		}
	} else if !ValidID(id) {
		return Organization{}, ErrInvalid
	}
	var out Organization
	e = s.mutate(id, actor, "organization.save", "", func(data *state, now time.Time) (any, any, error) {
		old, exists := data.Organizations[id]
		if creating && in.Revision != 0 || !creating && (!exists || old.ArchivedAt != nil) {
			return nil, nil, ErrNotFound
		}
		if exists && (old.Revision != in.Revision || old.Revision >= 1_000_000_000) {
			return nil, nil, ErrConflict
		}
		if creating && len(data.Organizations) >= MaxOrganizations {
			return nil, nil, ErrCapacity
		}
		if id == DefaultID && !in.Enabled {
			return nil, nil, ErrProtected
		}
		for other, o := range data.Organizations {
			if other != id && strings.EqualFold(o.Name, in.Name) {
				return nil, nil, ErrConflict
			}
		}
		in.Revision++
		out = Organization{ID: id, Input: in, Builtin: id == DefaultID, CreatedAt: old.CreatedAt, UpdatedAt: now}
		if creating {
			out.CreatedAt = now
		}
		data.Organizations[id] = out
		if !exists {
			return nil, out, nil
		}
		return old, out, nil
	})
	return clone(out), e
}
func (s *Store) Archive(id string, revision int, restore bool, actor string) error {
	if id == DefaultID {
		return ErrProtected
	}
	return s.mutate(id, actor, map[bool]string{true: "organization.restore", false: "organization.archive"}[restore], "", func(data *state, now time.Time) (any, any, error) {
		old, ok := data.Organizations[id]
		if !ok {
			return nil, nil, ErrNotFound
		}
		if old.Revision != revision || old.Revision >= 1_000_000_000 {
			return nil, nil, ErrConflict
		}
		if (old.ArchivedAt == nil) == restore {
			return nil, nil, ErrConflict
		}
		out := old
		out.Revision++
		out.UpdatedAt = now
		out.Enabled = false
		if restore {
			out.ArchivedAt = nil
		} else {
			out.ArchivedAt = &now
		}
		data.Organizations[id] = out
		return old, out, nil
	})
}
func (s *Store) Get(id string) (Organization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.data.Organizations[id]
	if !ok {
		return Organization{}, ErrNotFound
	}
	return clone(o), nil
}
func (s *Store) List(archived bool) []Organization {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Organization{}
	for _, o := range s.data.Organizations {
		if archived || o.ArchivedAt == nil {
			out = append(out, clone(o))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Builtin != out[j].Builtin {
			return out[i].Builtin
		}
		return out[i].Name < out[j].Name
	})
	return out
}
func (s *Store) Role(org, user string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.data.Organizations[org]
	if !ok || !o.Enabled || o.ArchivedAt != nil {
		return "none"
	}
	if m, ok := s.data.Members[org][user]; ok {
		return m.Role
	}
	if org == DefaultID {
		return "member"
	}
	return "none"
}
func (s *Store) Enabled(org string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.data.Organizations[org]
	return ok && o.Enabled && o.ArchivedAt == nil
}
func (s *Store) Member(org, user string) (Member, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.data.Members[org][user]
	return m, ok
}
func (s *Store) Members(org string) []Member {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Member{}
	for _, m := range s.data.Members[org] {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UserID < out[j].UserID })
	return out
}
func (s *Store) SaveMember(org string, in MemberInput, actor string) (Member, error) {
	if !validMember(in) {
		return Member{}, ErrInvalid
	}
	var out Member
	e := s.mutate(org, actor, "member.save", in.UserID, func(data *state, now time.Time) (any, any, error) {
		o, ok := data.Organizations[org]
		if !ok || o.ArchivedAt != nil {
			return nil, nil, ErrNotFound
		}
		old, exists := data.Members[org][in.UserID]
		if old.Revision != in.Revision || old.Revision >= 1_000_000_000 {
			return nil, nil, ErrConflict
		}
		if !exists && len(data.Members[org]) >= 10000 {
			return nil, nil, ErrCapacity
		}
		in.Revision++
		out = Member{MemberInput: in, UpdatedAt: now}
		if data.Members[org] == nil {
			data.Members[org] = map[string]Member{}
		}
		data.Members[org][in.UserID] = out
		if !exists {
			return nil, out, nil
		}
		return old, out, nil
	})
	return out, e
}
func (s *Store) Audit(org string, offset, limit int) ([]Audit, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Audit{}
	for i := len(s.data.Audit) - 1; i >= 0; i-- {
		a := s.data.Audit[i]
		if org == "" || a.OrganizationID == org {
			out = append(out, clone(a))
		}
	}
	total := len(out)
	offset = min(max(offset, 0), total)
	return out[offset:min(total, offset+min(max(limit, 1), 200))], total
}
func (s *Store) persist(data state) error {
	raw, e := json.Marshal(data)
	if e != nil {
		return e
	}
	if s.documents != nil {
		return s.documents.Save("organizations", raw)
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".organizations-*.tmp")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if e = f.Chmod(0600); e != nil {
		return e
	}
	if _, e = f.Write(raw); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), s.path)
}
