// Package sessionshares manages process-local invitations and participant authority.
// Live sessions do not migrate on takeover; invitations consequently do not either.
package sessionshares

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalid  = errors.New("invalid session share")
	ErrDenied   = errors.New("session share unavailable")
	ErrCapacity = errors.New("session share capacity reached")
	ErrAudit    = errors.New("session share audit unavailable")
)

const (
	ReadOnly          = "read_only"
	ReadWrite         = "read_write"
	maxShares         = 128
	maxSessionShares  = 8
	maxMembers        = 64
	maxSessionMembers = 8
)

type Actor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type Input struct {
	Authorize    func() error `json:"-"` // live owner authority; must not re-enter this store
	SessionID    string       `json:"session_id"`
	Mode         string       `json:"mode"`
	Minutes      int          `json:"minutes"`
	AllowedUsers []string     `json:"allowed_users"`
}
type Share struct {
	ID           string    `json:"id"`
	SessionID    string    `json:"session_id"`
	Owner        Actor     `json:"owner"`
	Mode         string    `json:"mode"`
	AllowedUsers []string  `json:"allowed_users"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}
type Created struct {
	Share
	Code string `json:"code"` // returned only by Create; never retained or audited
}
type Member struct {
	ID        string    `json:"id"`
	ShareID   string    `json:"share_id"`
	SessionID string    `json:"session_id"`
	Actor     Actor     `json:"actor"`
	Mode      string    `json:"mode"`
	JoinedAt  time.Time `json:"joined_at"`
}
type Event struct {
	Kind         string    `json:"event"`
	SessionID    string    `json:"session_id"`
	ShareID      string    `json:"share_id,omitempty"`
	MemberID     string    `json:"member_id,omitempty"`
	Actor        Actor     `json:"actor"`
	Mode         string    `json:"mode,omitempty"`
	AllowedUsers []string  `json:"allowed_users,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	At           time.Time `json:"at"`
}
type invitation struct {
	authorize    func() error
	share        Share
	codeHash     [32]byte
	failures     int
	blockedUntil time.Time
}
type Store struct {
	mu          sync.Mutex
	now         func() time.Time
	audit       func(Event) error
	shares      map[string]*invitation
	members     map[string]Member
	controllers map[string]controller
}

type controller struct {
	memberID, shareID string
	owner             Actor
}

func New(audit func(Event) error) *Store {
	return &Store{now: time.Now, audit: audit, shares: map[string]*invitation{}, members: map[string]Member{}, controllers: map[string]controller{}}
}
func token(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func validText(s string) bool {
	return s != "" && s == strings.TrimSpace(s) && len(s) <= 128 && !strings.ContainsAny(s, "\r\n\x00")
}
func validActor(a Actor) bool { return validText(a.ID) && validText(a.Name) }
func (s *Store) record(event Event) error {
	if s.audit == nil {
		return ErrAudit
	}
	event.At = s.now().UTC()
	event.AllowedUsers = append([]string(nil), event.AllowedUsers...)
	if err := s.audit(event); err != nil {
		return errors.Join(ErrAudit, err)
	}
	return nil
}
func clone(v Share) Share { v.AllowedUsers = append([]string{}, v.AllowedUsers...); return v }
func (s *Store) prune() {
	now := s.now()
	for id, invite := range s.shares {
		if !now.Before(invite.share.ExpiresAt) {
			s.remove(id)
		}
	}
}
func (s *Store) remove(id string) {
	delete(s.shares, id)
	for mid, member := range s.members {
		if member.ShareID == id {
			s.removeMember(mid)
		}
	}
}
func (s *Store) removeMember(id string) {
	delete(s.members, id)
	// A disconnected writer stays gated until another writer explicitly takes
	// control; the existing terminal input remains visible to that next writer.
}

func (s *Store) Create(in Input, owner Actor) (Created, error) {
	if !validActor(owner) || !validText(in.SessionID) || (in.Mode != ReadOnly && in.Mode != ReadWrite) || in.Minutes < 1 || in.Minutes > 1440 || len(in.AllowedUsers) < 1 || len(in.AllowedUsers) > 20 {
		return Created{}, ErrInvalid
	}
	users := append([]string{}, in.AllowedUsers...)
	for _, id := range users {
		if !validText(id) || id == owner.ID {
			return Created{}, ErrInvalid
		}
	}
	slices.Sort(users)
	users = slices.Compact(users)
	id, err := token(18)
	if err != nil {
		return Created{}, err
	}
	code, err := token(12)
	if err != nil {
		return Created{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	if in.Authorize != nil && in.Authorize() != nil {
		return Created{}, ErrDenied
	}
	count := 0
	for _, v := range s.shares {
		if v.share.SessionID == in.SessionID {
			count++
		}
	}
	if len(s.shares) >= maxShares || count >= maxSessionShares {
		return Created{}, ErrCapacity
	}
	now := s.now().UTC()
	v := Share{ID: id, SessionID: in.SessionID, Owner: owner, Mode: in.Mode, AllowedUsers: users, CreatedAt: now, ExpiresAt: now.Add(time.Duration(in.Minutes) * time.Minute)}
	if err = s.record(Event{Kind: "share_created", SessionID: v.SessionID, ShareID: id, Actor: owner, Mode: v.Mode, AllowedUsers: users, ExpiresAt: v.ExpiresAt}); err != nil {
		return Created{}, err
	}
	s.shares[id] = &invitation{share: v, codeHash: sha256.Sum256([]byte(id + ":" + code)), authorize: in.Authorize}
	return Created{Share: clone(v), Code: code}, nil
}

func (s *Store) List(sessionID, ownerID string) []Share {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	out := []Share{}
	for _, v := range s.shares {
		if v.share.SessionID == sessionID && v.share.Owner.ID == ownerID {
			out = append(out, clone(v.share))
		}
	}
	slices.SortFunc(out, func(a, b Share) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out
}
func (s *Store) Join(id, code string, actor Actor) (Member, error) {
	if !validActor(actor) || len(id) > 128 || len(code) > 128 {
		return Member{}, ErrDenied
	}
	mid, err := token(18)
	if err != nil {
		return Member{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	i := s.shares[id]
	if i == nil || i.authorize != nil && i.authorize() != nil || !slices.Contains(i.share.AllowedUsers, actor.ID) || s.now().Before(i.blockedUntil) {
		return Member{}, ErrDenied
	}
	hash := sha256.Sum256([]byte(id + ":" + code))
	if subtle.ConstantTimeCompare(hash[:], i.codeHash[:]) != 1 {
		i.failures++
		if i.failures >= 5 {
			i.failures = 0
			i.blockedUntil = s.now().Add(time.Minute)
		}
		return Member{}, ErrDenied
	}
	count := 0
	for _, v := range s.members {
		if v.SessionID == i.share.SessionID {
			count++
		}
	}
	if len(s.members) >= maxMembers || count >= maxSessionMembers {
		return Member{}, ErrCapacity
	}
	m := Member{ID: mid, ShareID: id, SessionID: i.share.SessionID, Actor: actor, Mode: i.share.Mode, JoinedAt: s.now().UTC()}
	if err = s.record(Event{Kind: "share_joined", SessionID: m.SessionID, ShareID: id, MemberID: mid, Actor: actor, Mode: m.Mode}); err != nil {
		return Member{}, err
	}
	i.failures = 0
	s.members[mid] = m
	return m, nil
}
func (s *Store) Member(id, actorID string) (Member, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	m, ok := s.members[id]
	if !ok || m.Actor.ID != actorID || s.shares[m.ShareID].authorize != nil && s.shares[m.ShareID].authorize() != nil {
		return Member{}, ErrDenied
	}
	return m, nil
}
func (s *Store) Members(sessionID, ownerID string) []Member {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	out := []Member{}
	for _, m := range s.members {
		if m.SessionID == sessionID && s.shares[m.ShareID].share.Owner.ID == ownerID {
			out = append(out, m)
		}
	}
	slices.SortFunc(out, func(a, b Member) int { return a.JoinedAt.Compare(b.JoinedAt) })
	return out
}

// TakeControl must run while the gateway serializes complete PTY input frames.
// The durable control event identifies who may submit subsequent commands.
func (s *Store) TakeControl(memberID, actorID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	m, ok := s.members[memberID]
	if !ok || m.Actor.ID != actorID || m.Mode != ReadWrite || s.shares[m.ShareID].authorize != nil && s.shares[m.ShareID].authorize() != nil {
		return ErrDenied
	}
	if s.controllers[m.SessionID].memberID == memberID {
		return nil
	}
	if _, exists := s.controllers[m.SessionID]; !exists && len(s.controllers) >= maxShares {
		return ErrCapacity
	}
	if err := s.record(Event{Kind: "share_control_taken", SessionID: m.SessionID, ShareID: m.ShareID, MemberID: memberID, Actor: m.Actor}); err != nil {
		return err
	}
	s.controllers[m.SessionID] = controller{memberID: memberID, shareID: m.ShareID, owner: s.shares[m.ShareID].share.Owner}
	return nil
}
func (s *Store) Reclaim(sessionID string, owner Actor) error {
	if !validActor(owner) {
		return ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	control := s.controllers[sessionID]
	if control.memberID == "" {
		return nil
	}
	if control.owner.ID != owner.ID {
		return ErrDenied
	}
	if err := s.record(Event{Kind: "share_control_reclaimed", SessionID: sessionID, ShareID: control.shareID, Actor: owner}); err != nil {
		return err
	}
	delete(s.controllers, sessionID)
	return nil
}
func (s *Store) Controller(sessionID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	return s.controllers[sessionID].memberID
}
func (s *Store) Leave(memberID, actorID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	m, ok := s.members[memberID]
	if !ok || m.Actor.ID != actorID {
		return ErrDenied
	}
	defer s.removeMember(memberID) // revocation stays effective even when auditing fails
	return s.record(Event{Kind: "share_left", SessionID: m.SessionID, ShareID: m.ShareID, MemberID: memberID, Actor: m.Actor})
}
func (s *Store) Kick(memberID string, owner Actor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	m, ok := s.members[memberID]
	if !ok || !validActor(owner) || s.shares[m.ShareID].share.Owner.ID != owner.ID {
		return ErrDenied
	}
	defer s.removeMember(memberID)
	return s.record(Event{Kind: "share_kicked", SessionID: m.SessionID, ShareID: m.ShareID, MemberID: memberID, Actor: owner})
}
func (s *Store) Revoke(id string, owner Actor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	i := s.shares[id]
	if i == nil || !validActor(owner) || i.share.Owner.ID != owner.ID {
		return ErrDenied
	}
	defer s.remove(id)
	return s.record(Event{Kind: "share_revoked", SessionID: i.share.SessionID, ShareID: id, Actor: owner})
}
func (s *Store) CloseSession(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, v := range s.shares {
		if v.share.SessionID == sessionID {
			s.remove(id)
		}
	}
	delete(s.controllers, sessionID)
}
