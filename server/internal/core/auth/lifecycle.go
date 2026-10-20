package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrUserRevision      = errors.New("user revision changed")
	ErrUserState         = errors.New("invalid user lifecycle operation")
	ErrUserSelf          = errors.New("cannot change own security state through administration")
	ErrUserAdmin         = errors.New("administrator management requires role management permission")
	ErrLastAdministrator = errors.New("one enabled local administrator without expiry must remain")
)

type UserActor struct {
	ID, Name             string
	AuthGeneration       int
	ManageAdministrators bool
	ManageCredentials    bool
}
type UserUpdate struct {
	Revision    int        `json:"revision"`
	Name        *string    `json:"name,omitempty"`
	Comment     *string    `json:"comment,omitempty"`
	Role        *string    `json:"role,omitempty"`
	IsActive    *bool      `json:"is_active,omitempty"`
	DateExpired *time.Time `json:"date_expired,omitempty"`
	ClearExpiry bool       `json:"clear_date_expired,omitempty"`
}
type UserChange struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	UserUpdate
}
type ManagedUser struct {
	User
	IsActive               bool      `json:"is_active"`
	State                  string    `json:"state"`
	PasswordChangeRequired bool      `json:"password_change_required,omitempty"`
	PasswordExpiresAt      time.Time `json:"password_expires_at,omitzero"`
}
type UserEvent struct {
	ID             string    `json:"id"`
	At             time.Time `json:"at"`
	UserID         string    `json:"user_id"`
	Username       string    `json:"username"`
	ActorID        string    `json:"actor_id"`
	Actor          string    `json:"actor"`
	Action         string    `json:"action"`
	Revision       int       `json:"revision"`
	AuthGeneration int       `json:"auth_generation"`
	Fields         []string  `json:"fields"`
	Before         string    `json:"before"`
	After          string    `json:"after"`
}
type userEnvelope struct {
	Version        int                   `json:"version"`
	Users          []storedUser          `json:"users"`
	Audit          []UserEvent           `json:"audit"`
	PasswordPolicy *PasswordPolicy       `json:"password_policy,omitempty"`
	PasswordAudit  []PasswordPolicyEvent `json:"password_policy_audit,omitempty"`
	PasswordMarker []byte                `json:"password_history_marker,omitempty"`
}

func userRevision(u User) int { return max(1, u.Revision) }
func userUsable(u User, now time.Time) bool {
	return !u.Disabled && !u.SourceSuspended && u.ArchivedAt.IsZero() && (u.DateExpired.IsZero() || now.Before(u.DateExpired))
}
func userState(u User, now time.Time) string {
	switch {
	case !u.ArchivedAt.IsZero():
		return "archived"
	case u.Disabled || u.SourceSuspended:
		return "disabled"
	case !u.DateExpired.IsZero() && !now.Before(u.DateExpired):
		return "expired"
	default:
		return "active"
	}
}
func managedUser(u User, now time.Time) ManagedUser {
	u.Revision = userRevision(u)
	return ManagedUser{User: u, IsActive: userUsable(u, now), State: userState(u, now)}
}
func lifecycleValid(u User) bool {
	return u.Revision >= 0 && u.AuthGeneration >= 0 && len(u.Name) <= 128 && len(u.Comment) <= 2000 && utf8.ValidString(u.Name) && utf8.ValidString(u.Comment) && strings.IndexFunc(u.Name, unicode.IsControl) < 0 && strings.IndexFunc(u.Comment, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }) < 0 && (u.DateExpired.IsZero() || u.DateExpired.Year() >= 1970 && u.DateExpired.Year() <= 9999) && (u.ArchivedAt.IsZero() || u.ArchivedAt.Year() >= 1970 && u.ArchivedAt.Year() <= 9999)
}
func (s *Service) ManagedUsers(scope, query string, offset, limit int) ([]ManagedUser, int, error) {
	if !slices.Contains([]string{"current", "archived", "all"}, scope) || len(query) > 128 || offset < 0 || limit < 1 || limit > 100 {
		return nil, 0, ErrUserState
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []ManagedUser{}
	query = strings.ToLower(strings.TrimSpace(query))
	for _, r := range s.users {
		if scope == "current" && !r.ArchivedAt.IsZero() || scope == "archived" && r.ArchivedAt.IsZero() {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(r.Username+" "+r.Name), query) {
			continue
		}
		out = append(out, s.managedPasswordUserLocked(r))
	}
	slices.SortFunc(out, func(a, b ManagedUser) int { return strings.Compare(a.Username, b.Username) })
	total := len(out)
	offset = min(offset, total)
	return out[offset:min(offset+limit, total)], total, nil
}
func (s *Service) ManagedUser(id string) (ManagedUser, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, r, ok := s.storedUserByIDLocked(id)
	if !ok {
		return ManagedUser{}, ErrUserNotFound
	}
	return s.managedPasswordUserLocked(r), nil
}
func (s *Service) UserAudit(user string, offset, limit int) ([]UserEvent, int, error) {
	if offset < 0 || limit < 1 || limit > 100 || len(user) > 128 {
		return nil, 0, ErrUserState
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []UserEvent{}
	for i := len(s.userEvents) - 1; i >= 0; i-- {
		e := s.userEvents[i]
		if user == "" || e.UserID == user {
			e.Fields = slices.Clone(e.Fields)
			out = append(out, e)
		}
	}
	total := len(out)
	offset = min(offset, total)
	return out[offset:min(offset+limit, total)], total, nil
}

// Changes, credential revocation and metadata-only audit commit in one user document.
// Old session documents cannot revive credentials after a failed cleanup write.
func (s *Service) ChangeUsers(changes []UserChange, actor UserActor) ([]ManagedUser, error) {
	if len(changes) < 1 || len(changes) > 100 {
		return nil, ErrUserState
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	if actor.ID != "admin-token" {
		_, u, ok := s.storedUserByIDLocked(actor.ID)
		if !ok || !s.externalAllowedLocked(u) || u.AuthGeneration != actor.AuthGeneration {
			return nil, ErrInvalidCredentials
		}
	}
	old := s.users
	next := make(map[string]storedUser, len(old))
	for name, r := range old {
		next[name] = r
	}
	events := slices.Clone(s.userEvents)
	out := make([]ManagedUser, 0, len(changes))
	seen := map[string]bool{}
	for _, in := range changes {
		if seen[in.ID] {
			return nil, ErrUserState
		}
		seen[in.ID] = true
		name := ""
		var r storedUser
		for n, v := range next {
			if v.ID == in.ID {
				name = n
				r = v
				break
			}
		}
		if name == "" {
			return nil, ErrUserNotFound
		}
		if in.Revision != userRevision(r.User) {
			return nil, ErrUserRevision
		}
		before := userState(r.User, now)
		previous := r
		fields := []string{}
		security := false
		switch in.Action {
		case "update":
			if !r.ArchivedAt.IsZero() {
				return nil, ErrUserState
			}
			if in.Name != nil {
				r.Name = *in.Name
				fields = append(fields, "name")
			}
			if in.Comment != nil {
				r.Comment = *in.Comment
				fields = append(fields, "comment")
			}
			if in.Role != nil {
				if *in.Role != RoleAdmin && *in.Role != RoleOperator {
					return nil, ErrInvalidRole
				}
				if r.Source != "" && *in.Role != RoleOperator {
					return nil, ErrExternalIdentity
				}
				security = security || r.Role != *in.Role
				r.Role = *in.Role
				fields = append(fields, "role")
			}
			if in.IsActive != nil {
				security = security || r.Disabled == *in.IsActive
				r.Disabled = !*in.IsActive
				fields = append(fields, "is_active")
			}
			if in.DateExpired != nil && in.ClearExpiry {
				return nil, ErrUserState
			}
			if in.DateExpired != nil {
				date := in.DateExpired.UTC()
				security = security || !r.DateExpired.Equal(date)
				r.DateExpired = date
				fields = append(fields, "date_expired")
			}
			if in.ClearExpiry {
				security = security || !r.DateExpired.IsZero()
				r.DateExpired = time.Time{}
				fields = append(fields, "date_expired")
			}
			if len(fields) == 0 {
				return nil, ErrUserState
			}
		case "archive":
			if !r.ArchivedAt.IsZero() {
				return nil, ErrUserState
			}
			r.ArchivedAt = now
			r.Disabled = true
			security = true
			fields = append(fields, "archived")
		case "restore":
			if r.ArchivedAt.IsZero() {
				return nil, ErrUserState
			}
			r.ArchivedAt = time.Time{}
			r.Disabled = true
			security = true
			fields = append(fields, "restored")
		case "revoke":
			if !r.ArchivedAt.IsZero() {
				return nil, ErrUserState
			}
			security = true
			fields = append(fields, "credentials")
		default:
			return nil, ErrUserState
		}
		if in.Action != "update" && (in.Name != nil || in.Comment != nil || in.Role != nil || in.IsActive != nil || in.DateExpired != nil || in.ClearExpiry) {
			return nil, ErrUserState
		}
		if (previous.Role == RoleAdmin || r.Role == RoleAdmin) && !actor.ManageAdministrators {
			return nil, ErrUserAdmin
		}
		if security && r.ID == actor.ID {
			return nil, ErrUserSelf
		}
		r.Revision = userRevision(previous.User) + 1
		if security {
			clearUserCapabilities(&r)
		}

		if !lifecycleValid(r.User) {
			return nil, ErrUserState
		}
		next[name] = r
		var id [16]byte
		if _, e := rand.Read(id[:]); e != nil {
			return nil, e
		}
		events = append(events, UserEvent{ID: "user-event-" + hex.EncodeToString(id[:]), At: now, UserID: r.ID, Username: r.Username, ActorID: actor.ID, Actor: actor.Name, Action: in.Action, Revision: r.Revision, AuthGeneration: r.AuthGeneration, Fields: fields, Before: before, After: userState(r.User, now)})
		out = append(out, managedUser(r.User, now))
	}
	permanent := false
	for _, r := range next {
		if r.Role == RoleAdmin && r.Source == "" && !r.Disabled && r.ArchivedAt.IsZero() && r.DateExpired.IsZero() {
			permanent = true
			break
		}
	}
	if !permanent {
		return nil, ErrLastAdministrator
	}
	events = slices.DeleteFunc(events, func(e UserEvent) bool { return e.At.Before(now.AddDate(0, -6, 0)) })
	if len(events) > 5000 {
		events = events[len(events)-5000:]
	}
	oldEvents := s.userEvents
	s.users = next
	s.userEvents = events
	if e := s.persistLocked(); e != nil {
		s.users = old
		s.userEvents = oldEvents
		return nil, e
	}
	changed := map[string]User{}
	for _, row := range out {
		changed[row.ID] = row.User
	}
	for hash, session := range s.sessions {
		if r, ok := changed[session.user.ID]; ok && r.AuthGeneration != session.user.AuthGeneration {
			delete(s.sessions, hash)
		}
	}
	_ = s.persistSessionsLocked()
	return out, nil
}
func (s *Service) ActiveUserSnapshot(user User) (User, bool) {
	current, ok := s.ActiveUserByID(user.ID)
	return current, ok && current.AuthGeneration == user.AuthGeneration
}
func (s *Service) marshalUsersLocked(users []storedUser) ([]byte, error) {
	return json.Marshal(userEnvelope{Version: 4, Users: users, Audit: s.userEvents, PasswordPolicy: &s.passwordPolicy, PasswordAudit: s.passwordPolicyEvents, PasswordMarker: s.passwordStoreMarker()})
}
func validUserEvents(events []UserEvent) bool {
	seen := map[string]bool{}
	for _, e := range events {
		if e.ID == "" || seen[e.ID] || e.At.IsZero() || e.UserID == "" || e.Username == "" || e.ActorID == "" || e.Revision < 2 || e.AuthGeneration < 0 || !slices.Contains([]string{"update", "archive", "restore", "revoke", "password_change", "password_reset", "mfa_reset"}, e.Action) || len(e.Fields) < 1 || len(e.Fields) > 6 {
			return false
		}
		seen[e.ID] = true
		for _, f := range e.Fields {
			if !slices.Contains([]string{"name", "comment", "role", "is_active", "date_expired", "archived", "restored", "credentials", "password", "password_reset_required", "mfa"}, f) {
				return false
			}
		}
		for _, state := range []string{e.Before, e.After} {
			if !slices.Contains([]string{"active", "disabled", "expired", "archived"}, state) {
				return false
			}
		}
	}
	return true
}
