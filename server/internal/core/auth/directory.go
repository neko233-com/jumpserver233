package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"github.com/neko233-com/jumpserver233/server/internal/core/identityscope"
	"strings"
)

// EnsureNamedDirectoryUsers persists an entire bounded batch once. A stable
// subject creates an operator identity; directory display names never link users.
func (s *Service) EnsureNamedDirectoryUsers(sourceID, issuer string, subjects []string) (map[string]User, error) {
	if !identityscope.ValidID(sourceID) || issuer == "" || len(issuer) > 2048 || len(subjects) > 10000 {
		return nil, ErrInvalidCredentials
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.users) == 0 {
		return nil, ErrBootstrapRequired
	}
	existing := map[string]storedUser{}
	for _, r := range s.users {
		if r.Source == "ldap" && r.SourceID == sourceID && r.ExternalIssuer == issuer {
			existing[r.ExternalIdentity] = r
		}
	}
	previous := s.users
	next := make(map[string]storedUser, len(previous))
	for name, r := range previous {
		next[name] = r
	}
	out := map[string]User{}
	changed := false
	for _, subject := range subjects {
		if subject == "" || len(subject) > 1024 || strings.ContainsRune(subject, 0) {
			return nil, ErrInvalidCredentials
		}
		if _, exists := out[subject]; exists {
			return nil, ErrInvalidCredentials
		}
		sum := sha256.Sum256([]byte(sourceID + "\x00" + issuer + "\x00" + subject))
		identity := hex.EncodeToString(sum[:])
		if r, ok := existing[identity]; ok {
			out[subject] = r.User
			continue
		}
		if len(next) >= 10000 {
			return nil, ErrAuthenticationBusy
		}
		name := "ldap." + identity[:32]
		if _, exists := next[name]; exists {
			return nil, ErrUserExists
		}
		var id, salt [16]byte
		var inert [32]byte
		for _, b := range [][]byte{id[:], salt[:], inert[:]} {
			if _, e := rand.Read(b); e != nil {
				return nil, e
			}
		}
		user := User{Revision: 1, ID: "user-" + hex.EncodeToString(id[:]), Username: name, Role: RoleOperator, Source: "ldap", SourceID: sourceID, CreatedAt: s.now().UTC()}
		next[name] = storedUser{User: user, ExternalIssuer: issuer, ExternalIdentity: identity, PasswordSalt: salt[:], PasswordHash: inert[:]}
		out[subject] = user
		changed = true
	}
	if changed {
		s.users = next
		if e := s.persistLocked(); e != nil {
			s.users = previous
			return nil, e
		}
	}
	return out, nil
}

// Directory suspension is independent of an administrator's disabled/archive
// state. Reappearing entries cannot undo a manual restriction.
func (s *Service) SetNamedDirectorySuspensions(sourceID string, users map[string]bool) error {
	if !identityscope.ValidID(sourceID) || len(users) > 10000 {
		return ErrInvalidCredentials
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := s.users
	next := make(map[string]storedUser, len(previous))
	found := 0
	changed := false
	for name, r := range previous {
		if suspended, ok := users[r.ID]; ok {
			if r.Source != "ldap" || r.SourceID != sourceID {
				return ErrInvalidCredentials
			}
			found++
			if r.SourceSuspended != suspended {
				r.SourceSuspended = suspended
				r.Revision++
				clearUserCapabilities(&r)
				changed = true
			}
		}
		next[name] = r
	}
	if found != len(users) {
		return ErrUserNotFound
	}
	if !changed {
		return nil
	}
	s.users = next
	if e := s.persistLocked(); e != nil {
		s.users = previous
		return e
	}
	return nil
}
func (s *Service) NamedDirectoryUsers(sourceID string) []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []User{}
	for _, r := range s.users {
		if r.Source == "ldap" && r.SourceID == sourceID {
			out = append(out, r.User)
		}
	}
	return out
}

func (s *Service) SuspendNamedDirectorySource(sourceID string) error {
	if !identityscope.ValidID(sourceID) {
		return ErrInvalidCredentials
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := s.users
	next := make(map[string]storedUser, len(previous))
	changed := false
	for name, r := range previous {
		if r.Source == "ldap" && r.SourceID == sourceID {
			r.SourceSuspended = true
			r.Revision++
			clearUserCapabilities(&r)
			changed = true
		}
		next[name] = r
	}
	if !changed {
		return nil
	}
	s.users = next
	if e := s.persistLocked(); e != nil {
		s.users = previous
		return e
	}
	return nil
}
