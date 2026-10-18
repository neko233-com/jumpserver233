// Package logintickets holds short-lived, browser-bound external login state.
// Only hashes are indexed; tickets do not survive restart or HA takeover.
package logintickets

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

var ErrTicket = errors.New("external login ticket invalid or expired")

type Ticket struct {
	UserID, SetupToken string
	CredentialID       string
	Revision, Attempts int
	AuthGeneration     int
	Expires            time.Time
}
type Store struct {
	mu      sync.Mutex
	pending map[[32]byte]Ticket
	now     func() time.Time
}

func New() *Store { return &Store{pending: map[[32]byte]Ticket{}, now: time.Now} }
func (s *Store) Issue(userID string, revision int, credentialID ...string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, p := range s.pending {
		if !s.now().Before(p.Expires) {
			delete(s.pending, k)
		}
	}
	if len(s.pending) >= 4096 {
		return "", ErrTicket
	}
	var raw [32]byte
	if _, e := rand.Read(raw[:]); e != nil {
		return "", e
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	id := ""
	if len(credentialID) > 1 {
		return "", ErrTicket
	}
	if len(credentialID) == 1 {
		id = credentialID[0]
	}
	if len(id) > 128 {
		return "", ErrTicket
	}
	s.pending[sha256.Sum256([]byte(token))] = Ticket{CredentialID: id, UserID: userID, Revision: revision, Expires: s.now().Add(5 * time.Minute)}
	return token, nil
}
func (s *Store) Read(token string, attempt bool) (Ticket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := sha256.Sum256([]byte(token))
	p, ok := s.pending[k]
	if !ok || len(token) > 128 || !s.now().Before(p.Expires) || p.Attempts >= 5 {
		delete(s.pending, k)
		return Ticket{}, ErrTicket
	}
	if attempt {
		p.Attempts++
		s.pending[k] = p
	}
	return p, nil
}
func (s *Store) SetSetup(token, setup string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := sha256.Sum256([]byte(token))
	p, ok := s.pending[k]
	if !ok || !s.now().Before(p.Expires) {
		return ErrTicket
	}
	p.SetupToken = setup
	s.pending[k] = p
	return nil
}

// BindGeneration is used before a verified primary ticket is given to a client.
func (s *Store) BindGeneration(token string, generation int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := sha256.Sum256([]byte(token))
	p, ok := s.pending[k]
	if !ok || generation < 0 || !s.now().Before(p.Expires) {
		return ErrTicket
	}
	p.AuthGeneration = generation
	s.pending[k] = p
	return nil
}
func (s *Store) Consume(token string) bool { _, ok := s.Take(token); return ok }
func (s *Store) Take(token string) (Ticket, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := sha256.Sum256([]byte(token))
	p, ok := s.pending[k]
	delete(s.pending, k)
	return p, ok && len(token) <= 128 && s.now().Before(p.Expires)
}
func (s *Store) Reset() { s.mu.Lock(); s.pending = map[[32]byte]Ticket{}; s.mu.Unlock() }
