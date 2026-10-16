package files

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

const (
	SFTPAccessSessionLifetime = 30 * time.Minute
	maxSFTPAccessSessions     = 10000
)

var (
	ErrInvalidAccessSession = errors.New("invalid SFTP access session")
	ErrAccessSessionLimit   = errors.New("active SFTP access session limit reached")
)

type sftpAccessSession struct {
	userID    string
	assetID   string
	account   string
	expiresAt time.Time
}

// AccessSessionStore keeps only hashes of short-lived browser SFTP permits.
// Sessions are intentionally process-local: a service restart or HA takeover
// invalidates them and requires the operator to open the file manager again.
type AccessSessionStore struct {
	mu       sync.Mutex
	sessions map[[sha256.Size]byte]sftpAccessSession
	now      func() time.Time
}

func NewAccessSessionStore() *AccessSessionStore {
	return &AccessSessionStore{sessions: make(map[[sha256.Size]byte]sftpAccessSession), now: time.Now}
}

// Issue returns a random bearer token once and stores only its SHA-256 digest.
func (s *AccessSessionStore) Issue(userID, assetID, account string) (string, time.Time, error) {
	if userID == "" || assetID == "" || account == "" {
		return "", time.Time{}, ErrInvalidAccessSession
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", time.Time{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	digest := sha256.Sum256([]byte(token))
	now := s.now().UTC()
	expiresAt := now.Add(SFTPAccessSessionLifetime)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	if len(s.sessions) >= maxSFTPAccessSessions {
		return "", time.Time{}, ErrAccessSessionLimit
	}
	s.sessions[digest] = sftpAccessSession{userID: userID, assetID: assetID, account: account, expiresAt: expiresAt}
	return token, expiresAt, nil
}

// Authorize checks the token against the authenticated operator and current
// asset account. It never returns the stored token or SSH credential.
func (s *AccessSessionStore) Authorize(token, userID, assetID, account string) bool {
	if !validAccessSessionToken(token) || userID == "" || assetID == "" || account == "" {
		return false
	}
	digest := sha256.Sum256([]byte(token))
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	session, exists := s.sessions[digest]
	return exists && session.userID == userID && session.assetID == assetID && session.account == account && now.Before(session.expiresAt)
}

// Revoke invalidates a token only for the operator who owns it.
func (s *AccessSessionStore) Revoke(token, userID, assetID, account string) bool {
	if !validAccessSessionToken(token) || userID == "" || assetID == "" || account == "" {
		return false
	}
	digest := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	session, exists := s.sessions[digest]
	if !exists || session.userID != userID || session.assetID != assetID || session.account != account {
		return false
	}
	delete(s.sessions, digest)
	return true
}

func (s *AccessSessionStore) pruneLocked(now time.Time) {
	for digest, session := range s.sessions {
		if !now.Before(session.expiresAt) {
			delete(s.sessions, digest)
		}
	}
}

func validAccessSessionToken(token string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == token
}
