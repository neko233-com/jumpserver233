package auth

import (
	"crypto/sha256"
	"encoding/hex"
)

func validSecondaryStamp(v string) bool {
	if v == "" {
		return true
	}
	if len(v) != 64 {
		return false
	}
	raw, e := hex.DecodeString(v)
	return e == nil && len(raw) == 32
}

// These methods are server-only; no request body accepts a verification stamp.
func (s *Service) SetSessionSecondaryStamp(token, userID, stamp string) error {
	if token == "" || len(token) > 128 || stamp == "" || !validSecondaryStamp(stamp) {
		return ErrInvalidLoginProof
	}
	hash := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[hash]
	if !ok || session.user.ID != userID || !s.now().Before(session.expiresAt) {
		return ErrInvalidLoginProof
	}
	old := session
	session.secondaryStamp = stamp
	s.sessions[hash] = session
	if e := s.persistSessionsLocked(); e != nil {
		s.sessions[hash] = old
		return e
	}
	return nil
}
func (s *Service) SessionSecondaryStamp(token string) string {
	if token == "" || len(token) > 128 {
		return ""
	}
	hash := sha256.Sum256([]byte(token))
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[hash]
	if !ok || !s.now().Before(session.expiresAt) {
		return ""
	}
	return session.secondaryStamp
}
func (s *Service) LoginProofSecondaryStamp(proof, userID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, _, e := s.openLoginProofLocked(proof)
	if e != nil || data.UserID != userID {
		return "", ErrInvalidLoginProof
	}
	return data.SecondaryStamp, nil
}
