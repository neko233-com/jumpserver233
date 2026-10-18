package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrInvalidLoginProof     = errors.New("verified login proof is invalid or expired")
	ErrLoginProofUnavailable = errors.New("verified login proof encryption is unavailable")
)

// RevokeReviewedSession is an internal cancellation hook. No HTTP endpoint
// accepts session digests; the encrypted review store owns this digest.
func (s *Service) RevokeReviewedSession(digest []byte) error {
	if len(digest) != sha256.Size {
		return ErrInvalidLoginProof
	}
	var hash [32]byte
	copy(hash[:], digest)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, hash)
	return s.persistSessionsLocked()
}

// QuarantinedLogin contains an opaque authenticated proof. It is internal
// server state, never a client response or an approval ticket.
type QuarantinedLogin struct {
	Proof      string
	ExpiresAt  time.Time
	AuthSource string
}
type loginProofData struct {
	SecondaryStamp   string    `json:"secondary_stamp,omitempty"`
	Version          int       `json:"version"`
	UserID           string    `json:"user_id"`
	CredentialStamp  []byte    `json:"credential_stamp"`
	AuthenticatedAt  time.Time `json:"authenticated_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	SessionExpiresAt time.Time `json:"session_expires_at"`
	PasskeyID        string    `json:"passkey_id,omitempty"`
}

func loginCredentialStamp(u storedUser) []byte {
	// MFA consumption counters are intentionally excluded: another valid login
	// must not invalidate a pending proof. Credential/configuration changes do.
	raw, _ := json.Marshal(struct {
		ID, Role, Source, Issuer, Identity    string
		MFA                                   bool
		PasswordHash, PasswordSalt, MFASecret []byte
	}{u.ID, u.Role, u.Source, u.ExternalIssuer, u.ExternalIdentity, u.MFAEnabled, u.PasswordHash, u.PasswordSalt, u.MFASecretCiphertext})
	hash := sha256.Sum256(raw)
	return hash[:]
}

// QuarantineLogin removes a just-created session before the API returns any
// token or cookie. Only primary + required MFA authentication can create it.
func (s *Service) QuarantineLogin(token string) (QuarantinedLogin, error) {
	if token == "" || len(token) > 128 {
		return QuarantinedLogin{}, ErrInvalidLoginProof
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.aead == nil {
		return QuarantinedLogin{}, ErrLoginProofUnavailable
	}
	hash := sha256.Sum256([]byte(token))
	session, ok := s.sessions[hash]
	now := s.now().UTC()
	if !ok || session.authenticatedAt.IsZero() || now.Before(session.authenticatedAt) || now.Sub(session.authenticatedAt) > time.Minute || !now.Before(session.expiresAt) {
		return QuarantinedLogin{}, ErrInvalidLoginProof
	}
	_, user, ok := s.storedUserByIDLocked(session.user.ID)
	if !ok || subtle.ConstantTimeCompare(session.credentialStamp, loginCredentialStamp(user)) != 1 || !s.externalAllowedLocked(user) || session.passkeyID != "" && (s.passkeyAllowed == nil || !s.passkeyAllowed(user.ID, session.passkeyID)) {
		return QuarantinedLogin{}, ErrInvalidLoginProof
	}
	expires := now.Add(5 * time.Minute)
	if session.expiresAt.Before(expires) {
		expires = session.expiresAt
	}
	data := loginProofData{SecondaryStamp: session.secondaryStamp, Version: 1, UserID: user.ID, CredentialStamp: loginCredentialStamp(user), AuthenticatedAt: session.authenticatedAt.UTC(), ExpiresAt: expires, SessionExpiresAt: session.expiresAt, PasskeyID: session.passkeyID}
	raw, e := json.Marshal(data)
	if e != nil {
		return QuarantinedLogin{}, e
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return QuarantinedLogin{}, e
	}
	sealed := s.aead.Seal(nonce, nonce, raw, []byte("jms233/verified-login-proof/v1"))
	delete(s.sessions, hash)
	if e = s.persistSessionsLocked(); e != nil {
		s.sessions[hash] = session
		return QuarantinedLogin{}, e
	}
	source := user.Source
	if session.passkeyID != "" {
		source = "passkey"
	}
	if source == "" {
		source = "local"
	}
	return QuarantinedLogin{Proof: base64.RawURLEncoding.EncodeToString(sealed), ExpiresAt: expires, AuthSource: source}, nil
}
func (s *Service) openLoginProofLocked(proof string) (loginProofData, storedUser, error) {
	if s.aead == nil || proof == "" || len(proof) > 8192 {
		return loginProofData{}, storedUser{}, ErrInvalidLoginProof
	}
	raw, e := base64.RawURLEncoding.DecodeString(proof)
	if e != nil || len(raw) < s.aead.NonceSize()+s.aead.Overhead() {
		return loginProofData{}, storedUser{}, ErrInvalidLoginProof
	}
	plain, e := s.aead.Open(nil, raw[:s.aead.NonceSize()], raw[s.aead.NonceSize():], []byte("jms233/verified-login-proof/v1"))
	if e != nil {
		return loginProofData{}, storedUser{}, ErrInvalidLoginProof
	}
	var data loginProofData
	now := s.now().UTC()
	if json.Unmarshal(plain, &data) != nil || !validSecondaryStamp(data.SecondaryStamp) {
		return loginProofData{}, storedUser{}, ErrInvalidLoginProof
	}
	if data.Version != 1 || data.UserID == "" || data.AuthenticatedAt.IsZero() || now.Before(data.AuthenticatedAt) || !now.Before(data.ExpiresAt) || data.ExpiresAt.After(data.AuthenticatedAt.Add(6*time.Minute)) || !now.Before(data.SessionExpiresAt) || data.SessionExpiresAt.After(data.AuthenticatedAt.Add(SessionTTL)) {
		return loginProofData{}, storedUser{}, ErrInvalidLoginProof
	}
	_, user, ok := s.storedUserByIDLocked(data.UserID)
	if !ok || subtle.ConstantTimeCompare(data.CredentialStamp, loginCredentialStamp(user)) != 1 || !s.externalAllowedLocked(user) || (s.requiresMFALocked(user.User) && !user.MFAEnabled) || (data.PasskeyID != "" && (s.passkeyAllowed == nil || !s.passkeyAllowed(user.ID, data.PasskeyID))) {
		return loginProofData{}, storedUser{}, ErrInvalidLoginProof
	}
	return data, user, nil
}

func (s *Service) ValidateLoginProof(proof, expectedUserID string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, _, e := s.openLoginProofLocked(proof)
	if e != nil || data.UserID != expectedUserID {
		return ErrInvalidLoginProof
	}
	return nil
}

// ResumeLoginProof is called only inside the approval store's serialized,
// one-use completion transaction. Its caller revokes this fresh session if
// persisting the consumed approval fails.
func (s *Service) ResumeLoginProof(proof string) (LoginSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, user, e := s.openLoginProofLocked(proof)
	if e != nil {
		return LoginSession{}, e
	}
	now := s.now().UTC()
	for hash, session := range s.sessions {
		if !now.Before(session.expiresAt) {
			delete(s.sessions, hash)
		}
	}
	if len(s.sessions) >= maxSessions {
		return LoginSession{}, ErrSessionLimit
	}
	var raw [32]byte
	if _, e = rand.Read(raw[:]); e != nil {
		return LoginSession{}, e
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	hash := sha256.Sum256([]byte(token))
	s.sessions[hash] = activeSession{secondaryStamp: data.SecondaryStamp, credentialStamp: loginCredentialStamp(user), user: user.User, expiresAt: data.SessionExpiresAt, authenticatedAt: data.AuthenticatedAt, passkeyID: data.PasskeyID}
	if e = s.persistSessionsLocked(); e != nil {
		delete(s.sessions, hash)
		return LoginSession{}, e
	}
	return LoginSession{AccessToken: token, ExpiresAt: data.SessionExpiresAt, User: user.User}, nil
}
