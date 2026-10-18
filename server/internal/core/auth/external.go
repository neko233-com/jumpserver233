package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

var ErrExternalIdentity = errors.New("password is managed by an external identity provider")
var ErrExternalReauthRequired = errors.New("a recent SSO session is required")

func isExternalSource(source string) bool {
	return source == "oidc" || source == "ldap" || source == "cas" || source == "saml"
}

func (s *Service) SetExternalIssuerAllowed(check func(string) bool) {
	s.SetExternalSourceAllowed("oidc", check)
}
func (s *Service) SetExternalSourceAllowed(source string, check func(string) bool) {
	s.mu.Lock()
	if s.externalAllowed == nil {
		s.externalAllowed = make(map[string]func(string) bool)
	}
	s.externalAllowed[source] = check
	s.mu.Unlock()
}
func (s *Service) externalAllowedLocked(record storedUser) bool {
	check := s.externalAllowed[record.Source]
	return record.Source == "" || (check != nil && check(record.ExternalIssuer))
}

// ActiveUserByID validates the current identity source for a long-lived session
// without requiring the remote client to resend a platform credential.
func (s *Service) ActiveUserByID(id string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, record := range s.users {
		if record.ID == id && s.externalAllowedLocked(record) {
			return record.User, true
		}
	}
	return User{}, false
}

// ActiveUsersSnapshot reads public identities in one pass for notification
// audience selection. Delivery rechecks the selected identity individually.
func (s *Service) ActiveUsersSnapshot() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, 0, len(s.users))
	for _, r := range s.users {
		if s.externalAllowedLocked(r) {
			out = append(out, r.User)
		}
	}
	return out
}

// Identity is bound to the exact issuer/subject pair. Provider names, email,
// preferred_username and role claims never link or promote existing accounts.
func (s *Service) EnsureOIDCUser(issuer, subject, alias string, provision bool) (User, error) {
	return s.EnsureExternalUser("oidc", issuer, subject, alias, provision)
}
func (s *Service) EnsureExternalUser(source, issuer, subject, alias string, provision bool) (User, error) {
	if !isExternalSource(source) || issuer == "" || subject == "" || len(issuer) > 2048 || len(subject) > 1024 {
		return User{}, ErrInvalidCredentials
	}
	digest := sha256.Sum256([]byte(issuer + "\x00" + subject))
	identity := hex.EncodeToString(digest[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.users {
		if r.Source == source && r.ExternalIdentity == identity && r.ExternalIssuer == issuer {
			return r.User, nil
		}
	}
	if !provision {
		return User{}, ErrUserNotFound
	}
	if len(s.users) == 0 {
		return User{}, ErrBootstrapRequired
	}
	if len(s.users) >= 10000 {
		return User{}, ErrAuthenticationBusy
	}
	if alias == "" {
		alias = source + "." + identity[:32]
	}
	name, valid := normalizeUsername(alias)
	if !valid {
		return User{}, ErrInvalidUsername
	}
	if _, ok := s.users[name]; ok {
		return User{}, ErrUserExists
	}
	var id [16]byte
	var salt [16]byte
	var inertHash [32]byte
	for _, dst := range [][]byte{id[:], salt[:], inertHash[:]} {
		if _, err := rand.Read(dst); err != nil {
			return User{}, err
		}
	}
	user := User{ID: "user-" + hex.EncodeToString(id[:]), Username: name, Role: RoleOperator, Source: source, CreatedAt: s.now().UTC()}
	s.users[name] = storedUser{User: user, ExternalIssuer: issuer, ExternalIdentity: identity, PasswordSalt: salt[:], PasswordHash: inertHash[:]}
	if err := s.persistLocked(); err != nil {
		delete(s.users, name)
		return User{}, err
	}
	return user, nil
}

// Called only after the OIDC boundary verified a one-use browser login ticket.
// Local MFA/recovery codes and mandatory enrollment still apply.
func (s *Service) AuthenticateOIDCUser(id, otp string) (LoginSession, *MFASetupChallenge, error) {
	return s.AuthenticateExternalUser(id, "oidc", otp)
}
func (s *Service) AuthenticateExternalUser(id, source, otp string) (LoginSession, *MFASetupChallenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name, current, ok := s.storedUserByIDLocked(id)
	if !ok || !isExternalSource(source) || current.Source != source || !s.externalAllowedLocked(current) {
		return LoginSession{}, nil, ErrInvalidCredentials
	}
	return s.authenticateVerifiedPrimaryLocked(name, current, otp, "")
}
func (s *Service) authenticateVerifiedPrimaryLocked(name string, current storedUser, otp, passkeyID string) (LoginSession, *MFASetupChallenge, error) {
	now := s.now()
	if current.MFAEnabled {
		if strings.TrimSpace(otp) == "" {
			return LoginSession{}, nil, ErrOTPRequired
		}
		updated, consumed, err := s.consumeMFASecondFactorLocked(current, otp, now)
		if err != nil {
			return LoginSession{}, nil, err
		}
		if !consumed {
			return LoginSession{}, nil, ErrInvalidCredentials
		}
		s.users[name] = updated
		if err := s.persistLocked(); err != nil {
			s.users[name] = current
			return LoginSession{}, nil, err
		}
		current = updated
	} else if s.requiresMFALocked(current.User) {
		challenge, updated, err := s.createMFASetupChallengeLocked(name, current, now.UTC())
		if err != nil {
			return LoginSession{}, nil, err
		}
		updated.MFASetupPasskeyID = passkeyID
		s.users[name] = updated
		if err := s.persistLocked(); err != nil {
			s.users[name] = current
			return LoginSession{}, nil, err
		}
		return LoginSession{}, &challenge, nil
	}
	for hash, session := range s.sessions {
		if !now.Before(session.expiresAt) {
			delete(s.sessions, hash)
		}
	}
	if len(s.sessions) >= maxSessions {
		return LoginSession{}, nil, ErrSessionLimit
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return LoginSession{}, nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	hash := sha256.Sum256([]byte(token))
	expires := now.UTC().Add(SessionTTL)
	s.sessions[hash] = activeSession{credentialStamp: loginCredentialStamp(current), user: current.User, expiresAt: expires, authenticatedAt: now.UTC(), passkeyID: passkeyID}
	if err := s.persistSessionsLocked(); err != nil {
		delete(s.sessions, hash)
		return LoginSession{}, nil, err
	}
	return LoginSession{AccessToken: token, ExpiresAt: expires, User: current.User}, nil, nil
}

func (s *Service) verifyMFACredential(snapshot storedUser, password string, tokens []string) error {
	if snapshot.Source == "" {
		hash, err := s.derivePassword(password, snapshot.PasswordSalt)
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(hash, snapshot.PasswordHash) != 1 {
			return ErrInvalidCredentials
		}
		return nil
	}
	if len(tokens) != 1 {
		return ErrExternalReauthRequired
	}
	hash := sha256.Sum256([]byte(tokens[0]))
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[hash]
	now := s.now()
	if !ok || session.user.ID != snapshot.ID || !now.Before(session.expiresAt) || session.passkeyID != "" || session.authenticatedAt.IsZero() || now.Before(session.authenticatedAt) || now.Sub(session.authenticatedAt) > 5*time.Minute || !s.externalAllowedLocked(snapshot) {
		return ErrExternalReauthRequired
	}
	return nil
}
