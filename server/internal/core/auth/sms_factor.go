package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"regexp"
)

var smsPhonePattern = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

// PrepareSMSFormat fences programs that predate SMS enforcement. Configuration
// activation must persist the new reader boundary before requiring the factor.
func (s *Service) PrepareSMSFormat() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.persistLocked()
}

// SMSContact is server-only. Public user responses expose the enabled flag;
// phone numbers remain encrypted and cannot be read by asset/agent clients.
func (s *Service) SMSContact(id string) (string, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, u, ok := s.storedUserByIDLocked(id)
	if !ok || !s.externalAllowedLocked(u) {
		return "", 0, ErrInvalidCredentials
	}
	if !u.SMSMFAEnabled {
		return "", u.AuthGeneration, nil
	}
	p, e := s.openSMSPhone(u.ID, u.SMSPhoneCiphertext)
	return p, u.AuthGeneration, e
}
func (s *Service) openSMSPhone(id string, sealed []byte) (string, error) {
	if s.aead == nil || len(sealed) < s.aead.NonceSize()+s.aead.Overhead() || len(sealed) > 128 {
		return "", ErrUserStoreCorrupt
	}
	n := s.aead.NonceSize()
	raw, e := s.aead.Open(nil, sealed[:n], sealed[n:], []byte("jms233/sms-phone/"+id+"/v1"))
	if e != nil || !smsPhonePattern.Match(raw) {
		return "", ErrUserStoreCorrupt
	}
	return string(raw), nil
}

// VerifySMSManagement requires local password/TOTP, or a recent external SSO
// session and existing local TOTP. Access keys alone cannot enroll a phone.
func (s *Service) VerifySMSManagement(id, password, otp, token string) (User, string, error) {
	if len(password) > 256 || len(token) > 128 {
		return User{}, "", ErrInvalidCredentials
	}
	s.mu.RLock()
	_, snapshot, ok := s.storedUserByIDLocked(id)
	s.mu.RUnlock()
	if !ok {
		return User{}, "", ErrInvalidCredentials
	}
	if e := s.verifyMFACredential(snapshot, password, []string{token}); e != nil {
		return User{}, "", e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	name, current, ok := s.storedUserByIDLocked(id)
	if !ok || subtle.ConstantTimeCompare(loginCredentialStamp(snapshot), loginCredentialStamp(current)) != 1 || !s.externalAllowedLocked(current) {
		return User{}, "", ErrInvalidCredentials
	}
	if current.MFAEnabled {
		updated, consumed, e := s.consumeMFASecondFactorLocked(current, otp, s.now())
		if e != nil {
			return User{}, "", e
		}
		if !consumed {
			return User{}, "", ErrInvalidOTP
		}
		s.users[name] = updated
		if e = s.persistLocked(); e != nil {
			s.users[name] = current
			return User{}, "", e
		}
		current = updated
	}
	return current.User, hex.EncodeToString(loginCredentialStamp(current)), nil
}

// SetVerifiedSMSContact accepts only an already-consumed, server-owned SMS
// capability. The generation CAS prevents changing a newer security identity.
// Repeating the same verified binding has no further security side effects.
func (s *Service) SetVerifiedSMSContact(id, phone string, generation int) (User, error) {
	if phone != "" && !smsPhonePattern.MatchString(phone) {
		return User{}, ErrInvalidCredentials
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.setVerifiedSMSContactLocked(id, phone, generation)
}
func (s *Service) setVerifiedSMSContactLocked(id, phone string, generation int) (User, error) {
	name, current, ok := s.storedUserByIDLocked(id)
	if !ok || !s.externalAllowedLocked(current) {
		return User{}, ErrInvalidCredentials
	}
	previousPhone := ""
	if current.SMSMFAEnabled {
		var e error
		previousPhone, e = s.openSMSPhone(id, current.SMSPhoneCiphertext)
		if e != nil {
			return User{}, e
		}
	}
	if previousPhone == phone && current.AuthGeneration == generation+1 {
		return current.User, nil
	}
	if current.AuthGeneration != generation {
		return User{}, ErrUserRevision
	}
	if previousPhone == phone {
		return current.User, nil
	}
	if s.aead == nil {
		return User{}, ErrMFAKeyUnavailable
	}
	next := current
	next.SMSMFAEnabled = phone != ""
	next.SMSPhoneCiphertext = nil
	if phone != "" {
		nonce := make([]byte, s.aead.NonceSize())
		if _, e := io.ReadFull(rand.Reader, nonce); e != nil {
			return User{}, e
		}
		next.SMSPhoneCiphertext = s.aead.Seal(nonce, nonce, []byte(phone), []byte("jms233/sms-phone/"+id+"/v1"))
	}
	clearUserCapabilities(&next)
	next.Revision++
	s.users[name] = next
	if e := s.persistLocked(); e != nil {
		s.users[name] = current
		return User{}, e
	}
	return next.User, nil
}
func (s *Service) SetSessionSMSStamp(token, userID, stamp string) error {
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
	session.smsStamp = stamp
	s.sessions[hash] = session
	if e := s.persistSessionsLocked(); e != nil {
		s.sessions[hash] = old
		return e
	}
	return nil
}
func (s *Service) SessionSMSStamp(token string) string {
	if token == "" || len(token) > 128 {
		return ""
	}
	hash := sha256.Sum256([]byte(token))
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.sessions[hash]
	if !ok || !s.now().Before(v.expiresAt) {
		return ""
	}
	return v.smsStamp
}
func (s *Service) LoginProofSMSStamp(proof, userID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, _, e := s.openLoginProofLocked(proof)
	if e != nil || v.UserID != userID {
		return "", ErrInvalidLoginProof
	}
	return v.SMSStamp, nil
}
func (s *Service) SMSIdentityStamp(id string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, current, ok := s.storedUserByIDLocked(id)
	if !ok || !s.externalAllowedLocked(current) {
		return ""
	}
	return hex.EncodeToString(loginCredentialStamp(current))
}

// First-login enrollment consumes an already-verified primary proof. Updating
// the binding and issuing its replacement identity are serialized under s.mu.
func (s *Service) ResumeLoginProofWithSMSContact(proof, phone string, generation int) (LoginSession, error) {
	if !smsPhonePattern.MatchString(phone) {
		return LoginSession{}, ErrInvalidCredentials
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, current, e := s.openLoginProofLocked(proof)
	if e != nil || current.AuthGeneration != generation || current.SMSMFAEnabled {
		return LoginSession{}, ErrInvalidLoginProof
	}
	user, e := s.setVerifiedSMSContactLocked(current.ID, phone, generation)
	if e != nil {
		return LoginSession{}, e
	}
	_, updated, ok := s.storedUserByIDLocked(user.ID)
	if !ok {
		return LoginSession{}, ErrInvalidCredentials
	}
	return s.resumeLoginDataLocked(data, updated)
}
