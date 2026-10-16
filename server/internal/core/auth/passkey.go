package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

func (s *Service) SetPasskeyAllowed(check func(string, string) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.passkeyAllowed = check
}

// Called only after the WebAuthn boundary verified a one-use browser assertion.
func (s *Service) AuthenticatePasskeyUser(id, credentialID, otp string) (LoginSession, *MFASetupChallenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name, current, ok := s.storedUserByIDLocked(id)
	if !ok || credentialID == "" || s.passkeyAllowed == nil || !s.passkeyAllowed(id, credentialID) || !s.externalAllowedLocked(current) {
		return LoginSession{}, nil, ErrInvalidCredentials
	}
	return s.authenticateVerifiedPrimaryLocked(name, current, otp, credentialID)
}

// VerifyPasskeyManagement requires a primary proof and consumes a fresh local
// second factor when enabled. Long-lived API credentials alone are insufficient.
func (s *Service) VerifyPasskeyManagement(id, password, otp, sessionToken string) error {
	if len(password) > 256 || len(otp) > 128 || len(sessionToken) > 128 {
		return ErrInvalidCredentials
	}
	s.mu.RLock()
	_, snapshot, ok := s.storedUserByIDLocked(id)
	s.mu.RUnlock()
	if !ok {
		return ErrUserNotFound
	}
	if e := s.verifyMFACredential(snapshot, password, []string{sessionToken}); e != nil {
		return e
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	name, current, ok := s.storedUserByIDLocked(id)
	if !ok || !sameCredentialVersion(current, snapshot) || !s.externalAllowedLocked(current) {
		return ErrInvalidCredentials
	}
	if s.requiresMFALocked(current.User) && !current.MFAEnabled {
		return ErrMFARequiredByPolicy
	}
	if current.MFAEnabled {
		if otp == "" {
			return ErrOTPRequired
		}
		updated, consumed, e := s.consumeMFASecondFactorLocked(current, otp, s.now())
		if e != nil {
			return e
		}
		if !consumed {
			return ErrInvalidOTP
		}
		s.users[name] = updated
		if e = s.persistLocked(); e != nil {
			s.users[name] = current
			return e
		}
	}
	return nil
}

func sameCredentialVersion(a, b storedUser) bool {
	return a.ID == b.ID && a.Source == b.Source && a.ExternalIdentity == b.ExternalIdentity && a.ExternalIssuer == b.ExternalIssuer && a.MFAEnabled == b.MFAEnabled && bytes.Equal(a.PasswordHash, b.PasswordHash) && bytes.Equal(a.PasswordSalt, b.PasswordSalt) && bytes.Equal(a.MFASecretCiphertext, b.MFASecretCiphertext)
}

func (s *Service) PasskeyManagementReady(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, u, ok := s.storedUserByIDLocked(id)
	return ok && s.externalAllowedLocked(u) && (!s.requiresMFALocked(u.User) || u.MFAEnabled)
}

// PasskeyManagementVersion is an internal fingerprint, never a client response.
// It binds a device ceremony to the primary credential/MFA state it verified.
func (s *Service) PasskeyManagementVersion(id string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, u, ok := s.storedUserByIDLocked(id)
	if !ok {
		return ""
	}
	raw, _ := json.Marshal(struct {
		ID, Source, Issuer, Identity  string
		Salt, PasswordHash, MFASecret []byte
		MFAEnabled                    bool
		Policy                        MFAEnforcement
	}{u.ID, u.Source, u.ExternalIssuer, u.ExternalIdentity, u.PasswordSalt, u.PasswordHash, u.MFASecretCiphertext, u.MFAEnabled, s.mfaPolicy})
	hash := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
