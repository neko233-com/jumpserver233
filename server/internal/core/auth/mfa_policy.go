package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type MFAEnforcement string

const (
	MFAEnforcementDisabled MFAEnforcement = "disabled"
	MFAEnforcementAdmins   MFAEnforcement = "admins"
	MFAEnforcementAll      MFAEnforcement = "all"
)

type MFAEnforcementSettings struct {
	Mode MFAEnforcement `json:"mode"`
}

// MFASetupChallenge is issued only after a valid password when policy requires
// MFA for an account that has not enrolled. Its token only authorizes setup.
type MFASetupChallenge struct {
	Token      string
	Enrollment MFAEnrollment
	ExpiresAt  time.Time
}

var (
	ErrInvalidMFAEnforcement = errors.New("invalid global MFA enforcement mode")
	ErrMFASetupChallenge     = errors.New("MFA setup challenge is invalid or expired")
)

func (mode MFAEnforcement) valid() bool {
	return mode == MFAEnforcementDisabled || mode == MFAEnforcementAdmins || mode == MFAEnforcementAll
}

func (mode MFAEnforcement) requires(role string) bool {
	return mode == MFAEnforcementAll || (mode == MFAEnforcementAdmins && role == RoleAdmin)
}

// The callback must not call back into Service. It is evaluated while the
// identity lock is held, so current delegated roles participate in admin MFA.
func (s *Service) SetPrivilegedCheck(check func(string) bool) {
	s.mu.Lock()
	s.privilegedCheck = check
	s.mu.Unlock()
}
func (s *Service) requiresMFALocked(user User) bool {
	return s.mfaPolicy.requires(user.Role) || (s.mfaPolicy == MFAEnforcementAdmins && s.privilegedCheck != nil && s.privilegedCheck(user.ID))
}

func (s *Service) MFAEnforcementSettings() MFAEnforcementSettings {
	s.mu.RLock()
	settings := MFAEnforcementSettings{Mode: s.mfaPolicy}
	s.mu.RUnlock()
	return settings
}

func (s *Service) SetMFAEnforcement(mode MFAEnforcement) (MFAEnforcementSettings, error) {
	if !mode.valid() {
		return MFAEnforcementSettings{}, ErrInvalidMFAEnforcement
	}
	if mode != MFAEnforcementDisabled && s.aead == nil {
		return MFAEnforcementSettings{}, ErrMFAKeyUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := s.mfaPolicy
	s.mfaPolicy = mode
	if err := s.persistMFAEnforcementLocked(); err != nil {
		s.mfaPolicy = previous
		return MFAEnforcementSettings{}, err
	}
	return MFAEnforcementSettings{Mode: mode}, nil
}

func (s *Service) loadMFAEnforcement() (MFAEnforcement, error) {
	var data []byte
	var err error
	if s.documents != nil {
		data, err = s.documents.LoadOrImport("mfa-policy", s.mfaPolicyPath)
	} else {
		data, err = os.ReadFile(s.mfaPolicyPath)
		if errors.Is(err, os.ErrNotExist) {
			return MFAEnforcementDisabled, nil
		}
	}
	if err != nil {
		return "", fmt.Errorf("read global MFA policy: %w", err)
	}
	if len(data) == 0 {
		return MFAEnforcementDisabled, nil
	}
	var settings MFAEnforcementSettings
	if err := json.Unmarshal(data, &settings); err != nil || !settings.Mode.valid() {
		return "", fmt.Errorf("decode global MFA policy: %w", ErrInvalidMFAEnforcement)
	}
	return settings.Mode, nil
}

func (s *Service) persistMFAEnforcementLocked() error {
	data, err := json.Marshal(MFAEnforcementSettings{Mode: s.mfaPolicy})
	if err != nil {
		return fmt.Errorf("encode global MFA policy: %w", err)
	}
	if s.documents != nil {
		if err := s.documents.Save("mfa-policy", data); err != nil {
			return fmt.Errorf("persist global MFA policy: %w", err)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.mfaPolicyPath), 0o700); err != nil {
		return fmt.Errorf("create MFA policy directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.mfaPolicyPath), ".mfa-policy-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary MFA policy: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("protect temporary MFA policy: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary MFA policy: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary MFA policy: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary MFA policy: %w", err)
	}
	if err := os.Rename(tmpPath, s.mfaPolicyPath); err != nil {
		return fmt.Errorf("replace global MFA policy: %w", err)
	}
	return nil
}

func (s *Service) createMFASetupChallengeLocked(username string, record storedUser, now time.Time) (MFASetupChallenge, storedUser, error) {
	enrollment, updated, err := s.startMFAEnrollmentLocked(username, record, now)
	if err != nil {
		return MFASetupChallenge{}, record, err
	}
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		return MFASetupChallenge{}, record, fmt.Errorf("generate MFA setup challenge: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	expiresAt := now.Add(totpEnrollmentTTL)
	if updated.PendingMFAExpiresAt != nil && updated.PendingMFAExpiresAt.Before(expiresAt) {
		expiresAt = *updated.PendingMFAExpiresAt
	}
	hash := sha256.Sum256([]byte(token))
	updated.MFASetupPasskeyID = ""
	updated.MFASetupChallengeHash = hash[:]
	updated.MFASetupChallengeExpiresAt = &expiresAt
	return MFASetupChallenge{Token: token, Enrollment: enrollment, ExpiresAt: expiresAt}, updated, nil
}

// ConfirmMFASetupChallenge consumes a password-verified, single-purpose setup
// challenge, enrolls TOTP, and returns the user's first normal login session.
func (s *Service) ConfirmMFASetupChallenge(token, code string, externalUserID ...string) (LoginSession, error) {
	return s.confirmMFASetupChallenge(token, code, "", externalUserID...)
}
func (s *Service) ConfirmPasskeyMFASetupChallenge(token, code, userID, credentialID string) (LoginSession, error) {
	if credentialID == "" {
		return LoginSession{}, ErrMFASetupChallenge
	}
	return s.confirmMFASetupChallenge(token, code, credentialID, userID)
}
func (s *Service) confirmMFASetupChallenge(token, code, passkeyID string, externalUserID ...string) (LoginSession, error) {
	if s.aead == nil {
		return LoginSession{}, ErrMFAKeyUnavailable
	}
	if token == "" || len(token) > 128 {
		return LoginSession{}, ErrMFASetupChallenge
	}
	challengeHash := sha256.Sum256([]byte(token))
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	username := ""
	var record storedUser
	for candidate, value := range s.users {
		if len(value.MFASetupChallengeHash) == sha256.Size && subtle.ConstantTimeCompare(value.MFASetupChallengeHash, challengeHash[:]) == 1 {
			username = candidate
			record = value
		}
	}
	if username == "" || !s.requiresMFALocked(record.User) || record.MFAEnabled || record.MFASetupChallengeExpiresAt == nil {
		return LoginSession{}, ErrMFASetupChallenge
	}
	if record.Source != "" && (len(externalUserID) != 1 || externalUserID[0] != record.ID) {
		return LoginSession{}, ErrMFASetupChallenge
	}
	if record.MFASetupPasskeyID != passkeyID || (passkeyID != "" && (len(externalUserID) != 1 || externalUserID[0] != record.ID || s.passkeyAllowed == nil || !s.passkeyAllowed(record.ID, passkeyID))) {
		return LoginSession{}, ErrMFASetupChallenge
	}
	if !s.externalAllowedLocked(record) {
		return LoginSession{}, ErrInvalidCredentials
	}
	if !now.Before(*record.MFASetupChallengeExpiresAt) || record.PendingMFAExpiresAt == nil || !now.Before(*record.PendingMFAExpiresAt) || len(record.PendingMFASecretCiphertext) == 0 {
		previous := record
		record.MFASetupPasskeyID = ""
		record.MFASetupChallengeHash = nil
		record.MFASetupChallengeExpiresAt = nil
		record.PendingMFASecretCiphertext = nil
		record.PendingMFAExpiresAt = nil
		s.users[username] = record
		if err := s.persistLocked(); err != nil {
			s.users[username] = previous
			return LoginSession{}, err
		}
		return LoginSession{}, ErrMFAEnrollmentExpired
	}
	secret, err := s.openMFASecret(record.ID, record.PendingMFASecretCiphertext)
	if err != nil {
		return LoginSession{}, err
	}
	step, valid := matchTOTP(secret, code, now)
	if !valid {
		return LoginSession{}, ErrInvalidOTP
	}
	for hash, session := range s.sessions {
		if !now.Before(session.expiresAt) {
			delete(s.sessions, hash)
		}
	}
	if len(s.sessions) >= maxSessions {
		return LoginSession{}, ErrSessionLimit
	}
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		return LoginSession{}, fmt.Errorf("generate access token: %w", err)
	}
	accessToken := base64.RawURLEncoding.EncodeToString(tokenBytes)
	expiresAt := now.Add(SessionTTL)
	tokenHash := sha256.Sum256([]byte(accessToken))

	previous := record
	record.MFAEnabled = true
	record.MFASecretCiphertext = append([]byte(nil), record.PendingMFASecretCiphertext...)
	record.MFALastAcceptedStep = step
	record.PendingMFASecretCiphertext = nil
	record.PendingMFAExpiresAt = nil
	record.MFASetupPasskeyID = ""
	record.MFASetupChallengeHash = nil
	record.MFASetupChallengeExpiresAt = nil
	s.users[username] = record
	if err := s.persistLocked(); err != nil {
		s.users[username] = previous
		return LoginSession{}, err
	}
	s.sessions[tokenHash] = activeSession{credentialStamp: loginCredentialStamp(record), user: record.User, expiresAt: expiresAt, authenticatedAt: now.UTC(), passkeyID: passkeyID}
	if err := s.persistSessionsLocked(); err != nil {
		delete(s.sessions, tokenHash)
		s.users[username] = previous
		if rollbackErr := s.persistLocked(); rollbackErr != nil {
			return LoginSession{}, errors.Join(err, fmt.Errorf("rollback MFA enrollment: %w", rollbackErr))
		}
		return LoginSession{}, err
	}
	return LoginSession{AccessToken: accessToken, ExpiresAt: expiresAt, User: record.User}, nil
}
