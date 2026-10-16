package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

const (
	totpIssuer           = "JumpServer233"
	totpDigits           = 6
	totpPeriod           = 30 * time.Second
	totpEnrollmentTTL    = 10 * time.Minute
	totpSecretBytes      = 20
	totpVerificationSkew = 1
	mfaRecoveryCodeCount = 10
	mfaRecoveryCodeBytes = 16
)

var (
	ErrMFAKeyUnavailable    = errors.New("MFA vault key is unavailable")
	ErrMFAAlreadyEnabled    = errors.New("MFA is already enabled")
	ErrMFAEnrollmentExpired = errors.New("MFA enrollment has expired")
	ErrMFAEnrollmentMissing = errors.New("MFA enrollment is required")
	ErrMFASetupRequired     = errors.New("MFA enrollment is required by global policy")
	ErrMFARequiredByPolicy  = errors.New("MFA cannot be disabled while global policy requires it")
	ErrInvalidOTP           = errors.New("one-time code is invalid")
	ErrOTPRequired          = errors.New("one-time code is required")
	ErrUserNotFound         = errors.New("user not found")
)

// MFAEnrollment is returned to the authenticated user so an authenticator app
// can be configured. Its secret is encrypted at rest and never appears in User.
type MFAEnrollment struct {
	Secret          string    `json:"secret"`
	ProvisioningURI string    `json:"provisioning_uri"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// MFARecoveryCodes contains one-time plaintext codes returned only when the
// authenticated user generates or regenerates their recovery codes.
type MFARecoveryCodes struct {
	Codes       []string  `json:"codes"`
	GeneratedAt time.Time `json:"generated_at"`
}

// StartMFAEnrollment creates or resumes a short-lived TOTP enrollment for the
// authenticated user. The returned secret must be confirmed before MFA is on.
func (s *Service) StartMFAEnrollment(userID string) (MFAEnrollment, error) {
	if s.aead == nil {
		return MFAEnrollment{}, ErrMFAKeyUnavailable
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	username, record, ok := s.storedUserByIDLocked(userID)
	if !ok {
		return MFAEnrollment{}, ErrUserNotFound
	}
	if record.MFAEnabled {
		return MFAEnrollment{}, ErrMFAAlreadyEnabled
	}
	enrollment, updated, err := s.startMFAEnrollmentLocked(username, record, now)
	if err != nil {
		return MFAEnrollment{}, err
	}
	s.users[username] = updated
	if err := s.persistLocked(); err != nil {
		s.users[username] = record
		return MFAEnrollment{}, err
	}
	return enrollment, nil
}

func (s *Service) startMFAEnrollmentLocked(username string, record storedUser, now time.Time) (MFAEnrollment, storedUser, error) {
	if len(record.PendingMFASecretCiphertext) > 0 && record.PendingMFAExpiresAt != nil && now.Before(*record.PendingMFAExpiresAt) {
		secret, err := s.openMFASecret(record.ID, record.PendingMFASecretCiphertext)
		if err != nil {
			return MFAEnrollment{}, record, err
		}
		return newMFAEnrollment(username, string(secret), *record.PendingMFAExpiresAt), record, nil
	}

	secret, err := generateTOTPSecret(rand.Reader)
	if err != nil {
		return MFAEnrollment{}, record, err
	}
	ciphertext, err := s.sealMFASecret(record.ID, []byte(secret))
	if err != nil {
		return MFAEnrollment{}, record, err
	}
	expiresAt := now.Add(totpEnrollmentTTL)
	record.PendingMFASecretCiphertext = ciphertext
	record.PendingMFAExpiresAt = &expiresAt
	return newMFAEnrollment(username, secret, expiresAt), record, nil
}

// ConfirmMFAEnrollment enables TOTP only after the user proves that their
// authenticator received the pending secret. Confirmation consumes that step.
func (s *Service) ConfirmMFAEnrollment(userID, code string) (User, error) {
	if s.aead == nil {
		return User{}, ErrMFAKeyUnavailable
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	username, record, ok := s.storedUserByIDLocked(userID)
	if !ok {
		return User{}, ErrUserNotFound
	}
	if record.MFAEnabled {
		return User{}, ErrMFAAlreadyEnabled
	}
	if len(record.PendingMFASecretCiphertext) == 0 || record.PendingMFAExpiresAt == nil {
		return User{}, ErrMFAEnrollmentMissing
	}
	if !now.Before(*record.PendingMFAExpiresAt) {
		previous := record
		record.PendingMFASecretCiphertext = nil
		record.PendingMFAExpiresAt = nil
		record.MFASetupPasskeyID = ""
		record.MFASetupChallengeHash = nil
		record.MFASetupChallengeExpiresAt = nil
		s.users[username] = record
		if err := s.persistLocked(); err != nil {
			s.users[username] = previous
			return User{}, err
		}
		return User{}, ErrMFAEnrollmentExpired
	}
	secret, err := s.openMFASecret(record.ID, record.PendingMFASecretCiphertext)
	if err != nil {
		return User{}, err
	}
	step, valid := matchTOTP(secret, code, now)
	if !valid {
		return User{}, ErrInvalidOTP
	}
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
		return User{}, err
	}
	return record.User, nil
}

// DisableMFA requires the current password and a fresh TOTP code.
func (s *Service) DisableMFA(userID, password, code string, sessionToken ...string) (User, error) {
	if s.aead == nil {
		return User{}, ErrMFAKeyUnavailable
	}
	s.mu.RLock()
	username, snapshot, ok := s.storedUserByIDLocked(userID)
	s.mu.RUnlock()
	if !ok {
		return User{}, ErrUserNotFound
	}
	if !snapshot.MFAEnabled {
		return User{}, ErrMFAEnrollmentMissing
	}
	if len(password) > 256 {
		return User{}, ErrInvalidCredentials
	}
	if err := s.verifyMFACredential(snapshot, password, sessionToken); err != nil {
		return User{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.users[username]
	if !exists || current.ID != userID || !current.MFAEnabled || subtle.ConstantTimeCompare(current.PasswordHash, snapshot.PasswordHash) != 1 {
		return User{}, ErrInvalidCredentials
	}
	if s.requiresMFALocked(current.User) {
		return User{}, ErrMFARequiredByPolicy
	}
	secret, err := s.openMFASecret(current.ID, current.MFASecretCiphertext)
	if err != nil {
		return User{}, err
	}
	step, valid := matchTOTP(secret, code, s.now())
	if !valid || step <= current.MFALastAcceptedStep {
		return User{}, ErrInvalidOTP
	}
	previous := current
	current.MFAEnabled = false
	current.MFASecretCiphertext = nil
	current.MFALastAcceptedStep = 0
	current.MFARecoveryCodeHashes = nil
	s.users[username] = current
	if err := s.persistLocked(); err != nil {
		s.users[username] = previous
		return User{}, err
	}
	return current.User, nil
}

// RegenerateMFARecoveryCodes replaces the user's recovery codes after checking
// the current password and consuming a fresh TOTP or unused recovery code.
func (s *Service) RegenerateMFARecoveryCodes(userID, password, code string, sessionToken ...string) (MFARecoveryCodes, error) {
	if s.aead == nil {
		return MFARecoveryCodes{}, ErrMFAKeyUnavailable
	}
	s.mu.RLock()
	username, snapshot, ok := s.storedUserByIDLocked(userID)
	s.mu.RUnlock()
	if !ok {
		return MFARecoveryCodes{}, ErrUserNotFound
	}
	if !snapshot.MFAEnabled {
		return MFARecoveryCodes{}, ErrMFAEnrollmentMissing
	}
	if len(password) > 256 {
		return MFARecoveryCodes{}, ErrInvalidCredentials
	}
	if err := s.verifyMFACredential(snapshot, password, sessionToken); err != nil {
		return MFARecoveryCodes{}, err
	}

	codes, hashes, err := generateMFARecoveryCodes()
	if err != nil {
		return MFARecoveryCodes{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.users[username]
	if !exists || current.ID != userID || !current.MFAEnabled || subtle.ConstantTimeCompare(current.PasswordHash, snapshot.PasswordHash) != 1 {
		return MFARecoveryCodes{}, ErrInvalidCredentials
	}
	updated, consumed, err := s.consumeMFASecondFactorLocked(current, code, s.now())
	if err != nil {
		return MFARecoveryCodes{}, err
	}
	if !consumed {
		return MFARecoveryCodes{}, ErrInvalidOTP
	}
	previous := current
	updated.MFARecoveryCodeHashes = hashes
	s.users[username] = updated
	if err := s.persistLocked(); err != nil {
		s.users[username] = previous
		return MFARecoveryCodes{}, err
	}
	return MFARecoveryCodes{Codes: codes, GeneratedAt: s.now().UTC()}, nil
}

// consumeMFASecondFactorLocked accepts a fresh TOTP step or removes exactly
// one matching recovery-code hash. The caller holds s.mu.
func (s *Service) consumeMFASecondFactorLocked(record storedUser, submitted string, now time.Time) (storedUser, bool, error) {
	secret, err := s.openMFASecret(record.ID, record.MFASecretCiphertext)
	if err != nil {
		return record, false, err
	}
	step, ok := matchTOTP(secret, submitted, now)
	if ok && step > record.MFALastAcceptedStep {
		record.MFALastAcceptedStep = step
		return record, true, nil
	}
	normalized := normalizeMFARecoveryCode(submitted)
	if normalized == "" {
		return record, false, nil
	}
	digest := sha256.Sum256([]byte(normalized))
	matched := -1
	for index, recoveryHash := range record.MFARecoveryCodeHashes {
		if subtle.ConstantTimeCompare(recoveryHash, digest[:]) == 1 {
			matched = index
		}
	}
	if matched < 0 {
		return record, false, nil
	}
	remaining := make([][]byte, 0, len(record.MFARecoveryCodeHashes)-1)
	remaining = append(remaining, record.MFARecoveryCodeHashes[:matched]...)
	remaining = append(remaining, record.MFARecoveryCodeHashes[matched+1:]...)
	record.MFARecoveryCodeHashes = remaining
	return record, true, nil
}

func generateMFARecoveryCodes() ([]string, [][]byte, error) {
	codes := make([]string, 0, mfaRecoveryCodeCount)
	hashes := make([][]byte, 0, mfaRecoveryCodeCount)
	seen := make(map[[sha256.Size]byte]struct{}, mfaRecoveryCodeCount)
	for len(codes) < mfaRecoveryCodeCount {
		secret := make([]byte, mfaRecoveryCodeBytes)
		if _, err := io.ReadFull(rand.Reader, secret); err != nil {
			return nil, nil, fmt.Errorf("generate MFA recovery code: %w", err)
		}
		raw := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
		normalized := normalizeMFARecoveryCode(raw)
		digest := sha256.Sum256([]byte(normalized))
		if _, duplicate := seen[digest]; duplicate {
			continue
		}
		seen[digest] = struct{}{}
		codes = append(codes, formatMFARecoveryCode(raw))
		hashes = append(hashes, append([]byte(nil), digest[:]...))
	}
	return codes, hashes, nil
}

func normalizeMFARecoveryCode(code string) string {
	var normalized strings.Builder
	normalized.Grow(len(code))
	for _, char := range strings.ToUpper(strings.TrimSpace(code)) {
		if char == '-' || char == ' ' || char == '\t' || char == '\r' || char == '\n' {
			continue
		}
		if (char < 'A' || char > 'Z') && (char < '2' || char > '7') {
			return ""
		}
		normalized.WriteRune(char)
	}
	value := normalized.String()
	if len(value) != 26 {
		return ""
	}
	return value
}

func formatMFARecoveryCode(code string) string {
	groups := make([]string, 0, 6)
	for len(code) > 6 {
		groups = append(groups, code[:5])
		code = code[5:]
	}
	groups = append(groups, code)
	return strings.Join(groups, "-")
}

func (s *Service) storedUserByIDLocked(id string) (string, storedUser, bool) {
	for username, record := range s.users {
		if record.ID == id {
			return username, record, true
		}
	}
	return "", storedUser{}, false
}

func (s *Service) sealMFASecret(userID string, plaintext []byte) ([]byte, error) {
	if s.aead == nil {
		return nil, ErrMFAKeyUnavailable
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate MFA secret nonce: %w", err)
	}
	sealed := s.aead.Seal(nil, nonce, plaintext, mfaAAD(userID))
	return append(nonce, sealed...), nil
}

func (s *Service) openMFASecret(userID string, ciphertext []byte) ([]byte, error) {
	if s.aead == nil {
		return nil, ErrMFAKeyUnavailable
	}
	if len(ciphertext) < s.aead.NonceSize()+s.aead.Overhead() {
		return nil, ErrUserStoreCorrupt
	}
	nonce := ciphertext[:s.aead.NonceSize()]
	plaintext, err := s.aead.Open(nil, nonce, ciphertext[s.aead.NonceSize():], mfaAAD(userID))
	if err != nil {
		return nil, fmt.Errorf("MFA secret cannot be opened with this vault key")
	}
	return plaintext, nil
}

func mfaAAD(userID string) []byte {
	return []byte("jumpserver233:mfa:" + userID)
}

func newMFAEnrollment(username, secret string, expiresAt time.Time) MFAEnrollment {
	query := url.Values{}
	query.Set("secret", secret)
	query.Set("issuer", totpIssuer)
	query.Set("algorithm", "SHA1")
	query.Set("digits", fmt.Sprint(totpDigits))
	query.Set("period", fmt.Sprint(int(totpPeriod/time.Second)))
	label := url.PathEscape(totpIssuer + ":" + username)
	return MFAEnrollment{
		Secret:          secret,
		ProvisioningURI: "otpauth://totp/" + label + "?" + query.Encode(),
		ExpiresAt:       expiresAt,
	}
}

func generateTOTPSecret(source io.Reader) (string, error) {
	secret := make([]byte, totpSecretBytes)
	if _, err := io.ReadFull(source, secret); err != nil {
		return "", fmt.Errorf("generate TOTP secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

func matchTOTP(secret []byte, code string, now time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}
	for _, char := range code {
		if char < '0' || char > '9' {
			return 0, false
		}
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(string(secret)))
	if err != nil || len(key) != totpSecretBytes {
		return 0, false
	}
	currentStep := now.Unix() / int64(totpPeriod/time.Second)
	steps := []int64{currentStep}
	for delta := int64(1); delta <= totpVerificationSkew; delta++ {
		if currentStep >= delta {
			steps = append(steps, currentStep-delta)
		}
		steps = append(steps, currentStep+delta)
	}
	for _, step := range steps {
		candidate := totpAtStep(key, uint64(step))
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

func totpAtStep(key []byte, step uint64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], step)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := int(digest[len(digest)-1] & 0x0f)
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1)
	for i := 0; i < totpDigits; i++ {
		modulus *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, value%modulus)
}
