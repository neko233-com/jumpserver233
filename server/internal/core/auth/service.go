package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/identityscope"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"golang.org/x/crypto/scrypt"
)

const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	SessionTTL   = 12 * time.Hour
	scryptN      = 1 << 15
	scryptR      = 8
	scryptP      = 1
	passwordSize = 32
	maxSessions  = 10000
)

var (
	ErrInvalidUsername     = errors.New("username must be 3 to 64 ASCII letters, digits, dot, underscore, or hyphen")
	ErrInvalidPassword     = errors.New("password must be between 12 and 256 bytes")
	ErrInvalidRole         = errors.New("role must be admin or operator")
	ErrUserExists          = errors.New("username already exists")
	ErrBootstrapRequired   = errors.New("initial administrator must be created through bootstrap")
	ErrBootstrapComplete   = errors.New("initial administrator is already configured")
	ErrInvalidCredentials  = errors.New("invalid username or password")
	ErrPasswordUnchanged   = errors.New("new password must differ from the current password")
	ErrPasswordChanged     = errors.New("password changed while the request was being processed")
	ErrAuthenticationBusy  = errors.New("too many authentication operations are in progress")
	ErrSessionLimit        = errors.New("active login session limit reached")
	ErrUserStoreCorrupt    = errors.New("user store contains an invalid record")
	ErrSessionStoreCorrupt = errors.New("session store contains an invalid record")
	dummySalt              = []byte("jumpserver233-dummy-salt")
)

// User is the public, non-secret identity representation.
type User struct {
	PasswordChangedAt     time.Time `json:"password_changed_at,omitzero"`
	PasswordResetRequired bool      `json:"password_reset_required,omitempty"`
	Name                  string    `json:"name,omitempty"`
	Comment               string    `json:"comment,omitempty"`
	Disabled              bool      `json:"disabled,omitempty"`
	DateExpired           time.Time `json:"date_expired,omitzero"`
	ArchivedAt            time.Time `json:"archived_at,omitzero"`
	Revision              int       `json:"revision,omitempty"`
	AuthGeneration        int       `json:"auth_generation,omitempty"`
	ID                    string    `json:"id"`
	Username              string    `json:"username"`
	Role                  string    `json:"role"`
	MFAEnabled            bool      `json:"mfa_enabled"`
	SMSMFAEnabled         bool      `json:"sms_mfa_enabled,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
	Source                string    `json:"source,omitempty"`
	SourceID              string    `json:"source_id,omitempty"`
	SourceSuspended       bool      `json:"source_suspended,omitempty"`
}

// LoginSession contains a one-time-returned bearer token. The token itself is
// kept only in the caller response; shared state stores only its SHA-256 digest.
type LoginSession struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
	User        User      `json:"user"`
}

type storedUser struct {
	User
	SMSPhoneCiphertext         []byte                 `json:"sms_phone_ciphertext,omitempty"`
	PasswordFingerprint        []byte                 `json:"password_fingerprint,omitempty"`
	PasswordHistory            []passwordHistory      `json:"password_history,omitempty"`
	PasswordPending            *passwordPending       `json:"password_pending,omitempty"`
	ExternalIssuer             string                 `json:"external_issuer,omitempty"`
	ExternalIdentity           string                 `json:"external_identity,omitempty"`
	PasswordSalt               []byte                 `json:"password_salt"`
	PasswordHash               []byte                 `json:"password_hash"`
	AccessKeys                 []storedAccessKey      `json:"access_keys,omitempty"`
	PermanentTokens            []storedPermanentToken `json:"permanent_tokens,omitempty"`
	MFASecretCiphertext        []byte                 `json:"mfa_secret_ciphertext,omitempty"`
	MFALastAcceptedStep        int64                  `json:"mfa_last_accepted_step,omitempty"`
	MFARecoveryCodeHashes      [][]byte               `json:"mfa_recovery_code_hashes,omitempty"`
	PendingMFASecretCiphertext []byte                 `json:"pending_mfa_secret_ciphertext,omitempty"`
	PendingMFAExpiresAt        *time.Time             `json:"pending_mfa_expires_at,omitempty"`
	MFASetupPasskeyID          string                 `json:"mfa_setup_passkey_id,omitempty"`
	MFASetupChallengeHash      []byte                 `json:"mfa_setup_challenge_hash,omitempty"`
	MFASetupChallengeExpiresAt *time.Time             `json:"mfa_setup_challenge_expires_at,omitempty"`
}

type activeSession struct {
	smsStamp        string
	secondaryStamp  string
	credentialStamp []byte
	user            User
	expiresAt       time.Time
	authenticatedAt time.Time
	issuedAt        time.Time
	proofDeadline   time.Time
	passkeyID       string
}

type storedSession struct {
	SMSStamp        string    `json:"sms_stamp,omitempty"`
	SecondaryStamp  string    `json:"secondary_stamp,omitempty"`
	CredentialStamp []byte    `json:"credential_stamp,omitempty"`
	TokenHash       string    `json:"token_hash"`
	User            User      `json:"user"`
	ExpiresAt       time.Time `json:"expires_at"`
	AuthenticatedAt time.Time `json:"authenticated_at,omitzero"`
	IssuedAt        time.Time `json:"issued_at,omitzero"`
	ProofDeadline   time.Time `json:"proof_deadline,omitzero"`
	PasskeyID       string    `json:"passkey_id,omitempty"`
}

// Service stores local users and short-lived login sessions. Standalone mode
// keeps sessions in memory; shared-state mode persists only token digests.
// Passwords are scrypt hashes.
type Service struct {
	mu                   sync.RWMutex
	path                 string
	documents            *storage.Documents
	aead                 cipher.AEAD
	mfaPolicyPath        string
	mfaPolicy            MFAEnforcement
	privilegedCheck      func(string) bool
	externalAllowed      map[string]func(string) bool
	passkeyAllowed       func(string, string) bool
	users                map[string]storedUser
	userEvents           []UserEvent
	passwordPolicy       PasswordPolicy
	passwordPolicyEvents []PasswordPolicyEvent
	passwordPepper       []byte
	passwordMarker       []byte
	sessions             map[[32]byte]activeSession
	hashSlots            chan struct{}
	now                  func() time.Time
}

func OpenService(path string) (*Service, error) {
	return openService(path, nil, nil)
}

func OpenServiceWithDocuments(path string, documents *storage.Documents) (*Service, error) {
	if documents == nil {
		return nil, fmt.Errorf("shared state documents are required")
	}
	return openService(path, documents, nil)
}

// OpenServiceWithVaultKey enables encrypted MFA enrollment for standalone mode.
func OpenServiceWithVaultKey(path string, key []byte) (*Service, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("vault key must be 32 bytes")
	}
	return openService(path, nil, key)
}

// OpenServiceWithDocumentsAndVaultKey enables shared MFA state in cluster mode.
func OpenServiceWithDocumentsAndVaultKey(path string, documents *storage.Documents, key []byte) (*Service, error) {
	if documents == nil {
		return nil, fmt.Errorf("shared state documents are required")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("vault key must be 32 bytes")
	}
	return openService(path, documents, key)
}

func openService(path string, documents *storage.Documents, key []byte) (*Service, error) {
	var aead cipher.AEAD
	if len(key) != 0 {
		if len(key) != 32 {
			return nil, fmt.Errorf("vault key must be 32 bytes")
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("create MFA vault cipher: %w", err)
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("create MFA vault AEAD: %w", err)
		}
	}
	service := &Service{
		path:           path,
		documents:      documents,
		aead:           aead,
		mfaPolicyPath:  filepath.Join(filepath.Dir(path), "mfa-policy.json"),
		users:          make(map[string]storedUser),
		sessions:       make(map[[32]byte]activeSession),
		hashSlots:      make(chan struct{}, 4),
		now:            time.Now,
		passwordPolicy: defaultPasswordPolicy(),
	}
	if len(key) > 0 {
		m := hmac.New(sha256.New, key)
		m.Write([]byte("jms233/password-history/v1"))
		service.passwordPepper = m.Sum(nil)
	}
	policy, err := service.loadMFAEnforcement()
	if err != nil {
		return nil, err
	}
	service.mfaPolicy = policy
	if policy != MFAEnforcementDisabled && aead == nil {
		return nil, ErrMFAKeyUnavailable
	}
	var data []byte
	if documents != nil {
		data, err = documents.LoadOrImport("users", path)
	} else {
		data, err = os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return service, nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("read user store: %w", err)
	}
	if len(data) == 0 {
		return service, nil
	}
	var users []storedUser
	var decodeErr error
	userFormat := 1
	if strings.HasPrefix(strings.TrimSpace(string(data)), "[") {
		decodeErr = json.Unmarshal(data, &users)
	} else {
		var doc userEnvelope
		decodeErr = json.Unmarshal(data, &doc)
		userFormat = doc.Version
		if decodeErr == nil && ((doc.Version != 2 && doc.Version != 3 && doc.Version != 4) || len(doc.Audit) > 5000 || len(doc.PasswordAudit) > 1000 || doc.Version >= 3 && doc.PasswordPolicy == nil || doc.Version == 2 && (doc.PasswordPolicy != nil || len(doc.PasswordAudit) > 0 || len(doc.PasswordMarker) > 0)) {
			decodeErr = ErrUserStoreCorrupt
		}
		if decodeErr == nil && doc.PasswordPolicy != nil {
			if !validPasswordPolicy(*doc.PasswordPolicy) || !validPasswordPolicyEvents(doc.PasswordAudit) || len(doc.PasswordMarker) != 0 && len(doc.PasswordMarker) != 32 {
				decodeErr = ErrUserStoreCorrupt
			} else {
				service.passwordPolicy = *doc.PasswordPolicy
				service.passwordPolicyEvents = doc.PasswordAudit
				service.passwordMarker = doc.PasswordMarker
				if len(service.passwordPepper) > 0 && len(doc.PasswordMarker) > 0 && subtle.ConstantTimeCompare(doc.PasswordMarker, service.passwordStoreMarker()) != 1 {
					decodeErr = ErrUserStoreCorrupt
				}
				if len(service.passwordPepper) == 0 && (service.passwordPolicy.HistoryCount > 0 || service.passwordPolicy.MaxAgeDays > 0 || service.passwordPolicy.AdminMaxAgeDays > 0) {
					return nil, ErrMFAKeyUnavailable
				}
			}
		}
		users = doc.Users
		service.userEvents = doc.Audit
	}
	if decodeErr == nil && !validUserEvents(service.userEvents) {
		decodeErr = ErrUserStoreCorrupt
	}
	if decodeErr != nil {
		return nil, fmt.Errorf("decode user store: %w", decodeErr)
	}
	seenAccessKeyIDs := make(map[string]struct{})
	seenPermanentTokenIDs := make(map[string]struct{})
	seenPermanentTokenHashes := make(map[string]struct{})
	for _, user := range users {
		if !validPasswordRecord(user) {
			return nil, ErrUserStoreCorrupt
		}
		if !lifecycleValid(user.User) {
			return nil, ErrUserStoreCorrupt
		}
		if user.Revision == 0 {
			user.Revision = 1
		}
		if (user.Source != "" && !isExternalSource(user.Source)) || (user.Source != "" && (user.ExternalIssuer == "" || len(user.ExternalIdentity) != 64 || user.Role != RoleOperator)) {
			return nil, ErrUserStoreCorrupt
		}
		if user.SourceID != "" && (user.Source == "" || !identityscope.ValidID(user.SourceID)) {
			return nil, ErrUserStoreCorrupt
		}
		if identityscope.NativeKind(user.Source) && !identityscope.ValidID(user.SourceID) {
			return nil, ErrUserStoreCorrupt
		}
		if user.SourceSuspended && (user.Source != "ldap" || !identityscope.ValidID(user.SourceID)) {
			return nil, ErrUserStoreCorrupt
		}
		username, valid := normalizeUsername(user.Username)
		if user.SMSMFAEnabled != (len(user.SMSPhoneCiphertext) > 0) {
			return nil, ErrUserStoreCorrupt
		}
		if userFormat < 4 && (user.SMSMFAEnabled || len(user.SMSPhoneCiphertext) > 0) {
			return nil, ErrUserStoreCorrupt
		}
		if user.SMSMFAEnabled {
			if aead == nil {
				return nil, ErrUserStoreCorrupt
			}
			if _, e := service.openSMSPhone(user.ID, user.SMSPhoneCiphertext); e != nil {
				return nil, ErrUserStoreCorrupt
			}
		}
		if !valid || username != user.Username || user.ID == "" || (user.Role != RoleAdmin && user.Role != RoleOperator) || len(user.PasswordSalt) != 16 || len(user.PasswordHash) != passwordSize || user.CreatedAt.IsZero() ||
			user.MFAEnabled != (len(user.MFASecretCiphertext) > 0) || (len(user.PendingMFASecretCiphertext) > 0) != (user.PendingMFAExpiresAt != nil) || (user.MFAEnabled && len(user.PendingMFASecretCiphertext) > 0) || user.MFALastAcceptedStep < 0 || (!user.MFAEnabled && user.MFALastAcceptedStep != 0) ||
			(len(user.MFASetupChallengeHash) != 0 && len(user.MFASetupChallengeHash) != sha256.Size) || (len(user.MFASetupChallengeHash) > 0) != (user.MFASetupChallengeExpiresAt != nil) || (len(user.MFASetupChallengeHash) > 0 && len(user.PendingMFASecretCiphertext) == 0) ||
			len(user.MFARecoveryCodeHashes) > mfaRecoveryCodeCount || (!user.MFAEnabled && len(user.MFARecoveryCodeHashes) > 0) {
			return nil, ErrUserStoreCorrupt
		}
		seenRecoveryHashes := make(map[string]struct{}, len(user.MFARecoveryCodeHashes))
		for _, recoveryHash := range user.MFARecoveryCodeHashes {
			if len(recoveryHash) != sha256.Size {
				return nil, ErrUserStoreCorrupt
			}
			if _, duplicate := seenRecoveryHashes[string(recoveryHash)]; duplicate {
				return nil, ErrUserStoreCorrupt
			}
			seenRecoveryHashes[string(recoveryHash)] = struct{}{}
		}
		if user.PendingMFAExpiresAt != nil && user.PendingMFAExpiresAt.IsZero() {
			return nil, ErrUserStoreCorrupt
		}
		if user.MFASetupChallengeExpiresAt != nil && user.MFASetupChallengeExpiresAt.IsZero() {
			return nil, ErrUserStoreCorrupt
		}
		if len(user.AccessKeys) > maxAccessKeys {
			return nil, ErrUserStoreCorrupt
		}
		if len(user.PermanentTokens) > maxPermanentTokens {
			return nil, ErrUserStoreCorrupt
		}
		for _, token := range user.PermanentTokens {
			if !validPermanentTokenID(token.ID) || len(token.TokenHash) != sha256.Size || token.CreatedAt.IsZero() {
				return nil, ErrUserStoreCorrupt
			}
			if _, duplicate := seenPermanentTokenIDs[token.ID]; duplicate {
				return nil, ErrUserStoreCorrupt
			}
			seenPermanentTokenIDs[token.ID] = struct{}{}
			if _, duplicate := seenPermanentTokenHashes[string(token.TokenHash)]; duplicate {
				return nil, ErrUserStoreCorrupt
			}
			seenPermanentTokenHashes[string(token.TokenHash)] = struct{}{}
		}
		for _, accessKey := range user.AccessKeys {
			if !validAccessKeyID(accessKey.ID) || accessKey.CreatedAt.IsZero() || (aead != nil && len(accessKey.SecretCiphertext) < aead.NonceSize()+aead.Overhead()) {
				return nil, ErrUserStoreCorrupt
			}
			if _, duplicate := seenAccessKeyIDs[accessKey.ID]; duplicate {
				return nil, ErrUserStoreCorrupt
			}
			seenAccessKeyIDs[accessKey.ID] = struct{}{}
			if aead == nil {
				return nil, fmt.Errorf("%w: AccessKey records require the vault key", ErrUserStoreCorrupt)
			}
			secret, err := service.openAccessKeySecret(user.ID, accessKey.ID, accessKey.SecretCiphertext)
			decodedSecret, decodeErr := base64.RawURLEncoding.DecodeString(string(secret))
			if err != nil || decodeErr != nil || len(decodedSecret) != accessKeySecretBytes {
				return nil, fmt.Errorf("%w: stored AccessKey secret is invalid", ErrUserStoreCorrupt)
			}
		}
		if user.MFAEnabled || len(user.PendingMFASecretCiphertext) > 0 {
			if aead == nil {
				return nil, fmt.Errorf("%w: MFA records require the vault key", ErrUserStoreCorrupt)
			}
			ciphertext := user.MFASecretCiphertext
			if !user.MFAEnabled {
				ciphertext = user.PendingMFASecretCiphertext
			}
			if _, err := service.openMFASecret(user.ID, ciphertext); err != nil {
				return nil, fmt.Errorf("%w: stored MFA secret is invalid", ErrUserStoreCorrupt)
			}
		}
		if _, exists := service.users[username]; exists {
			return nil, ErrUserStoreCorrupt
		}
		service.users[username] = user
	}
	if documents != nil {
		if err := service.loadSessions(); err != nil {
			return nil, err
		}
	}
	return service, nil
}

func (s *Service) BootstrapRequired() bool {
	s.mu.RLock()
	required := len(s.users) == 0
	s.mu.RUnlock()
	return required
}

// Bootstrap creates the first administrator once. It cannot be used after any
// user account exists.
func (s *Service) Bootstrap(username, password string) (User, error) {
	return s.createUser(username, password, RoleAdmin, true, false)
}

// InitializeDefaultAdministrator runs explicitly during startup. Existing stores
// are left untouched, including a root account whose password was changed.
func (s *Service) InitializeDefaultAdministrator() error {
	_, err := s.createUser("root", "root", RoleAdmin, true, true)
	if errors.Is(err, ErrBootstrapComplete) {
		return nil
	}
	return err
}

func (s *Service) CreateUser(username, password, role string) (User, error) {
	return s.createUser(username, password, role, false, false)
}

func (s *Service) createUser(username, password, role string, firstOnly, defaultAdministrator bool) (User, error) {
	canonical, valid := normalizeUsername(username)
	if !valid {
		return User{}, ErrInvalidUsername
	}
	defaultCredential := defaultAdministrator && firstOnly && canonical == "root" && password == "root" && role == RoleAdmin
	if !defaultCredential && (len(password) < 12 || len(password) > 256) {
		return User{}, ErrInvalidPassword
	}
	if role != RoleAdmin && role != RoleOperator {
		return User{}, ErrInvalidRole
	}
	s.mu.RLock()
	passwordPolicy := s.passwordPolicy
	s.mu.RUnlock()
	if !defaultCredential {
		if e := passwordPolicy.check(password, role); e != nil {
			return User{}, e
		}
	}
	if firstOnly {
		role = RoleAdmin
		s.mu.RLock()
		configured := len(s.users) != 0
		s.mu.RUnlock()
		if configured {
			return User{}, ErrBootstrapComplete
		}
	} else if s.BootstrapRequired() {
		return User{}, ErrBootstrapRequired
	}

	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return User{}, fmt.Errorf("generate password salt: %w", err)
	}
	passwordHash, err := s.derivePassword(password, salt)
	if err != nil {
		return User{}, err
	}
	var idBytes [16]byte
	if _, err := io.ReadFull(rand.Reader, idBytes[:]); err != nil {
		return User{}, fmt.Errorf("generate user ID: %w", err)
	}
	now := s.now().UTC()
	user := User{PasswordChangedAt: now, Revision: 1, ID: "user-" + hex.EncodeToString(idBytes[:]), Username: canonical, Role: role, CreatedAt: now}
	record := storedUser{User: user, PasswordSalt: salt, PasswordHash: passwordHash, PasswordFingerprint: s.passwordFingerprint(user.ID, password)}

	s.mu.Lock()
	defer s.mu.Unlock()
	if firstOnly && len(s.users) != 0 {
		return User{}, ErrBootstrapComplete
	}
	if !firstOnly && len(s.users) == 0 {
		return User{}, ErrBootstrapRequired
	}
	if _, exists := s.users[canonical]; exists {
		return User{}, ErrUserExists
	}
	if passwordPolicy.Revision != s.passwordPolicy.Revision {
		return User{}, ErrUserRevision
	}
	s.users[canonical] = record
	if err := s.persistLocked(); err != nil {
		delete(s.users, canonical)
		return User{}, err
	}
	return user, nil
}

func (s *Service) ListUsers() []User {
	s.mu.RLock()
	users := make([]User, 0, len(s.users))
	for _, record := range s.users {
		if !record.ArchivedAt.IsZero() {
			continue
		}
		users = append(users, record.User)
	}
	s.mu.RUnlock()
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	return users
}

func (s *Service) UserByID(id string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, record := range s.users {
		if record.ID == id && record.ArchivedAt.IsZero() {
			return record.User, true
		}
	}
	return User{}, false
}

// ChangePassword verifies the current password, stores a newly salted scrypt
// hash, and revokes the user's other active sessions. The session performing
// the change remains valid so the UI can confirm success.
func (s *Service) ChangePassword(userID, currentToken, currentPassword, newPassword string) error {
	return s.changePassword(userID, currentToken, currentPassword, newPassword)
}

func (s *Service) Authenticate(username, password string) (LoginSession, error) {
	return s.AuthenticateWithOTP(username, password, "")
}

// AuthenticateWithOTP verifies the password and, when configured, consumes a
// fresh TOTP step before issuing a login token.
func (s *Service) AuthenticateWithOTP(username, password, otp string) (LoginSession, error) {
	session, challenge, err := s.AuthenticateWithOTPOrMFASetup(username, password, otp)
	if err != nil {
		return LoginSession{}, err
	}
	if challenge != nil {
		return LoginSession{}, ErrMFASetupRequired
	}
	return session, nil
}

// AuthenticateWithOTPOrMFASetup either creates a normal session or returns a
// restricted setup challenge after password verification when global policy
// requires MFA for an account that has not enrolled yet.
func (s *Service) AuthenticateWithOTPOrMFASetup(username, password, otp string) (LoginSession, *MFASetupChallenge, error) {
	if len(password) > 256 {
		return LoginSession{}, nil, ErrInvalidCredentials
	}
	canonical, valid := normalizeUsername(username)
	s.mu.RLock()
	record, exists := s.users[canonical]
	s.mu.RUnlock()

	salt := dummySalt
	want := make([]byte, passwordSize)
	if valid && exists {
		salt = record.PasswordSalt
		want = record.PasswordHash
	}
	got, err := s.derivePassword(password, salt)
	if err != nil {
		return LoginSession{}, nil, err
	}
	if !valid || !exists || record.Source != "" || subtle.ConstantTimeCompare(got, want) != 1 {
		return LoginSession{}, nil, ErrInvalidCredentials
	}
	s.mu.Lock()
	now := s.now()
	current, currentExists := s.users[canonical]
	if !currentExists || current.ID != record.ID || current.AuthGeneration != record.AuthGeneration || !s.externalAllowedLocked(current) || subtle.ConstantTimeCompare(current.PasswordHash, record.PasswordHash) != 1 {
		s.mu.Unlock()
		return LoginSession{}, nil, ErrInvalidCredentials
	}
	if current.MFAEnabled {
		if strings.TrimSpace(otp) == "" {
			s.mu.Unlock()
			return LoginSession{}, nil, ErrOTPRequired
		}
		updated, consumed, err := s.consumeMFASecondFactorLocked(current, otp, now)
		if err != nil {
			s.mu.Unlock()
			return LoginSession{}, nil, err
		}
		if !consumed {
			s.mu.Unlock()
			return LoginSession{}, nil, ErrInvalidCredentials
		}
		previous := current
		current = updated
		s.users[canonical] = current
		if err := s.persistLocked(); err != nil {
			s.users[canonical] = previous
			s.mu.Unlock()
			return LoginSession{}, nil, err
		}
	} else if s.requiresMFALocked(current.User) {
		challenge, updated, err := s.createMFASetupChallengeLocked(canonical, current, now.UTC())
		if err != nil {
			s.mu.Unlock()
			return LoginSession{}, nil, err
		}
		previous := current
		s.users[canonical] = updated
		if err := s.persistLocked(); err != nil {
			s.users[canonical] = previous
			s.mu.Unlock()
			return LoginSession{}, nil, err
		}
		s.mu.Unlock()
		return LoginSession{}, &challenge, nil
	}
	record.User = current.User
	for hash, session := range s.sessions {
		if !now.Before(session.expiresAt) {
			delete(s.sessions, hash)
		}
	}
	if len(s.sessions) >= maxSessions {
		s.mu.Unlock()
		return LoginSession{}, nil, ErrSessionLimit
	}
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		s.mu.Unlock()
		return LoginSession{}, nil, fmt.Errorf("generate access token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	expiresAt := now.UTC().Add(SessionTTL)
	tokenHash := sha256.Sum256([]byte(token))
	s.sessions[tokenHash] = activeSession{credentialStamp: loginCredentialStamp(record), user: record.User, expiresAt: expiresAt, authenticatedAt: now.UTC()}
	if err := s.persistSessionsLocked(); err != nil {
		delete(s.sessions, tokenHash)
		s.mu.Unlock()
		return LoginSession{}, nil, err
	}
	s.mu.Unlock()
	return LoginSession{AccessToken: token, ExpiresAt: expiresAt, User: record.User}, nil, nil
}

func (s *Service) ValidateToken(token string) (User, bool) {
	if token == "" || len(token) > 128 {
		return User{}, false
	}
	hash := sha256.Sum256([]byte(token))
	s.mu.Lock()
	session, exists := s.sessions[hash]
	if exists && !s.now().Before(session.expiresAt) {
		delete(s.sessions, hash)
		exists = false
		_ = s.persistSessionsLocked()
	}
	if exists {
		for _, record := range s.users {
			if record.ID == session.user.ID {
				if session.user.AuthGeneration != record.AuthGeneration || !s.credentialUsableLocked(record) || (session.passkeyID != "" && (s.passkeyAllowed == nil || !s.passkeyAllowed(record.ID, session.passkeyID))) {
					delete(s.sessions, hash)
					exists = false
					_ = s.persistSessionsLocked()
					break
				}
				session.user = record.User
				s.sessions[hash] = session
				break
			}
		}
	}
	s.mu.Unlock()
	if !exists {
		return User{}, false
	}
	return session.user, true
}

func (s *Service) RevokeToken(token string) error {
	if token == "" || len(token) > 128 {
		return nil
	}
	hash := sha256.Sum256([]byte(token))
	s.mu.Lock()
	delete(s.sessions, hash)
	err := s.persistSessionsLocked()
	s.mu.Unlock()
	return err
}

func (s *Service) persistLocked() error {
	if s.documents != nil {
		users := make([]storedUser, 0, len(s.users))
		for _, record := range s.users {
			users = append(users, record)
		}
		sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
		data, err := s.marshalUsersLocked(users)
		if err != nil {
			return fmt.Errorf("encode user document: %w", err)
		}
		if err := s.documents.Save("users", data); err != nil {
			return fmt.Errorf("persist user document: %w", err)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create user data directory: %w", err)
	}
	users := make([]storedUser, 0, len(s.users))
	for _, record := range s.users {
		users = append(users, record)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	data, err := s.marshalUsersLocked(users)
	if err != nil {
		return fmt.Errorf("encode user store: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".users-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary user store: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("protect temporary user store: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary user store: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary user store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary user store: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("replace user store: %w", err)
	}
	return nil
}

func (s *Service) loadSessions() error {
	data, err := s.documents.Load("auth-sessions")
	if errors.Is(err, storage.ErrDocumentNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read shared login sessions: %w", err)
	}
	var records []storedSession
	if err := json.Unmarshal(data, &records); err != nil {
		return ErrSessionStoreCorrupt
	}
	now := s.now()
	for _, record := range records {
		hashBytes, err := hex.DecodeString(record.TokenHash)
		if err != nil || len(hashBytes) != sha256.Size || record.ExpiresAt.IsZero() || record.User.ID == "" || record.AuthenticatedAt.After(record.ExpiresAt) || len(record.CredentialStamp) != 0 && len(record.CredentialStamp) != sha256.Size {
			return ErrSessionStoreCorrupt
		}
		username, valid := normalizeUsername(record.User.Username)
		stored, exists := s.users[username]
		if exists && (record.User.AuthGeneration != stored.AuthGeneration || !userUsable(stored.User, now)) {
			continue
		}
		if !valid || !exists || stored.ID != record.User.ID || stored.Role != record.User.Role {
			return ErrSessionStoreCorrupt
		}
		if !now.Before(record.ExpiresAt) {
			continue
		}
		var hash [sha256.Size]byte
		copy(hash[:], hashBytes)
		if _, duplicate := s.sessions[hash]; duplicate {
			return ErrSessionStoreCorrupt
		}
		if !validSecondaryStamp(record.SecondaryStamp) || !validSecondaryStamp(record.SMSStamp) {
			return ErrSessionStoreCorrupt
		}
		if !record.IssuedAt.IsZero() && (record.AuthenticatedAt.IsZero() || record.IssuedAt.Before(record.AuthenticatedAt) || record.IssuedAt.After(record.ExpiresAt)) {
			return ErrSessionStoreCorrupt
		}
		if !record.ProofDeadline.IsZero() && (record.AuthenticatedAt.IsZero() || !record.ProofDeadline.After(record.AuthenticatedAt) || record.ProofDeadline.After(record.AuthenticatedAt.Add(6*time.Minute)) || record.ProofDeadline.After(record.ExpiresAt)) {
			return ErrSessionStoreCorrupt
		}
		s.sessions[hash] = activeSession{smsStamp: record.SMSStamp, secondaryStamp: record.SecondaryStamp, credentialStamp: append([]byte(nil), record.CredentialStamp...), user: stored.User, expiresAt: record.ExpiresAt, authenticatedAt: record.AuthenticatedAt, issuedAt: record.IssuedAt, proofDeadline: record.ProofDeadline, passkeyID: record.PasskeyID}
	}
	if len(s.sessions) > maxSessions {
		return ErrSessionStoreCorrupt
	}
	return nil
}

func (s *Service) persistSessionsLocked() error {
	if s.documents == nil {
		return nil
	}
	records := make([]storedSession, 0, len(s.sessions))
	for hash, session := range s.sessions {
		records = append(records, storedSession{
			CredentialStamp: session.credentialStamp,
			SecondaryStamp:  session.secondaryStamp,
			SMSStamp:        session.smsStamp,
			TokenHash:       hex.EncodeToString(hash[:]),
			User:            session.user,
			ExpiresAt:       session.expiresAt,
			AuthenticatedAt: session.authenticatedAt,
			IssuedAt:        session.issuedAt,
			ProofDeadline:   session.proofDeadline,
			PasskeyID:       session.passkeyID,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].TokenHash < records[j].TokenHash })
	data, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("encode shared login sessions: %w", err)
	}
	if err := s.documents.Save("auth-sessions", data); err != nil {
		return fmt.Errorf("persist shared login sessions: %w", err)
	}
	return nil
}

func normalizeUsername(username string) (string, bool) {
	username = strings.ToLower(strings.TrimSpace(username))
	if len(username) < 3 || len(username) > 64 {
		return "", false
	}
	for _, char := range username {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '.' && char != '_' && char != '-' {
			return "", false
		}
	}
	return username, true
}

func hashPassword(password string, salt []byte) ([]byte, error) {
	hash, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, passwordSize)
	if err != nil {
		return nil, fmt.Errorf("derive password hash: %w", err)
	}
	return hash, nil
}

func (s *Service) derivePassword(password string, salt []byte) ([]byte, error) {
	select {
	case s.hashSlots <- struct{}{}:
		defer func() { <-s.hashSlots }()
		return hashPassword(password, salt)
	default:
		return nil, ErrAuthenticationBusy
	}
}
