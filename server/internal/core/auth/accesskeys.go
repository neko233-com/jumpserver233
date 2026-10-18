package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

const (
	maxAccessKeys        = 10
	accessKeyIDBytes     = 16
	accessKeySecretBytes = 32
)

var (
	ErrAccessKeyUnavailable = errors.New("AccessKey encryption is unavailable")
	ErrAccessKeyLimit       = errors.New("AccessKey limit reached")
	ErrAccessKeyNotFound    = errors.New("AccessKey not found")
)

type storedAccessKey struct {
	ID               string    `json:"id"`
	SecretCiphertext []byte    `json:"secret_ciphertext"`
	CreatedAt        time.Time `json:"created_at"`
}

// AccessKeyMetadata is safe to return after the one-time secret response.
type AccessKeyMetadata struct {
	ID        string    `json:"access_key_id"`
	CreatedAt time.Time `json:"created_at"`
}

// AccessKeyCredentials returns its secret exactly once when a key is created.
type AccessKeyCredentials struct {
	ID        string    `json:"access_key_id"`
	Secret    string    `json:"access_key_secret"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateAccessKey adds a signing key to the authenticated user. Only encrypted
// secret bytes are persisted; the caller receives the plaintext once.
func (s *Service) CreateAccessKey(userID string) (AccessKeyCredentials, error) {
	if s.aead == nil {
		return AccessKeyCredentials{}, ErrAccessKeyUnavailable
	}
	var secretBytes [accessKeySecretBytes]byte
	if _, err := io.ReadFull(rand.Reader, secretBytes[:]); err != nil {
		return AccessKeyCredentials{}, fmt.Errorf("generate AccessKey secret: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(secretBytes[:])

	s.mu.Lock()
	defer s.mu.Unlock()
	username, record, exists := s.storedUserByIDLocked(userID)
	if !exists || !s.externalAllowedLocked(record) {
		return AccessKeyCredentials{}, ErrUserNotFound
	}
	if len(record.AccessKeys) >= maxAccessKeys {
		return AccessKeyCredentials{}, ErrAccessKeyLimit
	}

	keyID, err := s.newAccessKeyIDLocked()
	if err != nil {
		return AccessKeyCredentials{}, err
	}
	// JumpServer signs with the AccessKey secret text as the HMAC key. Store
	// that exact text encrypted so API clients can use the returned value as-is.
	ciphertext, err := s.sealAccessKeySecret(record.ID, keyID, []byte(secret))
	if err != nil {
		return AccessKeyCredentials{}, err
	}
	createdAt := s.now().UTC()
	key := storedAccessKey{ID: keyID, SecretCiphertext: ciphertext, CreatedAt: createdAt}
	previous := record.AccessKeys
	record.AccessKeys = append(append([]storedAccessKey(nil), record.AccessKeys...), key)
	s.users[username] = record
	if err := s.persistLocked(); err != nil {
		record.AccessKeys = previous
		s.users[username] = record
		return AccessKeyCredentials{}, err
	}
	return AccessKeyCredentials{ID: keyID, Secret: secret, CreatedAt: createdAt}, nil
}

func (s *Service) ListAccessKeys(userID string) ([]AccessKeyMetadata, error) {
	s.mu.RLock()
	_, record, exists := s.storedUserByIDLocked(userID)
	if !exists {
		s.mu.RUnlock()
		return nil, ErrUserNotFound
	}
	keys := make([]AccessKeyMetadata, 0, len(record.AccessKeys))
	for _, key := range record.AccessKeys {
		keys = append(keys, AccessKeyMetadata{ID: key.ID, CreatedAt: key.CreatedAt})
	}
	s.mu.RUnlock()
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].CreatedAt.Equal(keys[j].CreatedAt) {
			return keys[i].ID < keys[j].ID
		}
		return keys[i].CreatedAt.Before(keys[j].CreatedAt)
	})
	return keys, nil
}

func (s *Service) DeleteAccessKey(userID, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	username, record, exists := s.storedUserByIDLocked(userID)
	if !exists {
		return ErrUserNotFound
	}
	for index, key := range record.AccessKeys {
		if key.ID != keyID {
			continue
		}
		previous := record.AccessKeys
		record.AccessKeys = append(append([]storedAccessKey(nil), previous[:index]...), previous[index+1:]...)
		s.users[username] = record
		if err := s.persistLocked(); err != nil {
			record.AccessKeys = previous
			s.users[username] = record
			return err
		}
		return nil
	}
	return ErrAccessKeyNotFound
}

// VerifyAccessKeySignature verifies a base64-encoded HMAC-SHA256 signature
// using a key ID. It rechecks that the key remains active before returning.
func (s *Service) VerifyAccessKeySignature(keyID, stringToSign, signature string) (User, bool) {
	provided, err := base64.StdEncoding.Strict().DecodeString(signature)
	if err != nil || len(provided) != sha256.Size {
		return User{}, false
	}

	s.mu.RLock()
	var username string
	var owner User
	var snapshot storedAccessKey
	found := false
	for name, record := range s.users {
		for _, key := range record.AccessKeys {
			if key.ID == keyID {
				username, owner, snapshot, found = name, record.User, key, true
				break
			}
		}
		if found {
			break
		}
	}
	s.mu.RUnlock()
	if !found {
		return User{}, false
	}

	secret, err := s.openAccessKeySecret(owner.ID, snapshot.ID, snapshot.SecretCiphertext)
	if err != nil {
		return User{}, false
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(stringToSign))
	if subtle.ConstantTimeCompare(mac.Sum(nil), provided) != 1 {
		return User{}, false
	}

	s.mu.RLock()
	current, exists := s.users[username]
	if exists && current.ID == owner.ID && s.externalAllowedLocked(current) {
		for _, key := range current.AccessKeys {
			if key.ID == keyID && subtle.ConstantTimeCompare(key.SecretCiphertext, snapshot.SecretCiphertext) == 1 {
				owner = current.User
				found = true
				goto verified
			}
		}
	}
	found = false
verified:
	s.mu.RUnlock()
	return owner, found
}

func (s *Service) newAccessKeyIDLocked() (string, error) {
	for attempt := 0; attempt < 4; attempt++ {
		var idBytes [accessKeyIDBytes]byte
		if _, err := io.ReadFull(rand.Reader, idBytes[:]); err != nil {
			return "", fmt.Errorf("generate AccessKey ID: %w", err)
		}
		keyID := "ak-" + hex.EncodeToString(idBytes[:])
		if !s.accessKeyIDExistsLocked(keyID) {
			return keyID, nil
		}
	}
	return "", errors.New("could not allocate a unique AccessKey ID")
}

func (s *Service) accessKeyIDExistsLocked(keyID string) bool {
	for _, record := range s.users {
		for _, key := range record.AccessKeys {
			if key.ID == keyID {
				return true
			}
		}
	}
	return false
}

func validAccessKeyID(keyID string) bool {
	if !strings.HasPrefix(keyID, "ak-") || len(keyID) != 3+accessKeyIDBytes*2 {
		return false
	}
	decoded, err := hex.DecodeString(keyID[3:])
	return err == nil && len(decoded) == accessKeyIDBytes
}

func (s *Service) sealAccessKeySecret(userID, keyID string, plaintext []byte) ([]byte, error) {
	if s.aead == nil {
		return nil, ErrAccessKeyUnavailable
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate AccessKey nonce: %w", err)
	}
	sealed := s.aead.Seal(nil, nonce, plaintext, accessKeyAAD(userID, keyID))
	return append(nonce, sealed...), nil
}

func (s *Service) openAccessKeySecret(userID, keyID string, ciphertext []byte) ([]byte, error) {
	if s.aead == nil {
		return nil, ErrAccessKeyUnavailable
	}
	if len(ciphertext) < s.aead.NonceSize()+s.aead.Overhead() {
		return nil, ErrUserStoreCorrupt
	}
	nonce := ciphertext[:s.aead.NonceSize()]
	return s.aead.Open(nil, nonce, ciphertext[s.aead.NonceSize():], accessKeyAAD(userID, keyID))
}

func accessKeyAAD(userID, keyID string) []byte {
	return []byte("jumpserver233:access-key:" + userID + ":" + keyID)
}
