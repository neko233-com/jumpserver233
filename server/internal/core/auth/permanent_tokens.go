package auth

import (
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
	maxPermanentTokens    = 10
	permanentTokenBytes   = 32
	permanentTokenIDBytes = 16
)

var (
	ErrPermanentTokenLimit    = errors.New("permanent token limit reached")
	ErrPermanentTokenNotFound = errors.New("permanent token not found")
)

type storedPermanentToken struct {
	ID        string    `json:"id"`
	TokenHash []byte    `json:"token_hash"`
	CreatedAt time.Time `json:"created_at"`
}

// PermanentTokenMetadata never contains the token secret.
type PermanentTokenMetadata struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

// PermanentTokenCredentials exposes the token once at creation time.
type PermanentTokenCredentials struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
}

// CreatePermanentToken creates a long-lived JumpServer-compatible Token
// credential. Only its SHA-256 digest is persisted.
func (s *Service) CreatePermanentToken(userID string) (PermanentTokenCredentials, error) {
	var tokenBytes [permanentTokenBytes]byte
	if _, err := io.ReadFull(rand.Reader, tokenBytes[:]); err != nil {
		return PermanentTokenCredentials{}, fmt.Errorf("generate permanent token: %w", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(tokenBytes[:])
	hash := sha256.Sum256([]byte(plaintext))

	s.mu.Lock()
	defer s.mu.Unlock()
	username, record, exists := s.storedUserByIDLocked(userID)
	if !exists {
		return PermanentTokenCredentials{}, ErrUserNotFound
	}
	if len(record.PermanentTokens) >= maxPermanentTokens {
		return PermanentTokenCredentials{}, ErrPermanentTokenLimit
	}
	id, err := s.newPermanentTokenIDLocked()
	if err != nil {
		return PermanentTokenCredentials{}, err
	}
	createdAt := s.now().UTC()
	previous := record.PermanentTokens
	record.PermanentTokens = append(append([]storedPermanentToken(nil), previous...), storedPermanentToken{
		ID:        id,
		TokenHash: append([]byte(nil), hash[:]...),
		CreatedAt: createdAt,
	})
	s.users[username] = record
	if err := s.persistLocked(); err != nil {
		record.PermanentTokens = previous
		s.users[username] = record
		return PermanentTokenCredentials{}, err
	}
	return PermanentTokenCredentials{ID: id, Token: plaintext, CreatedAt: createdAt}, nil
}

func (s *Service) ListPermanentTokens(userID string) ([]PermanentTokenMetadata, error) {
	s.mu.RLock()
	_, record, exists := s.storedUserByIDLocked(userID)
	if !exists {
		s.mu.RUnlock()
		return nil, ErrUserNotFound
	}
	tokens := make([]PermanentTokenMetadata, 0, len(record.PermanentTokens))
	for _, token := range record.PermanentTokens {
		tokens = append(tokens, PermanentTokenMetadata{ID: token.ID, CreatedAt: token.CreatedAt})
	}
	s.mu.RUnlock()
	sort.Slice(tokens, func(i, j int) bool {
		if tokens[i].CreatedAt.Equal(tokens[j].CreatedAt) {
			return tokens[i].ID < tokens[j].ID
		}
		return tokens[i].CreatedAt.Before(tokens[j].CreatedAt)
	})
	return tokens, nil
}

func (s *Service) DeletePermanentToken(userID, tokenID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	username, record, exists := s.storedUserByIDLocked(userID)
	if !exists {
		return ErrUserNotFound
	}
	for index, token := range record.PermanentTokens {
		if token.ID != tokenID {
			continue
		}
		previous := record.PermanentTokens
		record.PermanentTokens = append(append([]storedPermanentToken(nil), previous[:index]...), previous[index+1:]...)
		s.users[username] = record
		if err := s.persistLocked(); err != nil {
			record.PermanentTokens = previous
			s.users[username] = record
			return err
		}
		return nil
	}
	return ErrPermanentTokenNotFound
}

func (s *Service) ValidatePermanentToken(plaintext string) (User, bool) {
	if len(plaintext) < 32 || len(plaintext) > 128 {
		return User{}, false
	}
	provided := sha256.Sum256([]byte(plaintext))
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, record := range s.users {
		for _, token := range record.PermanentTokens {
			if len(token.TokenHash) == sha256.Size && subtle.ConstantTimeCompare(provided[:], token.TokenHash) == 1 {
				if !s.externalAllowedLocked(record) {
					return User{}, false
				}
				return record.User, true
			}
		}
	}
	return User{}, false
}

func (s *Service) newPermanentTokenIDLocked() (string, error) {
	for attempt := 0; attempt < 4; attempt++ {
		var raw [permanentTokenIDBytes]byte
		if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
			return "", fmt.Errorf("generate permanent token ID: %w", err)
		}
		id := "pt-" + hex.EncodeToString(raw[:])
		if !s.permanentTokenIDExistsLocked(id) {
			return id, nil
		}
	}
	return "", errors.New("could not allocate a unique permanent token ID")
}

func (s *Service) permanentTokenIDExistsLocked(id string) bool {
	for _, record := range s.users {
		for _, token := range record.PermanentTokens {
			if token.ID == id {
				return true
			}
		}
	}
	return false
}

func validPermanentTokenID(id string) bool {
	if !strings.HasPrefix(id, "pt-") || len(id) != 3+permanentTokenIDBytes*2 {
		return false
	}
	decoded, err := hex.DecodeString(id[3:])
	return err == nil && len(decoded) == permanentTokenIDBytes
}
