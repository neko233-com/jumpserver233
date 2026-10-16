package groups

import (
	"crypto/rand"
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

	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

var (
	ErrNotFound     = errors.New("user group not found")
	ErrInvalidInput = errors.New("invalid user group input")
	ErrGroupExists  = errors.New("user group already exists")
)

type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	UserIDs     []string  `json:"user_ids"`
	CreatedAt   time.Time `json:"created_at"`
}

type Store struct {
	mu        sync.RWMutex
	path      string
	documents *storage.Documents
	groups    map[string]Group
}

func OpenStore(path string) (*Store, error) {
	return openStore(path, nil)
}

func OpenStoreWithDocuments(path string, documents *storage.Documents) (*Store, error) {
	if documents == nil {
		return nil, fmt.Errorf("shared state documents are required")
	}
	return openStore(path, documents)
}

func openStore(path string, documents *storage.Documents) (*Store, error) {
	store := &Store{path: path, documents: documents, groups: make(map[string]Group)}
	var data []byte
	var err error
	if documents != nil {
		data, err = documents.LoadOrImport("user-groups", path)
	} else {
		data, err = os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return store, nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("read user group store: %w", err)
	}
	if len(data) == 0 {
		return store, nil
	}
	var records []Group
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("decode user group store: %w", err)
	}
	for _, group := range records {
		if group.ID == "" || group.CreatedAt.IsZero() || validateName(group.Name, group.Description) != nil {
			return nil, fmt.Errorf("user group store contains an invalid record")
		}
		if _, exists := store.groups[group.ID]; exists {
			return nil, fmt.Errorf("user group store contains a duplicate ID")
		}
		if store.nameExistsLocked(group.Name, "") {
			return nil, fmt.Errorf("user group store contains a duplicate name")
		}
		if !validMembers(group.UserIDs) {
			return nil, fmt.Errorf("user group store contains invalid membership")
		}
		store.groups[group.ID] = cloneGroup(group)
	}
	return store, nil
}

func (s *Store) List() []Group {
	s.mu.RLock()
	result := make([]Group, 0, len(s.groups))
	for _, group := range s.groups {
		result = append(result, cloneGroup(group))
	}
	s.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool {
		if strings.EqualFold(result[i].Name, result[j].Name) {
			return result[i].ID < result[j].ID
		}
		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})
	return result
}

func (s *Store) Get(id string) (Group, error) {
	s.mu.RLock()
	group, exists := s.groups[id]
	s.mu.RUnlock()
	if !exists {
		return Group{}, ErrNotFound
	}
	return cloneGroup(group), nil
}

func (s *Store) Create(name, description string) (Group, error) {
	name = strings.TrimSpace(name)
	description = strings.TrimSpace(description)
	if err := validateName(name, description); err != nil {
		return Group{}, err
	}
	var rawID [16]byte
	if _, err := io.ReadFull(rand.Reader, rawID[:]); err != nil {
		return Group{}, fmt.Errorf("generate user group ID: %w", err)
	}
	group := Group{
		ID:          "group-" + hex.EncodeToString(rawID[:]),
		Name:        name,
		Description: description,
		UserIDs:     []string{},
		CreatedAt:   time.Now().UTC(),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nameExistsLocked(name, "") {
		return Group{}, ErrGroupExists
	}
	s.groups[group.ID] = group
	if err := s.persistLocked(); err != nil {
		delete(s.groups, group.ID)
		return Group{}, err
	}
	return cloneGroup(group), nil
}

func (s *Store) AddMember(groupID, userID string) (Group, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" || len(userID) > 128 {
		return Group{}, ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	group, exists := s.groups[groupID]
	if !exists {
		return Group{}, ErrNotFound
	}
	for _, existing := range group.UserIDs {
		if existing == userID {
			return cloneGroup(group), nil
		}
	}
	group.UserIDs = append(group.UserIDs, userID)
	sort.Strings(group.UserIDs)
	s.groups[groupID] = group
	if err := s.persistLocked(); err != nil {
		group.UserIDs = removeMember(group.UserIDs, userID)
		s.groups[groupID] = group
		return Group{}, err
	}
	return cloneGroup(group), nil
}

func (s *Store) RemoveMember(groupID, userID string) (Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	group, exists := s.groups[groupID]
	if !exists {
		return Group{}, ErrNotFound
	}
	previous := cloneGroup(group)
	group.UserIDs = removeMember(group.UserIDs, userID)
	s.groups[groupID] = group
	if err := s.persistLocked(); err != nil {
		s.groups[groupID] = previous
		return Group{}, err
	}
	return cloneGroup(group), nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	group, exists := s.groups[id]
	if !exists {
		return ErrNotFound
	}
	delete(s.groups, id)
	if err := s.persistLocked(); err != nil {
		s.groups[id] = group
		return err
	}
	return nil
}

func (s *Store) GroupIDsForUser(userID string) []string {
	s.mu.RLock()
	var ids []string
	for id, group := range s.groups {
		for _, memberID := range group.UserIDs {
			if memberID == userID {
				ids = append(ids, id)
				break
			}
		}
	}
	s.mu.RUnlock()
	sort.Strings(ids)
	return ids
}

func (s *Store) nameExistsLocked(name, excludingID string) bool {
	for id, group := range s.groups {
		if id != excludingID && strings.EqualFold(group.Name, name) {
			return true
		}
	}
	return false
}

func (s *Store) persistLocked() error {
	records := make([]Group, 0, len(s.groups))
	for _, group := range s.groups {
		records = append(records, cloneGroup(group))
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	data, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("encode user group store: %w", err)
	}
	if s.documents != nil {
		if err := s.documents.Save("user-groups", data); err != nil {
			return fmt.Errorf("persist shared user groups: %w", err)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create user group data directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".user-groups-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary user group store: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("protect temporary user group store: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary user group store: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary user group store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary user group store: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("replace user group store: %w", err)
	}
	return nil
}

func validateName(name, description string) error {
	if name == "" || len([]rune(name)) > 64 || len(description) > 256 {
		return ErrInvalidInput
	}
	return nil
}

func validMembers(userIDs []string) bool {
	seen := make(map[string]struct{}, len(userIDs))
	for _, userID := range userIDs {
		if userID == "" || len(userID) > 128 {
			return false
		}
		if _, exists := seen[userID]; exists {
			return false
		}
		seen[userID] = struct{}{}
	}
	return true
}

func removeMember(userIDs []string, userID string) []string {
	result := make([]string, 0, len(userIDs))
	for _, existing := range userIDs {
		if existing != userID {
			result = append(result, existing)
		}
	}
	return result
}

func cloneGroup(group Group) Group {
	group.UserIDs = append([]string(nil), group.UserIDs...)
	return group
}
