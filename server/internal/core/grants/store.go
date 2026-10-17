package grants

import (
	"crypto/rand"
	"encoding/hex"
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
	ErrNotFound     = errors.New("grant not found")
	ErrInvalidInput = errors.New("invalid grant input")
)

var allowedActions = map[string]struct{}{
	"view": {}, "connect": {}, "sftp": {},
}

type Grant struct {
	SourceTicketID string     `json:"source_ticket_id,omitempty"`
	ID             string     `json:"id"`
	UserID         string     `json:"user_id"`
	GroupID        string     `json:"group_id,omitempty"`
	AssetID        string     `json:"asset_id"`
	NodeID         string     `json:"node_id,omitempty"`
	Account        string     `json:"account"`
	Actions        []string   `json:"actions"`
	StartsAt       *time.Time `json:"starts_at,omitempty"`
	EndsAt         *time.Time `json:"ends_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	CreatedBy      string     `json:"created_by"`
}

type Input struct {
	UserID   string     `json:"user_id"`
	GroupID  string     `json:"group_id,omitempty"`
	AssetID  string     `json:"asset_id"`
	NodeID   string     `json:"node_id,omitempty"`
	Account  string     `json:"account"`
	Actions  []string   `json:"actions"`
	StartsAt *time.Time `json:"starts_at,omitempty"`
	EndsAt   *time.Time `json:"ends_at,omitempty"`
}

type Store struct {
	mu          sync.RWMutex
	path        string
	documents   *storage.Documents
	grants      map[string]Grant
	tickets     map[string]ticketBatch
	ticketGuard func(Grant, time.Time) bool
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
	store := &Store{path: path, documents: documents, grants: make(map[string]Grant), tickets: map[string]ticketBatch{}}
	var data []byte
	var err error
	if documents != nil {
		data, err = documents.LoadOrImport("grants", path)
	} else {
		data, err = os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return store, nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("read grant store: %w", err)
	}
	if len(data) == 0 {
		return store, nil
	}
	var records []Grant
	if err := store.decodeRecords(data, &records); err != nil {
		return nil, fmt.Errorf("decode grant store: %w", err)
	}
	for _, grant := range records {
		if err := validateGrant(grant.UserID, grant.GroupID, grant.AssetID, grant.NodeID, grant.Account, grant.Actions, grant.StartsAt, grant.EndsAt); err != nil || grant.ID == "" || grant.CreatedAt.IsZero() {
			return nil, fmt.Errorf("grant store contains an invalid record")
		}
		if _, exists := store.grants[grant.ID]; exists {
			return nil, fmt.Errorf("grant store contains a duplicate ID")
		}
		store.grants[grant.ID] = cloneGrant(grant)
	}
	if err := store.validateTickets(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) List() []Grant {
	s.mu.RLock()
	grants := make([]Grant, 0, len(s.grants))
	for _, grant := range s.grants {
		grants = append(grants, cloneGrant(grant))
	}
	s.mu.RUnlock()
	sort.Slice(grants, func(i, j int) bool {
		if grants[i].CreatedAt.Equal(grants[j].CreatedAt) {
			return grants[i].ID < grants[j].ID
		}
		return grants[i].CreatedAt.After(grants[j].CreatedAt)
	})
	return grants
}

func (s *Store) Create(input Input, createdBy string) (Grant, error) {
	actions, err := normalizeActions(input.Actions)
	if err != nil {
		return Grant{}, err
	}
	userID := strings.TrimSpace(input.UserID)
	groupID := strings.TrimSpace(input.GroupID)
	assetID := strings.TrimSpace(input.AssetID)
	nodeID := strings.TrimSpace(input.NodeID)
	account := strings.TrimSpace(input.Account)
	if err := validateGrant(userID, groupID, assetID, nodeID, account, actions, input.StartsAt, input.EndsAt); err != nil {
		return Grant{}, err
	}
	var rawID [16]byte
	if _, err := io.ReadFull(rand.Reader, rawID[:]); err != nil {
		return Grant{}, fmt.Errorf("generate grant ID: %w", err)
	}
	grant := Grant{
		ID:        "grant-" + hex.EncodeToString(rawID[:]),
		UserID:    userID,
		GroupID:   groupID,
		AssetID:   assetID,
		NodeID:    nodeID,
		Account:   account,
		Actions:   actions,
		StartsAt:  cloneTime(input.StartsAt),
		EndsAt:    cloneTime(input.EndsAt),
		CreatedAt: time.Now().UTC(),
		CreatedBy: strings.TrimSpace(createdBy),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.grants[grant.ID] = grant
	if err := s.persistLocked(); err != nil {
		delete(s.grants, grant.ID)
		return Grant{}, err
	}
	return cloneGrant(grant), nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, exists := s.grants[id]
	if !exists {
		return ErrNotFound
	}
	delete(s.grants, id)
	if err := s.persistLocked(); err != nil {
		s.grants[id] = previous
		return err
	}
	return nil
}

func (s *Store) Actions(userID, assetID, account string, at time.Time) []string {
	return s.ActionsFor(userID, nil, assetID, account, at)
}

func (s *Store) ActionsFor(userID string, groupIDs []string, assetID, account string, at time.Time) []string {
	return s.ActionsForScopes(userID, groupIDs, assetID, nil, account, at)
}

// ActionsForScopes combines direct asset grants with grants on any ancestor
// node. nodeIDs should include the asset's node and each parent up to the root.
func (s *Store) ActionsForScopes(userID string, groupIDs []string, assetID string, nodeIDs []string, account string, at time.Time) []string {
	groupSet := make(map[string]struct{}, len(groupIDs))
	for _, groupID := range groupIDs {
		groupSet[groupID] = struct{}{}
	}
	nodeSet := make(map[string]struct{}, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		nodeSet[nodeID] = struct{}{}
	}
	s.mu.RLock()
	actions := make(map[string]struct{})
	for _, grant := range s.grants {
		_, groupMatch := groupSet[grant.GroupID]
		_, nodeMatch := nodeSet[grant.NodeID]
		scopeMatch := grant.AssetID != "" && grant.AssetID == assetID || grant.NodeID != "" && nodeMatch
		if (grant.UserID != userID && !groupMatch) || !scopeMatch || grant.Account != account || !withinWindow(grant, at) {
			continue
		}
		if grant.SourceTicketID != "" && (s.ticketGuard == nil || !s.ticketGuard(cloneGrant(grant), at)) {
			continue
		}
		for _, action := range grant.Actions {
			actions[action] = struct{}{}
		}
	}
	s.mu.RUnlock()
	if _, canConnect := actions["connect"]; canConnect {
		actions["view"] = struct{}{}
	}
	result := make([]string, 0, len(actions))
	for action := range actions {
		result = append(result, action)
	}
	sort.Strings(result)
	return result
}

func (s *Store) Allows(userID, assetID, account, action string, at time.Time) bool {
	for _, granted := range s.Actions(userID, assetID, account, at) {
		if granted == action {
			return true
		}
	}
	return false
}

func (s *Store) AllowsFor(userID string, groupIDs []string, assetID, account, action string, at time.Time) bool {
	for _, granted := range s.ActionsFor(userID, groupIDs, assetID, account, at) {
		if granted == action {
			return true
		}
	}
	return false
}

func (s *Store) AllowsForScopes(userID string, groupIDs []string, assetID string, nodeIDs []string, account, action string, at time.Time) bool {
	for _, granted := range s.ActionsForScopes(userID, groupIDs, assetID, nodeIDs, account, at) {
		if granted == action {
			return true
		}
	}
	return false
}

func (s *Store) ReferencesGroup(groupID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, grant := range s.grants {
		if grant.GroupID == groupID {
			return true
		}
	}
	return false
}

func (s *Store) ReferencesNode(nodeID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, grant := range s.grants {
		if grant.NodeID == nodeID {
			return true
		}
	}
	return false
}

func (s *Store) persistLocked() error {
	if s.documents != nil {
		grants := make([]Grant, 0, len(s.grants))
		for _, grant := range s.grants {
			grants = append(grants, cloneGrant(grant))
		}
		sort.Slice(grants, func(i, j int) bool { return grants[i].ID < grants[j].ID })
		data, err := s.encodeRecords(grants, false)
		if err != nil {
			return fmt.Errorf("encode grant document: %w", err)
		}
		if err := s.documents.Save("grants", data); err != nil {
			return fmt.Errorf("persist grant document: %w", err)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create grant data directory: %w", err)
	}
	grants := make([]Grant, 0, len(s.grants))
	for _, grant := range s.grants {
		grants = append(grants, cloneGrant(grant))
	}
	sort.Slice(grants, func(i, j int) bool { return grants[i].ID < grants[j].ID })
	data, err := s.encodeRecords(grants, true)
	if err != nil {
		return fmt.Errorf("encode grant store: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".grants-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary grant store: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("protect temporary grant store: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary grant store: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary grant store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary grant store: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("replace grant store: %w", err)
	}
	return nil
}

func normalizeActions(actions []string) ([]string, error) {
	unique := make(map[string]struct{})
	for _, action := range actions {
		action = strings.TrimSpace(action)
		if _, allowed := allowedActions[action]; !allowed {
			return nil, fmt.Errorf("%w: unsupported action", ErrInvalidInput)
		}
		unique[action] = struct{}{}
	}
	if len(unique) == 0 {
		return nil, fmt.Errorf("%w: at least one action is required", ErrInvalidInput)
	}
	if _, canConnect := unique["connect"]; canConnect {
		unique["view"] = struct{}{}
	}
	if _, canTransfer := unique["sftp"]; canTransfer {
		unique["view"] = struct{}{}
	}
	result := make([]string, 0, len(unique))
	for action := range unique {
		result = append(result, action)
	}
	sort.Strings(result)
	return result, nil
}

func validateGrant(userID, groupID, assetID, nodeID, account string, actions []string, startsAt, endsAt *time.Time) error {
	validSubject := (userID == "") != (groupID == "")
	validScope := (assetID == "") != (nodeID == "")
	if !validSubject || !validScope || len(userID) > 128 || len(groupID) > 128 || len(assetID) > 128 || len(nodeID) > 128 || account == "" || len(account) > 128 {
		return fmt.Errorf("%w: exactly one user or group, asset or node, and account are required", ErrInvalidInput)
	}
	if _, err := normalizeActions(actions); err != nil {
		return err
	}
	if startsAt != nil && endsAt != nil && !startsAt.Before(*endsAt) {
		return fmt.Errorf("%w: grant end must be after grant start", ErrInvalidInput)
	}
	return nil
}

func withinWindow(grant Grant, at time.Time) bool {
	if grant.StartsAt != nil && at.Before(*grant.StartsAt) {
		return false
	}
	return grant.EndsAt == nil || at.Before(*grant.EndsAt)
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneGrant(grant Grant) Grant {
	grant.Actions = append([]string(nil), grant.Actions...)
	grant.StartsAt = cloneTime(grant.StartsAt)
	grant.EndsAt = cloneTime(grant.EndsAt)
	return grant
}
