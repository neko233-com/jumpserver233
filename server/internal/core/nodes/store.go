package nodes

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
	ErrNotFound      = errors.New("asset node not found")
	ErrInvalidInput  = errors.New("invalid asset node input")
	ErrNodeExists    = errors.New("asset node already exists")
	ErrHasChildren   = errors.New("asset node has children")
	ErrInvalidParent = errors.New("invalid asset node parent")
)

type Node struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	ParentID  string    `json:"parent_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Store struct {
	mu        sync.RWMutex
	path      string
	documents *storage.Documents
	nodes     map[string]Node
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
	store := &Store{path: path, documents: documents, nodes: make(map[string]Node)}
	var data []byte
	var err error
	if documents != nil {
		data, err = documents.LoadOrImport("asset-nodes", path)
	} else {
		data, err = os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return store, nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("read asset node store: %w", err)
	}
	if len(data) == 0 {
		return store, nil
	}
	var records []Node
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("decode asset node store: %w", err)
	}
	for _, node := range records {
		node.Name = strings.TrimSpace(node.Name)
		node.ParentID = strings.TrimSpace(node.ParentID)
		if node.ID == "" || node.CreatedAt.IsZero() || node.UpdatedAt.IsZero() || validateName(node.Name) != nil {
			return nil, fmt.Errorf("asset node store contains an invalid record")
		}
		if _, exists := store.nodes[node.ID]; exists {
			return nil, fmt.Errorf("asset node store contains a duplicate ID")
		}
		for _, existing := range store.nodes {
			if existing.ParentID == node.ParentID && strings.EqualFold(existing.Name, node.Name) {
				return nil, fmt.Errorf("asset node store contains duplicate sibling names")
			}
		}
		store.nodes[node.ID] = node
	}
	for _, node := range store.nodes {
		if node.ParentID != "" {
			if _, exists := store.nodes[node.ParentID]; !exists {
				return nil, fmt.Errorf("asset node store contains a missing parent")
			}
		}
		if _, ok := ancestorIDs(store.nodes, node.ID); !ok {
			return nil, fmt.Errorf("asset node store contains a parent cycle")
		}
	}
	return store, nil
}

func (s *Store) List() []Node {
	s.mu.RLock()
	result := make([]Node, 0, len(s.nodes))
	for _, node := range s.nodes {
		result = append(result, node)
	}
	s.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool {
		if result[i].ParentID == result[j].ParentID {
			if strings.EqualFold(result[i].Name, result[j].Name) {
				return result[i].ID < result[j].ID
			}
			return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
		}
		return result[i].ParentID < result[j].ParentID
	})
	return result
}

func (s *Store) Get(id string) (Node, error) {
	s.mu.RLock()
	node, exists := s.nodes[id]
	s.mu.RUnlock()
	if !exists {
		return Node{}, ErrNotFound
	}
	return node, nil
}

func (s *Store) Create(name, parentID string) (Node, error) {
	name = strings.TrimSpace(name)
	parentID = strings.TrimSpace(parentID)
	if err := validateName(name); err != nil {
		return Node{}, err
	}
	var rawID [16]byte
	if _, err := io.ReadFull(rand.Reader, rawID[:]); err != nil {
		return Node{}, fmt.Errorf("generate asset node ID: %w", err)
	}
	now := time.Now().UTC()
	node := Node{ID: "node-" + hex.EncodeToString(rawID[:]), Name: name, ParentID: parentID, CreatedAt: now, UpdatedAt: now}

	s.mu.Lock()
	defer s.mu.Unlock()
	if parentID != "" {
		if _, exists := s.nodes[parentID]; !exists {
			return Node{}, ErrInvalidParent
		}
	}
	if s.nameExistsLocked(name, parentID, "") {
		return Node{}, ErrNodeExists
	}
	s.nodes[node.ID] = node
	if err := s.persistLocked(); err != nil {
		delete(s.nodes, node.ID)
		return Node{}, err
	}
	return node, nil
}

func (s *Store) Update(id, name, parentID string) (Node, error) {
	name = strings.TrimSpace(name)
	parentID = strings.TrimSpace(parentID)
	if err := validateName(name); err != nil {
		return Node{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, exists := s.nodes[id]
	if !exists {
		return Node{}, ErrNotFound
	}
	if parentID != "" {
		if _, exists := s.nodes[parentID]; !exists {
			return Node{}, ErrInvalidParent
		}
		ancestors, ok := ancestorIDs(s.nodes, parentID)
		if !ok {
			return Node{}, ErrInvalidParent
		}
		for _, ancestorID := range ancestors {
			if ancestorID == id {
				return Node{}, ErrInvalidParent
			}
		}
	}
	if s.nameExistsLocked(name, parentID, id) {
		return Node{}, ErrNodeExists
	}
	node := previous
	node.Name = name
	node.ParentID = parentID
	node.UpdatedAt = time.Now().UTC()
	s.nodes[id] = node
	if err := s.persistLocked(); err != nil {
		s.nodes[id] = previous
		return Node{}, err
	}
	return node, nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	node, exists := s.nodes[id]
	if !exists {
		return ErrNotFound
	}
	for _, candidate := range s.nodes {
		if candidate.ParentID == id {
			return ErrHasChildren
		}
	}
	delete(s.nodes, id)
	if err := s.persistLocked(); err != nil {
		s.nodes[id] = node
		return err
	}
	return nil
}

// AncestorIDs returns node IDs from the root through the specified node.
func (s *Store) AncestorIDs(id string) []string {
	s.mu.RLock()
	result, ok := ancestorIDs(s.nodes, id)
	s.mu.RUnlock()
	if !ok {
		return nil
	}
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result
}

func (s *Store) DescendantIDs(id string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, exists := s.nodes[id]; !exists {
		return nil
	}
	result := []string{id}
	for cursor := 0; cursor < len(result); cursor++ {
		for _, node := range s.nodes {
			if node.ParentID == result[cursor] {
				result = append(result, node.ID)
			}
		}
	}
	sort.Strings(result)
	return result
}

func (s *Store) HasChildren(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, node := range s.nodes {
		if node.ParentID == id {
			return true
		}
	}
	return false
}

func ancestorIDs(nodes map[string]Node, id string) ([]string, bool) {
	if _, exists := nodes[id]; !exists {
		return nil, false
	}
	seen := make(map[string]struct{}, len(nodes))
	result := make([]string, 0, 4)
	for id != "" {
		if _, exists := seen[id]; exists {
			return nil, false
		}
		seen[id] = struct{}{}
		node, exists := nodes[id]
		if !exists {
			return nil, false
		}
		result = append(result, id)
		id = node.ParentID
	}
	return result, true
}

func (s *Store) nameExistsLocked(name, parentID, excludingID string) bool {
	for id, node := range s.nodes {
		if id != excludingID && node.ParentID == parentID && strings.EqualFold(node.Name, name) {
			return true
		}
	}
	return false
}

func (s *Store) persistLocked() error {
	records := make([]Node, 0, len(s.nodes))
	for _, node := range s.nodes {
		records = append(records, node)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	data, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("encode asset node store: %w", err)
	}
	if s.documents != nil {
		if err := s.documents.Save("asset-nodes", data); err != nil {
			return fmt.Errorf("persist shared asset nodes: %w", err)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create asset node data directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".asset-nodes-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary asset node store: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("protect temporary asset node store: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary asset node store: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary asset node store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary asset node store: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("replace asset node store: %w", err)
	}
	return nil
}

func validateName(name string) error {
	if name == "" || len([]rune(name)) > 64 {
		return ErrInvalidInput
	}
	return nil
}
