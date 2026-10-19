package commandfilters

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

var (
	ErrNotFound     = errors.New("command filter not found")
	ErrInvalidInput = errors.New("invalid command filter input")
)

const (
	ActionAllow  = "allow"
	ActionDeny   = "deny"
	ActionReview = "review"
	MatchExact   = "exact"
	MatchHas     = "contains"
	MatchRegex   = "regex"
)

type Filter struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	UserID           string     `json:"user_id,omitempty"`
	GroupID          string     `json:"group_id,omitempty"`
	AssetID          string     `json:"asset_id,omitempty"`
	NodeID           string     `json:"node_id,omitempty"`
	Account          string     `json:"account"`
	Match            string     `json:"match"`
	Pattern          string     `json:"pattern"`
	DirectoryMatch   string     `json:"directory_match,omitempty"`
	DirectoryPattern string     `json:"directory_pattern,omitempty"`
	Action           string     `json:"action"`
	Priority         int        `json:"priority"`
	StartsAt         *time.Time `json:"starts_at,omitempty"`
	EndsAt           *time.Time `json:"ends_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	CreatedBy        string     `json:"created_by"`
}

type Input struct {
	Name             string     `json:"name"`
	UserID           string     `json:"user_id,omitempty"`
	GroupID          string     `json:"group_id,omitempty"`
	AssetID          string     `json:"asset_id,omitempty"`
	NodeID           string     `json:"node_id,omitempty"`
	Account          string     `json:"account"`
	Match            string     `json:"match"`
	Pattern          string     `json:"pattern"`
	DirectoryMatch   string     `json:"directory_match,omitempty"`
	DirectoryPattern string     `json:"directory_pattern,omitempty"`
	Action           string     `json:"action"`
	Priority         int        `json:"priority"`
	StartsAt         *time.Time `json:"starts_at,omitempty"`
	EndsAt           *time.Time `json:"ends_at,omitempty"`
}

type Scope struct {
	UserID            string
	GroupIDs          []string
	AssetID           string
	NodeIDs           []string
	Account           string
	Directory         string
	DirectoryVerified bool
}

type Decision struct {
	Allowed           bool
	Action            string
	RuleID            string
	RuleName          string
	Reason            string
	PolicyKey         string
	DirectoryRequired bool
}

type Store struct {
	mu        sync.RWMutex
	path      string
	documents *storage.Documents
	filters   map[string]Filter
	regexps   map[string]*regexp.Regexp
}

func OpenStore(path string) (*Store, error) { return openStore(path, nil) }

func OpenStoreWithDocuments(path string, documents *storage.Documents) (*Store, error) {
	if documents == nil {
		return nil, fmt.Errorf("shared state documents are required")
	}
	return openStore(path, documents)
}

func openStore(path string, documents *storage.Documents) (*Store, error) {
	store := &Store{path: path, documents: documents, filters: make(map[string]Filter), regexps: make(map[string]*regexp.Regexp)}
	var data []byte
	var err error
	if documents != nil {
		data, err = documents.LoadOrImport("command-filters", path)
	} else {
		data, err = os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return store, nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("read command filter store: %w", err)
	}
	if len(data) == 0 {
		return store, nil
	}
	var records []Filter
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("decode command filter store: %w", err)
	}
	for _, filter := range records {
		directoryRE, directoryError := compileDirectory(filter.DirectoryMatch, filter.DirectoryPattern)
		if directoryError != nil {
			return nil, fmt.Errorf("command filter store contains an invalid directory rule")
		}
		if err := validateFilter(filter.Name, filter.UserID, filter.GroupID, filter.AssetID, filter.NodeID, filter.Account, filter.Match, filter.Pattern, filter.Action, filter.Priority, filter.StartsAt, filter.EndsAt); err != nil || filter.ID == "" || filter.CreatedAt.IsZero() {
			return nil, fmt.Errorf("command filter store contains an invalid record")
		}
		if _, exists := store.filters[filter.ID]; exists {
			return nil, fmt.Errorf("command filter store contains a duplicate ID")
		}
		compiled, err := compilePattern(filter.Match, filter.Pattern)
		if err != nil {
			return nil, fmt.Errorf("command filter store contains an invalid pattern")
		}
		store.filters[filter.ID] = cloneFilter(filter)
		if directoryRE != nil {
			store.regexps[filter.ID+"/directory"] = directoryRE
		}
		if compiled != nil {
			store.regexps[filter.ID] = compiled
		}
	}
	return store, nil
}

func (s *Store) List() []Filter {
	s.mu.RLock()
	filters := make([]Filter, 0, len(s.filters))
	for _, filter := range s.filters {
		filters = append(filters, cloneFilter(filter))
	}
	s.mu.RUnlock()
	sort.Slice(filters, func(i, j int) bool {
		if filters[i].Priority != filters[j].Priority {
			return filters[i].Priority < filters[j].Priority
		}
		if filters[i].CreatedAt.Equal(filters[j].CreatedAt) {
			return filters[i].ID < filters[j].ID
		}
		return filters[i].CreatedAt.Before(filters[j].CreatedAt)
	})
	return filters
}

func (s *Store) Create(input Input, createdBy string) (Filter, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.UserID = strings.TrimSpace(input.UserID)
	input.GroupID = strings.TrimSpace(input.GroupID)
	input.AssetID = strings.TrimSpace(input.AssetID)
	input.NodeID = strings.TrimSpace(input.NodeID)
	input.Account = strings.TrimSpace(input.Account)
	input.Pattern = strings.TrimSpace(input.Pattern)
	directoryRE, directoryError := compileDirectory(input.DirectoryMatch, input.DirectoryPattern)
	if directoryError != nil {
		return Filter{}, directoryError
	}
	if err := validateFilter(input.Name, input.UserID, input.GroupID, input.AssetID, input.NodeID, input.Account, input.Match, input.Pattern, input.Action, input.Priority, input.StartsAt, input.EndsAt); err != nil {
		return Filter{}, err
	}
	compiled, err := compilePattern(input.Match, input.Pattern)
	if err != nil {
		return Filter{}, fmt.Errorf("%w: invalid regular expression", ErrInvalidInput)
	}
	id, err := randomID()
	if err != nil {
		return Filter{}, err
	}
	now := time.Now().UTC()
	filter := Filter{
		ID: id, Name: input.Name, UserID: input.UserID, GroupID: input.GroupID,
		AssetID: input.AssetID, NodeID: input.NodeID, Account: input.Account,
		Match: input.Match, Pattern: input.Pattern, Action: input.Action, Priority: input.Priority,
		DirectoryMatch: input.DirectoryMatch, DirectoryPattern: input.DirectoryPattern,
		StartsAt: cloneTime(input.StartsAt), EndsAt: cloneTime(input.EndsAt), CreatedAt: now, CreatedBy: strings.TrimSpace(createdBy),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.filters[filter.ID] = filter
	if directoryRE != nil {
		s.regexps[filter.ID+"/directory"] = directoryRE
	}
	if compiled != nil {
		s.regexps[filter.ID] = compiled
	}
	if err := s.persistLocked(); err != nil {
		delete(s.filters, filter.ID)
		delete(s.regexps, filter.ID)
		delete(s.regexps, filter.ID+"/directory")
		return Filter{}, err
	}
	return cloneFilter(filter), nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	filter, exists := s.filters[id]
	if !exists {
		return ErrNotFound
	}
	delete(s.filters, id)
	delete(s.regexps, id)
	delete(s.regexps, id+"/directory")
	if err := s.persistLocked(); err != nil {
		s.filters[id] = filter
		if compiled, compileErr := compileDirectory(filter.DirectoryMatch, filter.DirectoryPattern); compileErr == nil && compiled != nil {
			s.regexps[id+"/directory"] = compiled
		}
		if compiled, compileErr := compilePattern(filter.Match, filter.Pattern); compileErr == nil && compiled != nil {
			s.regexps[id] = compiled
		}
		return err
	}
	return nil
}

// Decide evaluates the first active rule matching this user's session scope.
// Unknown terminal input is denied whenever any active rule applies to the
// session, because its command cannot be matched safely.
func (s *Store) Decide(scope Scope, command string, supported bool, at time.Time) Decision {
	s.mu.RLock()
	filters := make([]Filter, 0, len(s.filters))
	for _, filter := range s.filters {
		if matchesScope(filter, scope, at) {
			filters = append(filters, filter)
		}
	}
	sort.Slice(filters, func(i, j int) bool {
		if filters[i].Priority != filters[j].Priority {
			return filters[i].Priority < filters[j].Priority
		}
		if filters[i].CreatedAt.Equal(filters[j].CreatedAt) {
			return filters[i].ID < filters[j].ID
		}
		return filters[i].CreatedAt.Before(filters[j].CreatedAt)
	})
	defer s.mu.RUnlock()
	raw, _ := json.Marshal(filters)
	digest := sha256.Sum256(raw)
	policyKey := hex.EncodeToString(digest[:])
	if !supported && len(filters) > 0 {
		return Decision{Allowed: false, Action: ActionDeny, RuleID: filters[0].ID, RuleName: filters[0].Name, Reason: "unsupported terminal input", PolicyKey: policyKey}
	}
	for _, filter := range filters {
		if !matchesCommand(filter, s.regexps[filter.ID], command) {
			continue
		}
		if filter.DirectoryMatch != "" {
			if !scope.DirectoryVerified || !validDirectoryPath(scope.Directory) {
				return Decision{Action: ActionDeny, RuleID: filter.ID, RuleName: filter.Name, Reason: "working directory verification required", PolicyKey: policyKey, DirectoryRequired: true}
			}
			if !matchesDirectory(filter, s.regexps[filter.ID+"/directory"], scope.Directory) {
				continue
			}
		}
		return Decision{Allowed: filter.Action == ActionAllow, Action: filter.Action, RuleID: filter.ID, RuleName: filter.Name, Reason: "matched rule", PolicyKey: policyKey}
	}
	return Decision{Allowed: true, Action: ActionAllow, PolicyKey: policyKey}
}

func (s *Store) ReferencesGroup(groupID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, filter := range s.filters {
		if filter.GroupID == groupID {
			return true
		}
	}
	return false
}

func (s *Store) ReferencesNode(nodeID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, filter := range s.filters {
		if filter.NodeID == nodeID {
			return true
		}
	}
	return false
}

func (s *Store) persistLocked() error {
	filters := make([]Filter, 0, len(s.filters))
	for _, filter := range s.filters {
		filters = append(filters, cloneFilter(filter))
	}
	sort.Slice(filters, func(i, j int) bool { return filters[i].ID < filters[j].ID })
	data, err := json.Marshal(filters)
	if err != nil {
		return fmt.Errorf("encode command filter store: %w", err)
	}
	if s.documents != nil {
		if err := s.documents.Save("command-filters", data); err != nil {
			return fmt.Errorf("persist command filter document: %w", err)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create command filter directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".command-filters-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary command filter store: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("protect temporary command filter store: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary command filter store: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary command filter store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary command filter store: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("replace command filter store: %w", err)
	}
	return nil
}

func validateFilter(name, userID, groupID, assetID, nodeID, account, match, pattern, action string, priority int, startsAt, endsAt *time.Time) error {
	if name == "" || len(name) > 80 || (userID != "" && groupID != "") || len(userID) > 128 || len(groupID) > 128 || (assetID != "" && nodeID != "") || len(assetID) > 128 || len(nodeID) > 128 || account == "" || len(account) > 128 || len(pattern) == 0 || len(pattern) > 256 || priority < 0 || priority > 9999 {
		return fmt.Errorf("%w: invalid scope, name, account, pattern, or priority", ErrInvalidInput)
	}
	for _, value := range []string{name, account, pattern} {
		if strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return fmt.Errorf("%w: control characters are not allowed", ErrInvalidInput)
		}
	}
	if account != "*" && strings.ContainsAny(account, " \t\r\n") {
		return fmt.Errorf("%w: account must be an SSH account or *", ErrInvalidInput)
	}
	if match != MatchExact && match != MatchHas && match != MatchRegex {
		return fmt.Errorf("%w: unsupported match type", ErrInvalidInput)
	}
	if action != ActionAllow && action != ActionDeny && action != ActionReview {
		return fmt.Errorf("%w: unsupported action", ErrInvalidInput)
	}
	if startsAt != nil && endsAt != nil && !endsAt.After(*startsAt) {
		return fmt.Errorf("%w: end time must be after start time", ErrInvalidInput)
	}
	if _, err := compilePattern(match, pattern); err != nil {
		return fmt.Errorf("%w: invalid regular expression", ErrInvalidInput)
	}
	return nil
}

func compilePattern(match, pattern string) (*regexp.Regexp, error) {
	if match != MatchRegex {
		return nil, nil
	}
	return regexp.Compile(pattern)
}

func matchesScope(filter Filter, scope Scope, at time.Time) bool {
	if filter.UserID != "" && filter.UserID != scope.UserID {
		return false
	}
	if filter.GroupID != "" && !contains(scope.GroupIDs, filter.GroupID) {
		return false
	}
	if filter.AssetID != "" && filter.AssetID != scope.AssetID {
		return false
	}
	if filter.NodeID != "" && !contains(scope.NodeIDs, filter.NodeID) {
		return false
	}
	if filter.Account != "*" && filter.Account != scope.Account {
		return false
	}
	if filter.StartsAt != nil && at.Before(*filter.StartsAt) {
		return false
	}
	return filter.EndsAt == nil || at.Before(*filter.EndsAt)
}

func matchesCommand(filter Filter, compiled *regexp.Regexp, command string) bool {
	switch filter.Match {
	case MatchExact:
		return strings.TrimSpace(command) == filter.Pattern
	case MatchHas:
		return strings.Contains(command, filter.Pattern)
	case MatchRegex:
		return compiled != nil && compiled.MatchString(command)
	default:
		return false
	}
}

func contains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func cloneFilter(filter Filter) Filter {
	filter.StartsAt = cloneTime(filter.StartsAt)
	filter.EndsAt = cloneTime(filter.EndsAt)
	return filter
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := value.UTC()
	return &cloned
}

func randomID() (string, error) {
	var raw [16]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return "", fmt.Errorf("generate command filter ID: %w", err)
	}
	return "filter-" + hex.EncodeToString(raw[:]), nil
}
