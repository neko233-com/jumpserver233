package accessreviews

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

const (
	ActionSSH              = "ssh"
	ActionSFTP             = "sftp"
	ActionDatabase         = "database"
	ActionKubernetes       = "kubernetes"
	ActionTelnet           = "telnet"
	ActionRDP              = "rdp"
	ActionAccountDiscovery = "account_discovery"
	ActionAssetDiscovery   = "asset_discovery"
	ActionRemoteAccount    = "remote_account"
	StatePending           = "pending"
	StateApproved          = "approved"
	StateDenied            = "denied"
	StateExpired           = "expired"
	StateConsumed          = "consumed"

	requestLifetime = 5 * time.Minute
	permitLifetime  = time.Minute
	retention       = 7 * 24 * time.Hour
	maxRecords      = 5000
)

var (
	ErrNotFound   = errors.New("access review not found")
	ErrNotPending = errors.New("access review is no longer pending")
	ErrInvalid    = errors.New("invalid access review")
	ErrStoreFull  = errors.New("access review store is full")
)

// Review is safe to return to clients. It contains the request and decision
// history but no session ticket, credential, or approval permit.
type Review struct {
	ID           string     `json:"id"`
	UserID       string     `json:"user_id"`
	Operator     string     `json:"operator"`
	AssetID      string     `json:"asset_id"`
	AssetName    string     `json:"asset_name"`
	Account      string     `json:"account"`
	Action       string     `json:"action,omitempty"`
	RequestScope string     `json:"request_scope,omitempty"`
	Workspace    string     `json:"workspace,omitempty"`
	State        string     `json:"state"`
	RequestedAt  time.Time  `json:"requested_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	ReviewedAt   *time.Time `json:"reviewed_at,omitempty"`
	ReviewedBy   string     `json:"reviewed_by,omitempty"`
}

type record struct {
	Review
	PermitExpiresAt *time.Time `json:"permit_expires_at,omitempty"`
}

type Store struct {
	mu        sync.RWMutex
	path      string
	documents *storage.Documents
	records   map[string]record
}

func OpenStore(path string) (*Store, error) { return openStore(path, nil) }

func OpenStoreWithDocuments(path string, documents *storage.Documents) (*Store, error) {
	if documents == nil {
		return nil, fmt.Errorf("shared state documents are required")
	}
	return openStore(path, documents)
}

func openStore(path string, documents *storage.Documents) (*Store, error) {
	store := &Store{path: path, documents: documents, records: make(map[string]record)}
	var data []byte
	var err error
	if documents != nil {
		data, err = documents.LoadOrImport("access-reviews", path)
	} else {
		data, err = os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return store, nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("read access review store: %w", err)
	}
	if len(data) == 0 {
		return store, nil
	}
	var records []record
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("decode access review store: %w", err)
	}
	for _, item := range records {
		if item.Action == "" {
			item.Action = ActionSSH
		}
		if err := validate(item.Review); err != nil {
			return nil, fmt.Errorf("access review store contains an invalid record")
		}
		if item.State == StateApproved && (item.PermitExpiresAt == nil || item.ReviewedAt == nil || item.ReviewedBy == "") {
			return nil, fmt.Errorf("access review store contains an invalid approval")
		}
		if _, exists := store.records[item.ID]; exists {
			return nil, fmt.Errorf("access review store contains a duplicate ID")
		}
		store.records[item.ID] = cloneRecord(item)
	}
	return store, nil
}

// Request returns the pending request for the same operator and asset if one
// exists, making browser/CLI retries idempotent while an administrator decides.
func (s *Store) Request(userID, operator, assetID, assetName, account string) (Review, error) {
	return s.RequestAction(userID, operator, assetID, assetName, account, ActionSSH)
}

// RequestAction creates or reuses a pending request for one access method.
// SSH and SFTP approvals are deliberately independent even for the same asset account.
func (s *Store) RequestAction(userID, operator, assetID, assetName, account, action string) (Review, error) {
	return s.RequestScopedAction(userID, operator, assetID, assetName, account, action, "")
}
func (s *Store) RequestScopedAction(userID, operator, assetID, assetName, account, action, scope string) (Review, error) {
	if !validScope(action, scope) {
		return Review{}, ErrInvalid
	}
	userID = strings.TrimSpace(userID)
	operator = strings.TrimSpace(operator)
	assetID = strings.TrimSpace(assetID)
	assetName = strings.TrimSpace(assetName)
	account = strings.TrimSpace(account)
	action = strings.TrimSpace(action)
	now := time.Now().UTC()
	if userID == "" || operator == "" || assetID == "" || assetName == "" || account == "" || !validAction(action) {
		return Review{}, ErrInvalid
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := cloneRecords(s.records)
	changed := expireAndPrune(candidate, now)
	for _, item := range candidate {
		if item.UserID == userID && item.AssetID == assetID && item.Account == account && item.Action == action && item.RequestScope == scope && item.State == StatePending {
			if changed {
				if err := s.persistLocked(candidate); err != nil {
					return Review{}, err
				}
				s.records = candidate
			}
			return cloneReview(item.Review), nil
		}
	}
	if len(candidate) >= maxRecords {
		return Review{}, ErrStoreFull
	}
	id, err := newID()
	if err != nil {
		return Review{}, err
	}
	review := Review{
		ID: id, UserID: userID, Operator: operator, AssetID: assetID,
		AssetName: assetName, Account: account, Action: action, RequestScope: scope, State: StatePending,
		RequestedAt: now, ExpiresAt: now.Add(requestLifetime),
	}
	if connection, err := ParseConnectionScope(scope); err == nil {
		review.Workspace = connection.Workspace
	}
	candidate[id] = record{Review: review}
	if err := s.persistLocked(candidate); err != nil {
		return Review{}, err
	}
	s.records = candidate
	return cloneReview(review), nil
}

func (s *Store) ListPending() ([]Review, error) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := cloneRecords(s.records)
	if expireAndPrune(candidate, now) {
		if err := s.persistLocked(candidate); err != nil {
			return nil, err
		}
		s.records = candidate
	}
	results := make([]Review, 0)
	for _, item := range candidate {
		if item.State == StatePending {
			results = append(results, cloneReview(item.Review))
		}
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].RequestedAt.Equal(results[j].RequestedAt) {
			return results[i].ID < results[j].ID
		}
		return results[i].RequestedAt.Before(results[j].RequestedAt)
	})
	return results, nil
}

func (s *Store) Get(id string) (Review, error) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := cloneRecords(s.records)
	if expireAndPrune(candidate, now) {
		if err := s.persistLocked(candidate); err != nil {
			return Review{}, err
		}
		s.records = candidate
	}
	item, exists := candidate[id]
	if !exists {
		return Review{}, ErrNotFound
	}
	return cloneReview(item.Review), nil
}

func (s *Store) Resolve(id, reviewer string, approve bool) error {
	reviewer = strings.TrimSpace(reviewer)
	if id == "" || reviewer == "" {
		return ErrInvalid
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := cloneRecords(s.records)
	changed := expireAndPrune(candidate, now)
	item, exists := candidate[id]
	if !exists {
		if changed {
			if err := s.persistLocked(candidate); err != nil {
				return err
			}
			s.records = candidate
		}
		return ErrNotFound
	}
	if item.State != StatePending {
		if changed {
			if err := s.persistLocked(candidate); err != nil {
				return err
			}
			s.records = candidate
		}
		return ErrNotPending
	}
	item.State = StateDenied
	if approve {
		item.State = StateApproved
		permitExpiry := now.Add(permitLifetime)
		item.PermitExpiresAt = &permitExpiry
	}
	reviewedAt := now
	item.ReviewedAt = &reviewedAt
	item.ReviewedBy = reviewer
	candidate[id] = item
	if err := s.persistLocked(candidate); err != nil {
		return err
	}
	s.records = candidate
	return nil
}

// ConsumeApproved grants one login attempt to the exact user, asset, and
// account tuple. The permit is consumed before the SSH connector is opened.
func (s *Store) ConsumeApproved(userID, assetID, account string) (bool, error) {
	return s.ConsumeApprovedAction(userID, assetID, account, ActionSSH)
}

// ConsumeApprovedAction consumes a single permit for the exact user, asset,
// account, and access method tuple.
func (s *Store) ConsumeApprovedAction(userID, assetID, account, action string) (bool, error) {
	return s.ConsumeApprovedScopedAction(userID, assetID, account, action, "")
}
func (s *Store) ConsumeApprovedScopedAction(userID, assetID, account, action, scope string) (bool, error) {
	if !validScope(action, scope) {
		return false, ErrInvalid
	}
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(assetID) == "" || strings.TrimSpace(account) == "" || !validAction(action) {
		return false, ErrInvalid
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := cloneRecords(s.records)
	changed := expireAndPrune(candidate, now)
	var selected *record
	for _, item := range candidate {
		if item.UserID != userID || item.AssetID != assetID || item.Account != account || item.Action != action || item.RequestScope != scope || item.State != StateApproved || item.PermitExpiresAt == nil || !now.Before(*item.PermitExpiresAt) {
			continue
		}
		copy := item
		if selected == nil || copy.RequestedAt.Before(selected.RequestedAt) {
			selected = &copy
		}
	}
	if selected == nil {
		if changed {
			if err := s.persistLocked(candidate); err != nil {
				return false, err
			}
			s.records = candidate
		}
		return false, nil
	}
	item := candidate[selected.ID]
	item.State = StateConsumed
	item.PermitExpiresAt = nil
	candidate[selected.ID] = item
	if err := s.persistLocked(candidate); err != nil {
		return false, err
	}
	s.records = candidate
	return true, nil
}

func (s *Store) persistLocked(records map[string]record) error {
	items := make([]record, 0, len(records))
	for _, item := range records {
		items = append(items, cloneRecord(item))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	data, err := json.Marshal(items)
	if err != nil {
		return fmt.Errorf("encode access review store: %w", err)
	}
	if s.documents != nil {
		if err := s.documents.Save("access-reviews", data); err != nil {
			return fmt.Errorf("persist access review document: %w", err)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create access review directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".access-reviews-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary access review store: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("protect temporary access review store: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary access review store: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary access review store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary access review store: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("replace access review store: %w", err)
	}
	return nil
}

func expireAndPrune(records map[string]record, now time.Time) bool {
	changed := false
	for id, item := range records {
		if item.State == StatePending && !now.Before(item.ExpiresAt) {
			item.State = StateExpired
			changed = true
		}
		if item.State == StateApproved && (item.PermitExpiresAt == nil || !now.Before(*item.PermitExpiresAt)) {
			item.State = StateExpired
			item.PermitExpiresAt = nil
			changed = true
		}
		retainedSince := item.ExpiresAt
		if item.ReviewedAt != nil {
			retainedSince = *item.ReviewedAt
		}
		if item.State != StatePending && now.Sub(retainedSince) > retention {
			delete(records, id)
			changed = true
			continue
		}
		records[id] = item
	}
	return changed
}

func validate(review Review) error {
	if review.ID == "" || review.UserID == "" || review.Operator == "" || review.AssetID == "" || review.AssetName == "" || review.Account == "" || review.RequestedAt.IsZero() || review.ExpiresAt.IsZero() || !review.ExpiresAt.After(review.RequestedAt) {
		return ErrInvalid
	}
	if !validAction(review.Action) || !validScope(review.Action, review.RequestScope) {
		return ErrInvalid
	}
	if strings.HasPrefix(review.RequestScope, "cx1-") {
		connection, err := ParseConnectionScope(review.RequestScope)
		if err != nil || connection.Workspace != review.Workspace {
			return ErrInvalid
		}
	} else if review.Workspace != "" {
		return ErrInvalid
	}
	switch review.State {
	case StatePending, StateApproved, StateDenied, StateExpired, StateConsumed:
	default:
		return ErrInvalid
	}
	if (review.State == StateApproved || review.State == StateDenied || review.State == StateConsumed) && (review.ReviewedAt == nil || review.ReviewedBy == "") {
		return ErrInvalid
	}
	return nil
}

func validAction(action string) bool {
	return action == ActionSSH || action == ActionSFTP || action == ActionDatabase || action == ActionKubernetes || action == ActionTelnet || action == ActionRDP || action == ActionAccountDiscovery || action == ActionRemoteAccount || action == ActionAssetDiscovery
}

func validScope(action, scope string) bool {
	if action == ActionSSH || action == ActionSFTP {
		if scope == "" { // Read legacy records; new API requests always bind scope.
			return true
		}
		_, err := ParseConnectionScope(scope)
		return err == nil
	}
	if action == ActionAssetDiscovery {
		if !strings.HasPrefix(scope, "ad-") || len(scope) != 67 || strings.ToLower(scope) != scope {
			return false
		}
		_, e := hex.DecodeString(scope[3:])
		return e == nil
	}
	if action != ActionAccountDiscovery && action != ActionRemoteAccount {
		return scope == ""
	}
	prefix := "plan-"
	if action == ActionRemoteAccount {
		prefix = "ra-"
	}
	if len(scope) > 100 || !strings.HasPrefix(scope, prefix) {
		return false
	}
	parts := strings.Split(scope, ":")
	if len(parts) != 2 || len(parts[0]) != len(prefix)+32 {
		return false
	}
	if _, e := hex.DecodeString(parts[0][len(prefix):]); e != nil {
		return false
	}
	n, e := strconv.ParseUint(parts[1], 10, 53)
	return e == nil && n > 0 && strconv.FormatUint(n, 10) == parts[1]
}

// CancelOwned expires only this operator's pending request or unused permit.
// It is idempotent, including requests already expired or pruned.
func (s *Store) CancelOwned(id, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.records[id]
	if !ok {
		return nil
	}
	if item.UserID != userID {
		return ErrNotFound
	}
	if item.State != StatePending && item.State != StateApproved {
		return nil
	}
	candidate := cloneRecords(s.records)
	item.State = StateExpired
	item.PermitExpiresAt = nil
	item.ExpiresAt = time.Now().UTC()
	if !item.ExpiresAt.After(item.RequestedAt) {
		item.ExpiresAt = item.RequestedAt.Add(time.Nanosecond)
	}
	candidate[id] = item
	if e := s.persistLocked(candidate); e != nil {
		return e
	}
	s.records = candidate
	return nil
}

func cloneRecords(records map[string]record) map[string]record {
	result := make(map[string]record, len(records))
	for id, item := range records {
		result[id] = cloneRecord(item)
	}
	return result
}

func cloneRecord(item record) record {
	item.Review = cloneReview(item.Review)
	if item.PermitExpiresAt != nil {
		value := *item.PermitExpiresAt
		item.PermitExpiresAt = &value
	}
	return item
}

func cloneReview(review Review) Review {
	if review.ReviewedAt != nil {
		value := *review.ReviewedAt
		review.ReviewedAt = &value
	}
	return review
}

func newID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate access review ID: %w", err)
	}
	return "access-review-" + hex.EncodeToString(raw[:]), nil
}
