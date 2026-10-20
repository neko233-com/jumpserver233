package assets

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrAccountDisabled = errors.New("managed account is disabled")
var ErrAccountInUse = errors.New("asset still owns managed accounts")
var ErrAccountDuplicate = errors.New("username is already managed on this asset")
var ErrAccountCapacity = errors.New("managed account activity is full")

const maxAccountAudit = 2000

type AccountActor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type AccountAudit struct {
	ImportID  string       `json:"import_id,omitempty"`
	At        time.Time    `json:"at"`
	Action    string       `json:"action"`
	Actor     AccountActor `json:"actor"`
	AccountID string       `json:"account_id"`
	Username  string       `json:"username"`
	Before    string       `json:"before,omitempty"`
	After     string       `json:"after,omitempty"`
}
type ManagedAccount struct {
	PAM                     *PAMSettings            `json:"pam,omitempty"`
	RemoteAccount           *RemoteAccountState     `json:"remote_account,omitempty"`
	ID                      string                  `json:"id"`
	AssetID                 string                  `json:"asset_id"`
	Name                    string                  `json:"name"`
	Username                string                  `json:"username"`
	Remark                  string                  `json:"remark"`
	DiscoveryID             string                  `json:"discovery_id,omitempty"`
	Default                 bool                    `json:"default"`
	Active                  bool                    `json:"active"`
	CredentialType          string                  `json:"credential_type"`
	CredentialRevision      uint64                  `json:"credential_revision"`
	KeyFingerprint          string                  `json:"key_fingerprint,omitempty"`
	Version                 string                  `json:"version"`
	PasswordRotationEnabled bool                    `json:"password_rotation_enabled"`
	KeyRotationEnabled      bool                    `json:"key_rotation_enabled"`
	PasswordRotation        *PasswordRotationStatus `json:"password_rotation,omitempty"`
	SSHKeyRotation          *SSHKeyRotationStatus   `json:"ssh_key_rotation,omitempty"`
	Permissions             []string                `json:"permissions"`
	CreatedAt               time.Time               `json:"created_at"`
	UpdatedAt               time.Time               `json:"updated_at"`
}
type AccountInput struct {
	PAM                     *PAMSettings `json:"pam,omitempty"`
	Name                    *string      `json:"name"`
	Username                string       `json:"username"`
	Remark                  *string      `json:"remark"`
	DiscoveryID             *string      `json:"discovery_id"`
	Active                  *bool        `json:"active"`
	PasswordRotationEnabled *bool        `json:"password_rotation_enabled"`
	KeyRotationEnabled      *bool        `json:"key_rotation_enabled"`
	CredentialType          string       `json:"credential_type"`
	Password                string       `json:"password"`
	PrivateKey              string       `json:"private_key"`
	PrivateKeyPassphrase    string       `json:"private_key_passphrase"`
	Version                 string       `json:"version"`
}

type AccountChoice struct {
	ID                 string                  `json:"id"`
	Name               string                  `json:"name"`
	Username           string                  `json:"username"`
	Default            bool                    `json:"default"`
	Active             bool                    `json:"active"`
	CredentialType     string                  `json:"credential_type"`
	KeyFingerprint     string                  `json:"key_fingerprint,omitempty"`
	CredentialRevision uint64                  `json:"credential_revision"`
	Permissions        []string                `json:"permissions"`
	PasswordRotation   *PasswordRotationStatus `json:"password_rotation,omitempty"`
	SSHKeyRotation     *SSHKeyRotationStatus   `json:"ssh_key_rotation,omitempty"`
}

func (s *Service) AccountAsset(parentID, id string) (Asset, error) {
	a, ok := s.find(id)
	if !ok || ResourceID(a) != parentID {
		return Asset{}, ErrNotFound
	}
	if !ManagedAccountsSupported(a) {
		return Asset{}, ErrUnsupportedProtocol
	}
	return a, nil
}

// AccountChoices snapshots metadata once for the whole inventory. It does not
// calculate vault history, status or version hashes for every poll.
func (s *Service) AccountChoices() map[string][]AccountChoice {
	groups := map[string][]AccountChoice{}
	for _, a := range s.store.List() {
		if !ManagedAccountsSupported(a) {
			continue
		}
		name := a.AccountName
		if name == "" {
			name = a.Username
		}
		id := ResourceID(a)
		groups[id] = append(groups[id], AccountChoice{ID: a.ID, Name: name, Username: a.Username, Default: a.ParentAssetID == "", Active: !a.AccountDisabled,
			CredentialType: credentialType(a.CredentialType), KeyFingerprint: a.KeyFingerprint, CredentialRevision: a.CredentialRevision, Permissions: []string{}})
	}
	for _, rows := range groups {
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].Default != rows[j].Default {
				return rows[i].Default
			}
			return rows[i].Username < rows[j].Username
		})
	}
	return groups
}

func (s *Service) ManagedAccount(parentID, id string) (ManagedAccount, error) {
	a, e := s.AccountAsset(parentID, id)
	if e != nil {
		return ManagedAccount{}, e
	}
	row := accountView(a)
	row.PasswordRotation = s.passwordRotationStatus(a)
	row.SSHKeyRotation = s.sshKeyRotationStatus(a)
	return row, nil
}

// ResourceID is the physical asset used by grants, nodes and access policies.
// ID remains the stable credential endpoint used by connectors and recordings.
func ResourceID(a Asset) string {
	if a.ParentAssetID != "" {
		return a.ParentAssetID
	}
	return a.ID
}
func accountVersion(a Asset) string {
	raw, _ := json.Marshal(a)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func accountText(v string, size int) bool {
	return len(v) <= size && utf8.ValidString(v) && strings.IndexFunc(v, unicode.IsControl) < 0
}
func validAccountActor(v AccountActor) bool {
	return v.ID != "" && v.Name != "" && accountText(v.ID, 128) && accountText(v.Name, 128)
}
func newAccountAudit(action string, actor AccountActor, a Asset, before, after string) AccountAudit {
	return AccountAudit{At: time.Now().UTC(), Action: action, Actor: actor, AccountID: a.ID, Username: a.Username, Before: before, After: after}
}

// Only account-owned fields are serialized for additional credential endpoints.
// Host/port, node, gateway and access-review configuration have one parent source.
func accountFields(a Asset) Asset {
	return Asset{PAM: clonePAM(a.PAM), RemoteAccount: cloneRemoteAccountState(a.RemoteAccount), ID: a.ID, ParentAssetID: a.ParentAssetID, AccountName: a.AccountName, AccountRemark: a.AccountRemark, AccountDiscoveryID: a.AccountDiscoveryID,
		Username: a.Username, AccountDisabled: a.AccountDisabled, PasswordRotationDisabled: a.PasswordRotationDisabled,
		CredentialType: a.CredentialType, CredentialRevision: a.CredentialRevision, KeyFingerprint: a.KeyFingerprint,
		KeyRotationEnabled: a.KeyRotationEnabled, KeyRotatedAt: a.KeyRotatedAt,
		CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt, PasswordRotatedAt: a.PasswordRotatedAt}
}
func inheritAccount(parent, account Asset) Asset {
	a := cloneAsset(parent)
	a.Discovery = nil
	v := accountFields(account)
	a.ID, a.ParentAssetID = v.ID, parent.ID
	a.AccountName, a.AccountRemark = v.AccountName, v.AccountRemark
	a.AccountDiscoveryID = v.AccountDiscoveryID
	a.RemoteAccount = cloneRemoteAccountState(v.RemoteAccount)
	a.PAM = clonePAM(v.PAM)
	if a.PAM == nil && parent.PAM != nil {
		a.PAM = &PAMSettings{Platform: parent.PAM.Platform}
	}
	a.Username, a.AccountDisabled, a.PasswordRotationDisabled = v.Username, v.AccountDisabled, v.PasswordRotationDisabled
	a.CredentialType, a.CredentialRevision, a.KeyFingerprint = v.CredentialType, v.CredentialRevision, v.KeyFingerprint
	a.KeyRotationEnabled, a.KeyRotatedAt = v.KeyRotationEnabled, v.KeyRotatedAt
	a.CreatedAt, a.UpdatedAt, a.PasswordRotatedAt = v.CreatedAt, v.UpdatedAt, v.PasswordRotatedAt
	return a
}
func persistedAsset(r storedAsset) storedAsset {
	if r.ParentAssetID != "" {
		r.Asset = accountFields(r.Asset)
	}
	return r
}
func (s *Store) materializeAccountsLocked() error {
	names := map[string]bool{}
	updates := map[string]storedAsset{}
	for id, r := range s.assets {
		if r.ParentAssetID != "" {
			parent, ok := s.assets[r.ParentAssetID]
			prefix := "account-" + r.ParentAssetID + "-"
			decoded, e := hex.DecodeString(strings.TrimPrefix(id, prefix))
			if !ok || parent.ParentAssetID != "" || !ManagedAccountsSupported(parent.Asset) || id == r.ParentAssetID || !strings.HasPrefix(id, prefix) || len(decoded) != 16 || e != nil || strings.ToLower(id) != id {
				return ErrInvalidInput
			}
			r.Asset = inheritAccount(parent.Asset, r.Asset)
			updates[id] = r
		}
		if !ManagedAccountsSupported(r.Asset) {
			continue
		}
		if e := validateProtocolAsset(r.Asset); e != nil {
			return e
		}
		if !IsSSH(r.Asset) && r.PendingKeyChange != nil || !SupportsPasswordRotation(r.Asset) && r.PendingRotation != nil {
			return ErrUnsupportedProtocol
		}
		key := accountNameKey(r.Asset)
		if names[key] {
			return ErrAccountDuplicate
		}
		names[key] = true
		if len(r.AccountAudit) > maxAccountAudit {
			return ErrAccountCapacity
		}
	}
	for id, r := range updates {
		s.assets[id] = r
	}
	return nil
}
func (s *Store) lookup(id string) (Asset, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.assets[id]
	return cloneAsset(r.Asset), ok
}
func (s *Service) accountChildrenBlocked(parentID string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.store.List() {
		if a.ParentAssetID != parentID {
			continue
		}
		if remoteAccountPending(a) {
			return ErrRemoteAccountPending
		}
		if s.rotationRunning[a.ID] {
			return ErrRotationInProgress
		}
		if s.store.HasPendingPasswordRotation(a.ID) || s.store.HasPendingSSHKeyChange(a.ID) {
			return ErrRotationPending
		}
		if c := s.passwordCoordinator; c != nil && c.blocked(s.passwordScope, a.ID) {
			return ErrRotationPending
		}
	}
	return nil
}
func accountView(a Asset) ManagedAccount {
	name := a.AccountName
	if name == "" {
		name = a.Username
	}
	return ManagedAccount{PAM: clonePAM(a.PAM), ID: a.ID, AssetID: ResourceID(a), Name: name, Username: a.Username, Remark: a.AccountRemark,
		RemoteAccount: cloneRemoteAccountState(a.RemoteAccount),
		DiscoveryID:   a.AccountDiscoveryID,
		Default:       a.ParentAssetID == "", Active: !a.AccountDisabled, Version: accountVersion(a),
		CredentialType: credentialType(a.CredentialType), CredentialRevision: a.CredentialRevision, KeyFingerprint: a.KeyFingerprint,
		PasswordRotationEnabled: !a.PasswordRotationDisabled, KeyRotationEnabled: a.KeyRotationEnabled,
		Permissions: []string{}, CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt}
}
func (s *Service) ManagedAccounts(id string) ([]ManagedAccount, error) {
	parent, ok := s.find(id)
	if !ok || parent.ParentAssetID != "" {
		return nil, ErrNotFound
	}
	if !ManagedAccountsSupported(parent) {
		return nil, ErrUnsupportedProtocol
	}
	rows := []ManagedAccount{}
	for _, a := range s.store.List() {
		if ResourceID(a) != id {
			continue
		}
		row := accountView(a)
		row.PasswordRotation = s.passwordRotationStatus(a)
		row.SSHKeyRotation = s.sshKeyRotationStatus(a)
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Default != rows[j].Default {
			return rows[i].Default
		}
		return rows[i].Username < rows[j].Username
	})
	return rows, nil
}
func normalizeAccountInput(a *Asset, in AccountInput) error {
	if in.PAM != nil {
		a.PAM = clonePAM(in.PAM)
	}
	if in.DiscoveryID != nil {
		value := *in.DiscoveryID
		decoded, e := hex.DecodeString(value)
		if value != "" && (e != nil || len(decoded) != 16 || strings.ToLower(value) != value) {
			return ErrInvalidInput
		}
		a.AccountDiscoveryID = value
	}
	if in.Name != nil {
		a.AccountName = strings.TrimSpace(*in.Name)
	}
	if in.Remark != nil {
		a.AccountRemark = *in.Remark
	}
	if in.Active != nil {
		a.AccountDisabled = !*in.Active
	}
	if in.PasswordRotationEnabled != nil {
		a.PasswordRotationDisabled = !*in.PasswordRotationEnabled
	}
	if !accountText(a.AccountName, 480) || utf8.RuneCountInString(a.AccountName) > 120 || !accountText(a.AccountRemark, 2048) || a.Username == "" || !accountText(a.Username, 128) || IsSSH(*a) && !WindowsPAM(*a) && strings.ContainsAny(a.Username, ":/\\ \t") {
		return ErrInvalidInput
	}
	if a.PAM != nil {
		candidate := *a
		if in.CredentialType != "" {
			candidate.CredentialType = in.CredentialType
		}
		if in.KeyRotationEnabled != nil {
			candidate.KeyRotationEnabled = *in.KeyRotationEnabled
		}
		if e := validatePAM(candidate); e != nil {
			return e
		}
	}
	return nil
}
func (s *Service) CreateManagedAccount(parentID string, in AccountInput, actor AccountActor) (ManagedAccount, error) {
	if !validAccountActor(actor) {
		return ManagedAccount{}, ErrInvalidInput
	}
	if c := s.passwordCoordinator; c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		defer c.refreshSharedLocked()
	}
	parent, ok := s.find(parentID)
	if !ok || parent.ParentAssetID != "" {
		return ManagedAccount{}, ErrNotFound
	}
	if !ManagedAccountsSupported(parent) {
		return ManagedAccount{}, ErrUnsupportedProtocol
	}
	if in.Version == "" || in.Version != accountVersion(parent) {
		return ManagedAccount{}, ErrCredentialChanged
	}
	id, e := newID()
	if e != nil {
		return ManagedAccount{}, e
	}
	now := time.Now().UTC()
	// The endpoint ID includes its parent so existing vault AAD also binds ownership.
	a := inheritAccount(parent, Asset{ID: "account-" + parentID + "-" + strings.TrimPrefix(id, "asset-"), ParentAssetID: parentID, Username: strings.TrimSpace(in.Username), CreatedAt: now, UpdatedAt: now, PasswordRotatedAt: now})
	if e := normalizeAccountInput(&a, in); e != nil {
		return ManagedAccount{}, e
	}
	ci := Input{CredentialType: in.CredentialType, Password: in.Password, PrivateKey: in.PrivateKey, PrivateKeyPassphrase: in.PrivateKeyPassphrase, KeyRotationEnabled: in.KeyRotationEnabled}
	kind, pin, credentials, e := inputCredential(ci, nil)
	if e != nil {
		return ManagedAccount{}, e
	}
	a.CredentialType, a.KeyFingerprint = kind, pin
	if e = applyKeyRotationPolicy(&a, ci, nil); e != nil {
		return ManagedAccount{}, e
	}
	if c := s.passwordCoordinator; c != nil {
		if e = c.validateMutation(s.passwordScope, a, credentials); e != nil {
			return ManagedAccount{}, e
		}
	}
	a, e = s.store.createCredentials(a, *credentials, in.Version, &actor)
	if e != nil {
		return ManagedAccount{}, e
	}
	return accountView(a), nil
}
func (s *Service) UpdateManagedAccount(parentID, id string, in AccountInput, actor AccountActor) (ManagedAccount, error) {
	if !validAccountActor(actor) {
		return ManagedAccount{}, ErrInvalidInput
	}
	if c := s.passwordCoordinator; c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		defer c.refreshSharedLocked()
		if c.blocked(s.passwordScope, id) {
			return ManagedAccount{}, ErrRotationPending
		}
	}
	current, ok := s.find(id)
	if !ok || ResourceID(current) != parentID {
		return ManagedAccount{}, ErrNotFound
	}
	if remoteAccountPending(current) || current.RemoteAccount != nil && current.RemoteAccount.State == "disabled" && in.Active != nil && *in.Active {
		return ManagedAccount{}, ErrRemoteAccountPending
	}
	if !ManagedAccountsSupported(current) || in.Username != "" && in.Username != current.Username {
		return ManagedAccount{}, ErrInvalidInput
	}
	if in.Version == "" || in.Version != accountVersion(current) {
		return ManagedAccount{}, ErrCredentialChanged
	}
	a := cloneAsset(current)
	if e := normalizeAccountInput(&a, in); e != nil {
		return ManagedAccount{}, e
	}
	ci := Input{CredentialType: in.CredentialType, Password: in.Password, PrivateKey: in.PrivateKey, PrivateKeyPassphrase: in.PrivateKeyPassphrase, KeyRotationEnabled: in.KeyRotationEnabled}
	kind, pin, credentials, e := inputCredential(ci, &current)
	if e != nil {
		return ManagedAccount{}, e
	}
	a.CredentialType, a.KeyFingerprint = kind, pin
	if e = applyKeyRotationPolicy(&a, ci, &current); e != nil {
		return ManagedAccount{}, e
	}
	a.UpdatedAt = time.Now().UTC()
	if c := s.passwordCoordinator; c != nil {
		if e = c.validateMutation(s.passwordScope, a, credentials); e != nil {
			return ManagedAccount{}, e
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rotationRunning[id] {
		return ManagedAccount{}, ErrRotationInProgress
	}
	a, e = s.store.updateCredentials(a, credentials, in.Version, &actor)
	if e != nil {
		return ManagedAccount{}, e
	}
	delete(s.rotationStatus, id)
	if a.AccountDisabled {
		delete(s.status, id)
		delete(s.last, id)
	}
	return accountView(a), nil
}

func (s *Service) DeleteManagedAccount(parentID, id, version string, actor AccountActor) error {
	if !validAccountActor(actor) || id == parentID {
		return ErrInvalidInput
	}
	if c := s.passwordCoordinator; c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		defer c.refreshSharedLocked()
		if c.blocked(s.passwordScope, id) {
			return ErrRotationPending
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rotationRunning[id] {
		return ErrRotationInProgress
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	r, ok := s.store.assets[id]
	parent, parentOK := s.store.assets[parentID]
	if !ok || !parentOK || r.ParentAssetID != parentID || parent.ParentAssetID != "" {
		return ErrNotFound
	}
	if remoteAccountPending(r.Asset) {
		return ErrRemoteAccountPending
	}
	if version == "" || accountVersion(r.Asset) != version {
		return ErrCredentialChanged
	}
	if r.PendingRotation != nil || r.PendingKeyChange != nil {
		return ErrRotationPending
	}
	for _, other := range s.store.assets {
		if other.GatewayID == id {
			return ErrGatewayInUse
		}
	}
	if len(parent.AccountAudit)+len(r.AccountAudit)+1 > maxAccountAudit {
		return ErrAccountCapacity
	}
	previousParent := parent
	parent.AccountAudit = append(append([]AccountAudit(nil), parent.AccountAudit...), r.AccountAudit...)
	parent.AccountAudit = append(parent.AccountAudit, newAccountAudit("deleted", actor, r.Asset, version, ""))
	s.store.assets[parentID] = parent
	delete(s.store.assets, id)
	if e := s.store.persistLocked(); e != nil {
		s.store.assets[parentID], s.store.assets[id] = previousParent, r
		return e
	}
	delete(s.status, id)
	delete(s.last, id)
	delete(s.rotationStatus, id)
	return nil
}

// AccountActivity returns safe metadata only. Passwords, notes and key bytes
// never enter these events; credential versions remain in the encrypted vault.
func (s *Service) AccountActivity(parentID, id string, offset, limit int) ([]AccountAudit, int, error) {
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	r, ok := s.store.assets[id]
	if !ok || ResourceID(r.Asset) != parentID {
		return nil, 0, ErrNotFound
	}
	if offset < 0 || offset > maxAccountAudit || limit < 1 || limit > 100 {
		return nil, 0, ErrInvalidInput
	}
	events := append([]AccountAudit(nil), r.AccountAudit...)
	sort.SliceStable(events, func(i, j int) bool { return events[i].At.After(events[j].At) })
	rows := []AccountAudit{}
	if offset < len(events) {
		rows = events[offset:min(offset+limit, len(events))]
	}
	return rows, len(r.AccountAudit), nil
}
