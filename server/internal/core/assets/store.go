package assets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/core/credentialpolicy"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/kubeclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/rdpclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/telnetclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/sshcertificates"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

var (
	ErrNotFound                 = errors.New("asset not found")
	ErrRotationPending          = errors.New("asset password rotation is pending")
	ErrNoPendingRotation        = errors.New("asset has no pending password rotation")
	ErrCredentialBackupNotFound = errors.New("credential backup not found")
	ErrCredentialBackupLimit    = errors.New("credential backup limit reached")
)

const maxCredentialBackups = 10

// Asset contains non-secret inventory fields. Credential material is encrypted
// separately and never appears in API representations.
type Asset struct {
	PAM                      *PAMSettings           `json:"pam,omitempty"`
	SSHWorkspace             string                 `json:"ssh_workspace,omitempty"`
	Discovery                *DiscoveryOrigin       `json:"discovery,omitempty"`
	RemoteAccount            *RemoteAccountState    `json:"remote_account,omitempty"`
	ParentAssetID            string                 `json:"parent_asset_id,omitempty"`
	AccountName              string                 `json:"account_name,omitempty"`
	AccountRemark            string                 `json:"account_remark,omitempty"`
	AccountDiscoveryID       string                 `json:"account_discovery_id,omitempty"`
	AccountDisabled          bool                   `json:"account_disabled,omitempty"`
	PasswordRotationDisabled bool                   `json:"password_rotation_disabled,omitempty"`
	RDP                      *rdpclient.Settings    `json:"rdp,omitempty"`
	Telnet                   *telnetclient.Settings `json:"telnet,omitempty"`
	Kubernetes               *kubeclient.Settings   `json:"kubernetes,omitempty"`
	Protocol                 string                 `json:"protocol,omitempty"`
	PostgreSQL               *sqlclient.Settings    `json:"postgresql,omitempty"`
	MySQL                    *sqlclient.Settings    `json:"mysql,omitempty"`
	SQLServer                *sqlclient.Settings    `json:"sqlserver,omitempty"`
	ClickHouse               *sqlclient.Settings    `json:"clickhouse,omitempty"`
	Redis                    *sqlclient.Settings    `json:"redis,omitempty"`
	MongoDB                  *sqlclient.Settings    `json:"mongodb,omitempty"`
	CredentialRevision       uint64                 `json:"credential_revision"`
	KeyRotationEnabled       bool                   `json:"key_rotation_enabled,omitempty"`
	KeyRotatedAt             time.Time              `json:"key_rotated_at,omitempty"`
	GatewayID                string                 `json:"gateway_id,omitempty"`
	GatewayIDs               []string               `json:"-"`
	CredentialType           string                 `json:"credential_type,omitempty"`
	KeyFingerprint           string                 `json:"key_fingerprint,omitempty"`
	ID                       string                 `json:"id"`
	Name                     string                 `json:"name"`
	Host                     string                 `json:"host"`
	Group                    string                 `json:"group"`
	NodeID                   string                 `json:"node_id,omitempty"`
	Username                 string                 `json:"username"`
	HostKeyFingerprint       string                 `json:"host_key_fingerprint"`
	Port                     int                    `json:"port"`
	Remark                   string                 `json:"remark"`
	LoginReviewRequired      bool                   `json:"login_review_required,omitempty"`
	CreatedAt                time.Time              `json:"created_at"`
	UpdatedAt                time.Time              `json:"updated_at"`
	PasswordRotatedAt        time.Time              `json:"-"`
}

// Input is the create/update payload. Password is write-only.
type Input struct {
	PAM                  *PAMSettings           `json:"pam,omitempty"`
	SSHWorkspace         *string                `json:"ssh_workspace,omitempty"`
	RDP                  *rdpclient.Settings    `json:"rdp,omitempty"`
	Telnet               *telnetclient.Settings `json:"telnet,omitempty"`
	Kubernetes           *kubeclient.Settings   `json:"kubernetes,omitempty"`
	Protocol             string                 `json:"protocol,omitempty"`
	PostgreSQL           *PostgreSQLInput       `json:"postgresql,omitempty"`
	MySQL                *PostgreSQLInput       `json:"mysql,omitempty"`
	SQLServer            *PostgreSQLInput       `json:"sqlserver,omitempty"`
	ClickHouse           *PostgreSQLInput       `json:"clickhouse,omitempty"`
	Redis                *PostgreSQLInput       `json:"redis,omitempty"`
	MongoDB              *PostgreSQLInput       `json:"mongodb,omitempty"`
	KeyRotationEnabled   *bool                  `json:"key_rotation_enabled,omitempty"`
	CredentialType       string                 `json:"credential_type,omitempty"`
	PrivateKey           string                 `json:"private_key,omitempty"`
	PrivateKeyPassphrase string                 `json:"private_key_passphrase,omitempty"`
	GatewayID            *string                `json:"gateway_id,omitempty"`
	Name                 string                 `json:"name"`
	Host                 string                 `json:"host"`
	Group                string                 `json:"group"`
	NodeID               string                 `json:"node_id,omitempty"`
	Username             string                 `json:"username"`
	HostKeyFingerprint   string                 `json:"host_key_fingerprint"`
	Password             string                 `json:"password"`
	Port                 int                    `json:"port"`
	Remark               string                 `json:"remark"`
	LoginReviewRequired  *bool                  `json:"login_review_required,omitempty"`
}

type encryptedSecret struct {
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

type storedAsset struct {
	PlannedPasswordReceipt *plannedPasswordReceipt `json:"planned_password_receipt,omitempty"`
	RemoteOperations       []RemoteAccountTask     `json:"remote_operations,omitempty"`
	AccountAudit           []AccountAudit          `json:"account_audit,omitempty"`
	PendingKeyChange       *pendingKeyChange       `json:"pending_key_change,omitempty"`
	KeyLastAttemptAt       time.Time               `json:"key_last_attempt_at,omitempty"`
	KeyLastError           string                  `json:"key_last_error,omitempty"`
	LastKeyRequestID       string                  `json:"last_key_request_id,omitempty"`
	LastKeyRequestRevision uint64                  `json:"last_key_request_revision,omitempty"`
	LastKeyResult          string                  `json:"last_key_result,omitempty"`
	Asset
	Credential            encryptedSecret    `json:"credential"`
	CredentialBackups     []credentialBackup `json:"credential_backups,omitempty"`
	PendingRotation       *pendingRotation   `json:"pending_rotation,omitempty"`
	PasswordRotatedAt     time.Time          `json:"password_rotated_at"`
	RotationLastAttemptAt time.Time          `json:"rotation_last_attempt_at,omitempty"`
	RotationState         string             `json:"rotation_state,omitempty"`
	RotationErrorCode     string             `json:"rotation_error_code,omitempty"`
}

type credentialBackup struct {
	CredentialType string          `json:"credential_type,omitempty"`
	KeyFingerprint string          `json:"key_fingerprint,omitempty"`
	ID             string          `json:"id"`
	CreatedAt      time.Time       `json:"created_at"`
	Credential     encryptedSecret `json:"credential"`
}

// CredentialBackup is safe to return to clients; it never contains credential material.
type CredentialBackup struct {
	CredentialType string    `json:"credential_type,omitempty"`
	KeyFingerprint string    `json:"key_fingerprint,omitempty"`
	ID             string    `json:"backup_id"`
	CreatedAt      time.Time `json:"created_at"`
}

type pendingRotation struct {
	Planned    *plannedPasswordIntent `json:"planned,omitempty"`
	Credential encryptedSecret        `json:"credential"`
	StartedAt  time.Time              `json:"started_at"`
	Trigger    string                 `json:"trigger,omitempty"`
	Actor      string                 `json:"actor,omitempty"`
	BackupID   string                 `json:"backup_id,omitempty"`
}

// Store persists assets and AES-GCM-encrypted credentials in a single-user
// standalone file. The key is supplied separately from the data file.
type Store struct {
	certificates       *sshcertificates.Store
	passwordPolicy     *credentialpolicy.Store
	admission          *workgate.Gate
	mu                 sync.RWMutex
	path               string
	documents          *storage.Documents
	aead               cipher.AEAD
	assets             map[string]storedAsset
	imports            []accountImportRecord
	importKey          []byte
	discoveryUncertain bool
	discoveryStaging   bool // private in-memory transaction; never exposed by OpenStore
}

func OpenStore(path string, key []byte) (*Store, error) {
	return openStore(path, key, nil)
}

func OpenStoreWithDocuments(path string, key []byte, documents *storage.Documents) (*Store, error) {
	if documents == nil {
		return nil, fmt.Errorf("shared state documents are required")
	}
	return openStore(path, key, documents)
}

func openStore(path string, key []byte, documents *storage.Documents) (*Store, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("vault key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create vault cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create vault AEAD: %w", err)
	}
	return openStoreWithCipher(path, aead, accountImportKey(key), documents)
}
func openStoreWithCipher(path string, aead cipher.AEAD, importKey []byte, documents *storage.Documents) (*Store, error) {
	store := &Store{path: path, documents: documents, aead: aead, assets: make(map[string]storedAsset), importKey: append([]byte(nil), importKey...)}
	var data []byte
	var err error
	if documents != nil {
		data, err = documents.LoadOrImport("assets", path)
	} else {
		data, err = os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return store, nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("read asset store: %w", err)
	}
	if len(data) == 0 {
		return store, nil
	}
	var records []storedAsset
	if err := decodeRemoteAssetRecords(data, &records, &store.imports); err != nil {
		return nil, fmt.Errorf("decode asset store: %w", err)
	}
	migrated := false
	for _, record := range records {
		if e := validatePlannedRotationRecord(record); e != nil {
			return nil, e
		}
		if err := validateRemoteAssetRecord(record); err != nil {
			return nil, err
		}
		if record.ParentAssetID == "" {
			if err := validateProtocolAsset(record.Asset); err != nil {
				return nil, err
			}
		}
		if record.ParentAssetID == "" && (!IsSSH(record.Asset) && record.PendingKeyChange != nil || !SupportsPasswordRotation(record.Asset) && record.PendingRotation != nil) {
			return nil, ErrUnsupportedProtocol
		}
		if record.ID == "" || record.Credential.Nonce == nil || record.Credential.Ciphertext == nil {
			return nil, fmt.Errorf("asset store contains an incomplete record")
		}
		plain, err := aead.Open(nil, record.Credential.Nonce, record.Credential.Ciphertext, credentialAAD(record.ID, record.CredentialType, ""))
		if err != nil || validateCredential(record.CredentialType, record.KeyFingerprint, plain) != nil {
			return nil, fmt.Errorf("asset store cannot be opened with this vault key")
		}
		if record.PendingRotation != nil {
			pending := record.PendingRotation
			if pending.StartedAt.IsZero() || pending.Credential.Nonce == nil || pending.Credential.Ciphertext == nil {
				return nil, fmt.Errorf("asset store contains an incomplete password rotation")
			}
			plaintext, err := aead.Open(nil, pending.Credential.Nonce, pending.Credential.Ciphertext, []byte(record.ID))
			if err != nil || len(plaintext) == 0 {
				return nil, fmt.Errorf("asset store contains an invalid pending credential")
			}
			if pending.Planned != nil {
				if pending.Trigger != "planned" || pending.Actor != pending.Planned.Actor.ID || pending.BackupID != "" {
					return nil, ErrInvalidInput
				}
			} else if pending.Trigger == "credential_restore" {
				if pending.Actor == "" || len(pending.Actor) > 128 || !validCredentialBackupID(pending.BackupID) {
					return nil, fmt.Errorf("asset store contains incomplete credential restore metadata")
				}
			} else if pending.Trigger != "" || pending.Actor != "" || pending.BackupID != "" {
				return nil, fmt.Errorf("asset store contains invalid password rotation metadata")
			}
		}
		if len(record.CredentialBackups) > maxCredentialBackups {
			return nil, fmt.Errorf("asset store contains too many credential backups")
		}
		seenBackupIDs := make(map[string]struct{}, len(record.CredentialBackups))
		for _, backup := range record.CredentialBackups {
			if !validCredentialBackupID(backup.ID) || backup.CreatedAt.IsZero() || len(backup.Credential.Nonce) != aead.NonceSize() || len(backup.Credential.Ciphertext) < aead.Overhead() {
				return nil, fmt.Errorf("asset store contains an incomplete credential backup")
			}
			if _, duplicate := seenBackupIDs[backup.ID]; duplicate {
				return nil, fmt.Errorf("asset store contains duplicate credential backup IDs")
			}
			seenBackupIDs[backup.ID] = struct{}{}
			plaintext, err := aead.Open(nil, backup.Credential.Nonce, backup.Credential.Ciphertext, credentialAAD(record.ID, backup.CredentialType, backup.ID))
			if err != nil || validateCredential(backup.CredentialType, backup.KeyFingerprint, plaintext) != nil {
				return nil, fmt.Errorf("asset store contains an invalid credential backup")
			}
		}
		if record.PasswordRotatedAt.IsZero() {
			record.PasswordRotatedAt = record.CreatedAt
			if record.PasswordRotatedAt.IsZero() {
				record.PasswordRotatedAt = time.Now().UTC()
			}
			migrated = true
		}
		if record.CredentialRevision == 0 {
			record.CredentialRevision = 1
			migrated = true
		}
		if credentialType(record.CredentialType) == CredentialSSHKey && record.KeyRotatedAt.IsZero() {
			record.KeyRotatedAt = record.PasswordRotatedAt
			migrated = true
		}
		if record.PendingKeyChange != nil {
			if _, _, e := store.openKeyChange(record); e != nil {
				return nil, fmt.Errorf("invalid SSH key change journal")
			}
		}
		record.Asset.PasswordRotatedAt = record.PasswordRotatedAt
		if _, duplicate := store.assets[record.ID]; duplicate {
			return nil, fmt.Errorf("duplicate asset or account ID")
		}
		store.assets[record.ID] = record
	}
	if err := store.materializeAccountsLocked(); err != nil {
		return nil, err
	}
	if err := store.validateGatewaysLocked(); err != nil {
		return nil, err
	}
	if migrated {
		if err := store.persistLocked(); err != nil {
			return nil, err
		}
	}
	return store, nil
}

func (s *Store) List() []Asset {
	s.mu.RLock()
	assets := make([]Asset, 0, len(s.assets))
	for _, record := range s.assets {
		assets = append(assets, cloneAsset(record.Asset))
	}
	s.mu.RUnlock()
	sort.Slice(assets, func(i, j int) bool {
		if assets[i].Group == assets[j].Group {
			return assets[i].Name < assets[j].Name
		}
		return assets[i].Group < assets[j].Group
	})
	return assets
}

func (s *Store) Create(asset Asset, password string) (Asset, error) {
	return s.CreateCredentials(asset, sshclient.Credentials{Password: password})
}
func (s *Store) CreateCredentials(asset Asset, c sshclient.Credentials) (Asset, error) {
	return s.createCredentials(asset, c, "", nil)
}
func (s *Store) createCredentials(asset Asset, c sshclient.Credentials, parentVersion string, actor *AccountActor) (Asset, error) {
	asset = cloneAsset(asset)
	if e := validateProtocolAsset(asset); e != nil {
		return Asset{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.assets[asset.ID]; ok {
		return Asset{}, fmt.Errorf("asset ID already exists")
	}
	if err := s.remoteAccountCopyAllowedLocked(asset); err != nil {
		return Asset{}, err
	}
	if asset.ParentAssetID != "" {
		parent, ok := s.assets[asset.ParentAssetID]
		if !ok || parentVersion == "" || accountVersion(parent.Asset) != parentVersion {
			return Asset{}, ErrCredentialChanged
		}
	}
	asset.CredentialRevision = 1
	secret, e := s.sealCredentials(&asset, c)
	if e != nil {
		return Asset{}, e
	}
	if asset.PasswordRotatedAt.IsZero() {
		asset.PasswordRotatedAt = asset.CreatedAt
		if asset.PasswordRotatedAt.IsZero() {
			asset.PasswordRotatedAt = time.Now().UTC()
		}
	}
	if asset.CredentialType == CredentialSSHKey {
		asset.KeyRotatedAt = asset.PasswordRotatedAt
	}
	s.assets[asset.ID] = storedAsset{Asset: asset, Credential: secret, PasswordRotatedAt: asset.PasswordRotatedAt}
	if actor != nil {
		r := s.assets[asset.ID]
		r.AccountAudit = []AccountAudit{newAccountAudit("created", *actor, asset, "", accountVersion(asset))}
		s.assets[asset.ID] = r
	}
	if e = s.materializeAccountsLocked(); e != nil {
		delete(s.assets, asset.ID)
		return Asset{}, e
	}
	if e = s.validateGatewaysLocked(); e != nil {
		delete(s.assets, asset.ID)
		return Asset{}, e
	}
	if e = s.persistLocked(); e != nil {
		delete(s.assets, asset.ID)
		return Asset{}, e
	}
	return cloneAsset(asset), nil
}

func (s *Store) Update(asset Asset, password string) (Asset, error) {
	var replacement *sshclient.Credentials
	if password != "" {
		replacement = &sshclient.Credentials{Password: password}
		asset.CredentialType = CredentialPassword
		asset.KeyFingerprint = ""
	}
	return s.UpdateCredentials(asset, replacement)
}
func (s *Store) UpdateCredentials(asset Asset, replacement *sshclient.Credentials) (Asset, error) {
	return s.updateCredentials(asset, replacement, "", nil)
}
func (s *Store) updateCredentials(asset Asset, replacement *sshclient.Credentials, version string, actor *AccountActor) (Asset, error) {
	asset = cloneAsset(asset)
	if e := validateProtocolAsset(asset); e != nil {
		return Asset{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, ok := s.assets[asset.ID]
	if !ok {
		return Asset{}, ErrNotFound
	}
	if err := s.remoteAccountCopyAllowedLocked(asset); err != nil {
		return Asset{}, err
	}
	if previous.ParentAssetID != asset.ParentAssetID || version != "" && accountVersion(previous.Asset) != version {
		return Asset{}, ErrCredentialChanged
	}
	if actor != nil && len(previous.AccountAudit) >= maxAccountAudit {
		return Asset{}, ErrAccountCapacity
	}
	if Protocol(asset) != Protocol(previous.Asset) {
		return Asset{}, ErrUnsupportedProtocol
	}
	if previous.PendingKeyChange != nil {
		return Asset{}, ErrSSHKeyPending
	}
	if previous.PendingRotation != nil {
		return Asset{}, ErrRotationPending
	}
	asset.CreatedAt = previous.CreatedAt
	asset.PasswordRotatedAt = previous.PasswordRotatedAt
	record := previous
	if replacement != nil {
		if _, e := s.snapshotCredentialLocked(asset.ID, &record, time.Now().UTC(), true); e != nil {
			return Asset{}, e
		}
		secret, e := s.sealCredentials(&asset, *replacement)
		if e != nil {
			return Asset{}, e
		}
		revision, e := nextCredentialRevision(previous.Asset)
		if e != nil {
			return Asset{}, e
		}
		asset.CredentialRevision = revision
		if asset.CredentialType == CredentialSSHKey {
			asset.KeyRotatedAt = time.Now().UTC()
		} else {
			asset.KeyRotatedAt = time.Time{}
			asset.KeyRotationEnabled = false
		}
		record.Credential = secret
		record.PasswordRotatedAt = time.Now().UTC()
		asset.PasswordRotatedAt = record.PasswordRotatedAt
		record.RotationLastAttemptAt = time.Time{}
		record.RotationState = "scheduled"
		record.RotationErrorCode = ""
	} else {
		asset.CredentialType = previous.CredentialType
		asset.KeyFingerprint = previous.KeyFingerprint
		asset.CredentialRevision = previous.CredentialRevision
		asset.KeyRotatedAt = previous.KeyRotatedAt
	}
	record.Asset = asset
	if actor != nil {
		record.AccountAudit = append(append([]AccountAudit(nil), previous.AccountAudit...), newAccountAudit("updated", *actor, asset, accountVersion(previous.Asset), accountVersion(asset)))
	}
	s.assets[asset.ID] = record
	if e := s.materializeAccountsLocked(); e != nil {
		s.assets[asset.ID] = previous
		_ = s.materializeAccountsLocked()
		return Asset{}, e
	}
	if e := s.validateGatewaysLocked(); e != nil {
		s.assets[asset.ID] = previous
		_ = s.materializeAccountsLocked()
		return Asset{}, e
	}
	if e := s.persistLocked(); e != nil {
		s.assets[asset.ID] = previous
		_ = s.materializeAccountsLocked()
		return Asset{}, e
	}
	return cloneAsset(asset), nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, exists := s.assets[id]
	if !exists {
		return ErrNotFound
	}
	if previous.PendingKeyChange != nil {
		return ErrSSHKeyPending
	}
	if previous.PendingRotation != nil {
		return ErrRotationPending
	}
	for _, r := range s.assets {
		if r.ParentAssetID == id {
			return ErrAccountInUse
		}
		if r.GatewayID == id {
			return ErrGatewayInUse
		}
	}
	delete(s.assets, id)
	if err := s.persistLocked(); err != nil {
		s.assets[id] = previous
		return err
	}
	return nil
}

func (s *Store) Password(id string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.assets[id]
	if !ok {
		return "", ErrNotFound
	}
	if credentialType(record.CredentialType) != CredentialPassword {
		return "", ErrCredentialType
	}
	plain, e := s.aead.Open(nil, record.Credential.Nonce, record.Credential.Ciphertext, []byte(id))
	if e != nil {
		return "", e
	}
	return string(plain), nil
}

func (s *Store) CreateCredentialBackup(id string, createdAt time.Time) (CredentialBackup, error) {
	if createdAt.IsZero() {
		return CredentialBackup{}, fmt.Errorf("credential backup time is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.assets[id]
	if !exists {
		return CredentialBackup{}, ErrNotFound
	}
	if record.PendingKeyChange != nil {
		return CredentialBackup{}, ErrSSHKeyPending
	}
	if record.PendingRotation != nil {
		return CredentialBackup{}, ErrRotationPending
	}
	previous := record
	metadata, err := s.snapshotCredentialLocked(id, &record, createdAt.UTC(), false)
	if err != nil {
		return CredentialBackup{}, err
	}
	s.assets[id] = record
	if err := s.persistLocked(); err != nil {
		s.assets[id] = previous
		return CredentialBackup{}, err
	}
	return metadata, nil
}

func (s *Store) ListCredentialBackups(id string) ([]CredentialBackup, error) {
	s.mu.RLock()
	record, exists := s.assets[id]
	if !exists {
		s.mu.RUnlock()
		return nil, ErrNotFound
	}
	backups := make([]CredentialBackup, 0, len(record.CredentialBackups))
	for _, backup := range record.CredentialBackups {
		backups = append(backups, backupMetadata(backup))
	}
	s.mu.RUnlock()
	sort.Slice(backups, func(i, j int) bool {
		if backups[i].CreatedAt.Equal(backups[j].CreatedAt) {
			return backups[i].ID > backups[j].ID
		}
		return backups[i].CreatedAt.After(backups[j].CreatedAt)
	})
	return backups, nil
}

func (s *Store) CredentialBackupPassword(id, backupID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, c, e := s.backupCredentialsLocked(id, backupID)
	if e != nil {
		return "", e
	}
	if credentialType(b.CredentialType) != CredentialPassword {
		return "", ErrCredentialType
	}
	return c.Password, nil
}

func (s *Store) DeleteCredentialBackup(id, backupID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.assets[id]
	if !exists {
		return ErrNotFound
	}
	if record.PendingKeyChange != nil {
		return ErrSSHKeyPending
	}
	if record.PendingRotation != nil {
		return ErrRotationPending
	}
	for index, backup := range record.CredentialBackups {
		if backup.ID != backupID {
			continue
		}
		previous := record
		record.CredentialBackups = append(append([]credentialBackup(nil), record.CredentialBackups[:index]...), record.CredentialBackups[index+1:]...)
		s.assets[id] = record
		if err := s.persistLocked(); err != nil {
			s.assets[id] = previous
			return err
		}
		return nil
	}
	return ErrCredentialBackupNotFound
}

func (s *Store) BeginPasswordRotation(id, newPassword string, startedAt time.Time) error {
	return s.beginPasswordRotation(id, newPassword, startedAt, "", "", "")
}

func (s *Store) BeginCredentialRestore(id, newPassword string, startedAt time.Time, actor, backupID string) error {
	if actor == "" || len(actor) > 128 || !validCredentialBackupID(backupID) {
		return fmt.Errorf("invalid credential restore metadata")
	}
	return s.beginPasswordRotation(id, newPassword, startedAt, "credential_restore", actor, backupID)
}

func (s *Store) beginPasswordRotation(id, newPassword string, startedAt time.Time, trigger, actor, backupID string, planned ...*plannedPasswordIntent) error {
	if newPassword == "" || startedAt.IsZero() {
		return fmt.Errorf("password and rotation time are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.assets[id]
	if !exists {
		return ErrNotFound
	}
	if record.PendingKeyChange != nil {
		return ErrSSHKeyPending
	}
	if record.PendingRotation != nil {
		return ErrRotationPending
	}
	var intent *plannedPasswordIntent
	if len(planned) > 0 {
		intent = planned[0]
		if !validPlannedPassword(intent) || backupID != "" || credentialType(record.CredentialType) != CredentialPassword {
			return ErrInvalidInput
		}
		if record.CredentialRevision != intent.Revision || accountVersion(record.Asset) != intent.Version || record.AccountDisabled {
			return ErrCredentialChanged
		}
		trigger, actor = "planned", intent.Actor.ID
	}
	if trigger == "" && credentialType(record.CredentialType) != CredentialPassword {
		return ErrCredentialType
	}
	credential, err := s.seal(id, newPassword)
	if err != nil {
		return err
	}
	record.PendingRotation = &pendingRotation{Credential: credential, StartedAt: startedAt.UTC(), Trigger: trigger, Actor: actor, BackupID: backupID, Planned: intent}
	s.assets[id] = record
	if err := s.persistLocked(); err != nil {
		record.PendingRotation = nil
		s.assets[id] = record
		return err
	}
	return nil
}

func (s *Store) PendingRotationAuditMetadata(id string) (trigger, actor, backupID string, err error) {
	s.mu.RLock()
	record, exists := s.assets[id]
	s.mu.RUnlock()
	if !exists {
		return "", "", "", ErrNotFound
	}
	if record.PendingRotation == nil {
		return "", "", "", ErrNoPendingRotation
	}
	return record.PendingRotation.Trigger, record.PendingRotation.Actor, record.PendingRotation.BackupID, nil
}

func (s *Store) PasswordRotationAttemptStatus(id string) (time.Time, string, string, error) {
	s.mu.RLock()
	record, exists := s.assets[id]
	s.mu.RUnlock()
	if !exists {
		return time.Time{}, "", "", ErrNotFound
	}
	return record.RotationLastAttemptAt, record.RotationState, record.RotationErrorCode, nil
}

func (s *Store) RecordPasswordRotationAttempt(id string, attemptedAt time.Time, state string) error {
	if attemptedAt.IsZero() || (state != "rotating" && state != "recovery_required") {
		return fmt.Errorf("invalid password rotation attempt")
	}
	return s.updatePasswordRotationRecord(id, func(record *storedAsset) {
		record.RotationLastAttemptAt = attemptedAt.UTC()
		record.RotationState = state
		record.RotationErrorCode = ""
	})
}

func (s *Store) SetPasswordRotationResult(id, state, errorCode string) error {
	if (state != "scheduled" && state != "failed" && state != "recovery_required") || len(errorCode) > 80 {
		return fmt.Errorf("invalid password rotation result")
	}
	return s.updatePasswordRotationRecord(id, func(record *storedAsset) {
		record.RotationState = state
		record.RotationErrorCode = errorCode
	})
}

func (s *Store) updatePasswordRotationRecord(id string, update func(*storedAsset)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.assets[id]
	if !exists {
		return ErrNotFound
	}
	previous := record
	update(&record)
	s.assets[id] = record
	if err := s.persistLocked(); err != nil {
		s.assets[id] = previous
		return err
	}
	return nil
}

func (s *Store) HasPendingPasswordRotation(id string) bool {
	s.mu.RLock()
	record, exists := s.assets[id]
	pending := exists && record.PendingRotation != nil
	s.mu.RUnlock()
	return pending
}

func (s *Store) PendingPassword(id string) (string, error) {
	s.mu.RLock()
	record, exists := s.assets[id]
	s.mu.RUnlock()
	if !exists {
		return "", ErrNotFound
	}
	if record.PendingRotation == nil {
		return "", ErrNoPendingRotation
	}
	secret, err := s.aead.Open(nil, record.PendingRotation.Credential.Nonce, record.PendingRotation.Credential.Ciphertext, []byte(id))
	if err != nil {
		return "", fmt.Errorf("decrypt pending SSH credential: %w", err)
	}
	return string(secret), nil
}

func (s *Store) CommitPasswordRotation(id string, rotatedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.assets[id]
	if !exists {
		return ErrNotFound
	}
	if record.PendingRotation == nil {
		return ErrNoPendingRotation
	}
	previous := record
	if _, err := s.snapshotCredentialLocked(id, &record, rotatedAt.UTC(), true); err != nil {
		return err
	}
	revision, e := nextCredentialRevision(record.Asset)
	if e != nil {
		return e
	}
	record.CredentialRevision = revision
	record.KeyRotationEnabled = false
	record.KeyRotatedAt = time.Time{}
	record.Credential = record.PendingRotation.Credential
	record.CredentialType = CredentialPassword
	record.KeyFingerprint = ""
	if p := record.PendingRotation.Planned; p != nil {
		record.PlannedPasswordReceipt = &plannedPasswordReceipt{plannedPasswordIntent: *p, State: "succeeded", AfterRevision: record.CredentialRevision, At: rotatedAt.UTC()}
	}
	record.PendingRotation = nil
	record.PasswordRotatedAt = rotatedAt.UTC()
	record.Asset.PasswordRotatedAt = record.PasswordRotatedAt
	record.RotationState = "scheduled"
	record.RotationErrorCode = ""
	s.assets[id] = record
	if err := s.persistLocked(); err != nil {
		s.assets[id] = previous
		return err
	}
	return nil
}

func (s *Store) AbortPasswordRotation(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.assets[id]
	if !exists {
		return ErrNotFound
	}
	if record.PendingRotation == nil {
		return ErrNoPendingRotation
	}
	previous := record
	if p := record.PendingRotation.Planned; p != nil {
		record.PlannedPasswordReceipt = &plannedPasswordReceipt{plannedPasswordIntent: *p, State: "failed", AfterRevision: record.CredentialRevision, At: time.Now().UTC()}
	}
	record.PendingRotation = nil
	s.assets[id] = record
	if err := s.persistLocked(); err != nil {
		s.assets[id] = previous
		return err
	}
	return nil
}

func (s *Store) seal(id, password string) (encryptedSecret, error) {
	return s.sealWithAAD(password, []byte(id))
}

func (s *Store) sealWithAAD(password string, aad []byte) (encryptedSecret, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return encryptedSecret{}, fmt.Errorf("generate credential nonce: %w", err)
	}
	ciphertext := s.aead.Seal(nil, nonce, []byte(password), aad)
	return encryptedSecret{Nonce: nonce, Ciphertext: ciphertext}, nil
}

func (s *Store) snapshotCredentialLocked(assetID string, record *storedAsset, createdAt time.Time, pruneOldest bool) (CredentialBackup, error) {
	if len(record.CredentialBackups) >= maxCredentialBackups && !pruneOldest {
		return CredentialBackup{}, ErrCredentialBackupLimit
	}
	plaintext, err := s.aead.Open(nil, record.Credential.Nonce, record.Credential.Ciphertext, credentialAAD(assetID, record.CredentialType, ""))
	if err != nil {
		return CredentialBackup{}, fmt.Errorf("decrypt current credential for backup: %w", err)
	}
	backupID, err := s.newCredentialBackupIDLocked(*record)
	if err != nil {
		return CredentialBackup{}, err
	}
	credential, err := s.sealWithAAD(string(plaintext), credentialAAD(assetID, record.CredentialType, backupID))
	if err != nil {
		return CredentialBackup{}, err
	}
	if len(record.CredentialBackups) >= maxCredentialBackups {
		oldest := 0
		for index := 1; index < len(record.CredentialBackups); index++ {
			if record.CredentialBackups[index].CreatedAt.Before(record.CredentialBackups[oldest].CreatedAt) {
				oldest = index
			}
		}
		record.CredentialBackups = append(append([]credentialBackup(nil), record.CredentialBackups[:oldest]...), record.CredentialBackups[oldest+1:]...)
	}
	backup := credentialBackup{ID: backupID, CreatedAt: createdAt.UTC(), Credential: credential, CredentialType: record.CredentialType, KeyFingerprint: record.KeyFingerprint}
	record.CredentialBackups = append(record.CredentialBackups, backup)
	return backupMetadata(backup), nil
}

func (s *Store) newCredentialBackupIDLocked(record storedAsset) (string, error) {
	for attempt := 0; attempt < 4; attempt++ {
		var idBytes [16]byte
		if _, err := io.ReadFull(rand.Reader, idBytes[:]); err != nil {
			return "", fmt.Errorf("generate credential backup ID: %w", err)
		}
		backupID := "cb-" + hex.EncodeToString(idBytes[:])
		duplicate := false
		for _, backup := range record.CredentialBackups {
			if backup.ID == backupID {
				duplicate = true
				break
			}
		}
		if !duplicate {
			return backupID, nil
		}
	}
	return "", fmt.Errorf("could not allocate a unique credential backup ID")
}

func validCredentialBackupID(id string) bool {
	if len(id) != 3+16*2 || id[:3] != "cb-" {
		return false
	}
	decoded, err := hex.DecodeString(id[3:])
	return err == nil && len(decoded) == 16
}

func credentialBackupAAD(assetID, backupID string) []byte {
	return []byte("jumpserver233:credential-backup:" + assetID + ":" + backupID)
}

func (s *Store) persistLocked() error {
	if s.discoveryStaging {
		return nil
	}
	if s.discoveryUncertain {
		return ErrDiscoveryUncertain
	}
	if s.documents != nil {
		return s.persistDocumentLocked()
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create asset data directory: %w", err)
	}
	records := make([]storedAsset, 0, len(s.assets))
	for _, record := range s.assets {
		records = append(records, persistedAsset(record))
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	data, err := encodeRemoteAssetRecords(records, true, s.imports)
	if err != nil {
		return fmt.Errorf("encode asset store: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".assets-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary asset store: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("protect temporary asset store: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary asset store: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary asset store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary asset store: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("replace asset store: %w", err)
	}
	return nil
}

func (s *Store) persistDocumentLocked() error {
	records := make([]storedAsset, 0, len(s.assets))
	for _, record := range s.assets {
		records = append(records, persistedAsset(record))
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	data, err := encodeRemoteAssetRecords(records, false, s.imports)
	if err != nil {
		return fmt.Errorf("encode asset document: %w", err)
	}
	if err := s.documents.Save("assets", data); err != nil {
		return fmt.Errorf("persist asset document: %w", err)
	}
	return nil
}

// LoadOrCreateVaultKey reads JMS_VAULT_KEY as base64 or creates a private local
// key file. Set the environment variable to share the vault across HA nodes.
func LoadOrCreateVaultKey(dataDir, encoded string) ([]byte, error) {
	if encoded != "" {
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("JMS_VAULT_KEY must be base64-encoded 32-byte key material")
		}
		return key, nil
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create vault directory: %w", err)
	}
	path := filepath.Join(dataDir, "vault.key")
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != 32 {
			return nil, fmt.Errorf("vault key file must contain exactly 32 bytes")
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read vault key: %w", err)
	}
	key = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate vault key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return LoadOrCreateVaultKey(dataDir, encoded)
	}
	if err != nil {
		return nil, fmt.Errorf("create vault key file: %w", err)
	}
	if _, err := file.Write(key); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("write vault key: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("sync vault key: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close vault key: %w", err)
	}
	return key, nil
}
