package assets

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
)

const CredentialPassword = "password"
const CredentialSSHKey = "ssh_key"

var ErrCredentialType = errors.New("credential type does not support this operation")
var ErrCredentialChanged = errors.New("credential changed during verification")

func credentialType(kind string) string {
	if kind == "" {
		return CredentialPassword
	}
	return kind
}
func credentialAAD(id, kind, backupID string) []byte {
	aad := []byte(id)
	if backupID != "" {
		aad = credentialBackupAAD(id, backupID)
	}
	if credentialType(kind) == CredentialSSHKey {
		return append([]byte("ssh-key\x00"), aad...)
	}
	return aad
}
func decodeCredentials(kind string, plain []byte) sshclient.Credentials {
	if credentialType(kind) == CredentialSSHKey {
		return sshclient.Credentials{PrivateKey: plain}
	}
	return sshclient.Credentials{Password: string(plain)}
}
func validateCredential(kind, fingerprint string, plain []byte) error {
	switch credentialType(kind) {
	case CredentialPassword:
		if fingerprint != "" || len(plain) == 0 || len(plain) > 4096 {
			return ErrCredentialType
		}
	case CredentialSSHKey:
		_, actual, e := sshclient.ImportPrivateKey(plain, "")
		if e != nil || fingerprint != actual {
			return ErrCredentialType
		}
	default:
		return ErrCredentialType
	}
	return nil
}
func inputCredential(input Input, current *Asset) (string, string, *sshclient.Credentials, error) {
	kind := strings.TrimSpace(input.CredentialType)
	if kind == "" {
		kind = CredentialPassword
		if current != nil {
			kind = credentialType(current.CredentialType)
		}
	}
	invalid := func() (string, string, *sshclient.Credentials, error) {
		return "", "", nil, fmt.Errorf("%w: invalid SSH credential", ErrInvalidInput)
	}
	switch kind {
	case CredentialPassword:
		if input.PrivateKey != "" || input.PrivateKeyPassphrase != "" {
			return invalid()
		}
		if input.Password == "" {
			if current == nil || credentialType(current.CredentialType) != CredentialPassword {
				return invalid()
			}
			return kind, "", nil, nil
		}
		if len(input.Password) > 4096 || strings.TrimSpace(input.Password) == "" {
			return invalid()
		}
		return kind, "", &sshclient.Credentials{Password: input.Password}, nil
	case CredentialSSHKey:
		if input.Password != "" {
			return invalid()
		}
		if input.PrivateKey == "" {
			if input.PrivateKeyPassphrase != "" || current == nil || credentialType(current.CredentialType) != CredentialSSHKey {
				return invalid()
			}
			return kind, current.KeyFingerprint, nil, nil
		}
		normalized, fingerprint, e := sshclient.ImportPrivateKey([]byte(input.PrivateKey), input.PrivateKeyPassphrase)
		if e != nil {
			return invalid()
		}
		return kind, fingerprint, &sshclient.Credentials{PrivateKey: normalized}, nil
	default:
		return invalid()
	}
}
func (s *Store) sealCredentials(asset *Asset, c sshclient.Credentials) (encryptedSecret, error) {
	asset.CredentialType = credentialType(asset.CredentialType)
	plain := []byte(c.Password)
	if asset.CredentialType == CredentialSSHKey {
		if c.Password != "" {
			return encryptedSecret{}, ErrCredentialType
		}
		normalized, pin, e := sshclient.ImportPrivateKey(c.PrivateKey, "")
		if e != nil {
			return encryptedSecret{}, ErrCredentialType
		}
		plain = normalized
		asset.KeyFingerprint = pin
	} else {
		if len(c.PrivateKey) > 0 {
			return encryptedSecret{}, ErrCredentialType
		}
		asset.KeyFingerprint = ""
	}
	if e := validateCredential(asset.CredentialType, asset.KeyFingerprint, plain); e != nil {
		return encryptedSecret{}, e
	}
	return s.sealWithAAD(string(plain), credentialAAD(asset.ID, asset.CredentialType, ""))
}
func backupMetadata(b credentialBackup) CredentialBackup {
	return CredentialBackup{ID: b.ID, CreatedAt: b.CreatedAt, CredentialType: credentialType(b.CredentialType), KeyFingerprint: b.KeyFingerprint}
}
func (s *Store) backupCredentialsLocked(id, backupID string) (credentialBackup, sshclient.Credentials, error) {
	record, ok := s.assets[id]
	if !ok {
		return credentialBackup{}, sshclient.Credentials{}, ErrNotFound
	}
	for _, b := range record.CredentialBackups {
		if b.ID == backupID {
			plain, e := s.aead.Open(nil, b.Credential.Nonce, b.Credential.Ciphertext, credentialAAD(id, b.CredentialType, b.ID))
			if e != nil {
				return credentialBackup{}, sshclient.Credentials{}, e
			}
			return b, decodeCredentials(b.CredentialType, plain), nil
		}
	}
	return credentialBackup{}, sshclient.Credentials{}, ErrCredentialBackupNotFound
}
func (s *Store) CredentialBackupForRestore(id, backupID string) (CredentialBackup, sshclient.Credentials, [32]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, c, e := s.backupCredentialsLocked(id, backupID)
	if e != nil {
		return CredentialBackup{}, sshclient.Credentials{}, [32]byte{}, e
	}
	raw, e := json.Marshal(s.assets[id])
	if e != nil {
		return CredentialBackup{}, sshclient.Credentials{}, [32]byte{}, e
	}
	return backupMetadata(b), c, sha256.Sum256(raw), nil
}

// RestoreKeyCredential only promotes a previously verified candidate if the
// complete asset/backup record still matches the verification snapshot.
func (s *Store) RestoreKeyCredential(id, backupID string, version [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, ok := s.assets[id]
	if !ok {
		return ErrNotFound
	}
	if previous.PendingKeyChange != nil {
		return ErrSSHKeyPending
	}
	if previous.PendingRotation != nil {
		return ErrRotationPending
	}
	raw, e := json.Marshal(previous)
	if e != nil {
		return e
	}
	if sha256.Sum256(raw) != version {
		return ErrCredentialChanged
	}
	b, c, e := s.backupCredentialsLocked(id, backupID)
	if e != nil {
		return e
	}
	if credentialType(b.CredentialType) != CredentialSSHKey {
		return ErrCredentialType
	}
	record := previous
	if _, e = s.snapshotCredentialLocked(id, &record, time.Now().UTC(), true); e != nil {
		return e
	}
	asset := record.Asset
	asset.CredentialType = CredentialSSHKey
	secret, e := s.sealCredentials(&asset, c)
	if e != nil {
		return e
	}
	revision, e := nextCredentialRevision(previous.Asset)
	if e != nil {
		return e
	}
	asset.CredentialRevision = revision
	asset.KeyRotatedAt = time.Now().UTC()
	asset.UpdatedAt = time.Now().UTC()
	record.Asset = asset
	record.Credential = secret
	record.RotationState = ""
	record.RotationErrorCode = ""
	record.RotationLastAttemptAt = time.Time{}
	s.assets[id] = record
	if e = s.persistLocked(); e != nil {
		s.assets[id] = previous
		return e
	}
	return nil
}
