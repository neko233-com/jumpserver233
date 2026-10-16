package assets

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"regexp"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	xssh "golang.org/x/crypto/ssh"
)

var (
	ErrSSHKeyPending        = errors.New("SSH key change is pending")
	ErrSSHKeyCommitted      = errors.New("SSH key change has already committed")
	ErrSSHKeyCancelled      = errors.New("SSH key request was cancelled")
	ErrSSHKeyRotationFailed = errors.New("SSH key change failed")
	keyRequestPattern       = regexp.MustCompile(`^[A-Za-z0-9_-]{8,80}$`)
)

type pendingKeyChange struct {
	OperationID      string          `json:"operation_id"`
	RequestID        string          `json:"request_id"`
	ExpectedRevision uint64          `json:"expected_revision"`
	Phase            string          `json:"phase"`
	StartedAt        time.Time       `json:"started_at"`
	Payload          encryptedSecret `json:"payload"`
}
type keyChangeData struct {
	Version        int                   `json:"version"`
	Actor          string                `json:"actor"`
	OldType        string                `json:"old_type"`
	OldFingerprint string                `json:"old_fingerprint,omitempty"`
	NewFingerprint string                `json:"new_fingerprint"`
	Old            sshclient.Credentials `json:"old"`
	New            sshclient.Credentials `json:"new"`
	Plan           *sshclient.KeyPlan    `json:"plan,omitempty"`
}

func nextCredentialRevision(asset Asset) (uint64, error) {
	if asset.CredentialRevision == math.MaxUint64 {
		return 0, ErrCredentialChanged
	}
	return asset.CredentialRevision + 1, nil
}
func keyChangeAAD(id string, p pendingKeyChange) []byte {
	return []byte(fmt.Sprintf("ssh-key-change\x00%s\x00%s\x00%s\x00%s\x00%d", id, p.OperationID, p.Phase, p.RequestID, p.ExpectedRevision))
}
func (s *Store) sealKeyChange(id string, p *pendingKeyChange, data keyChangeData) error {
	raw, e := json.Marshal(data)
	if e != nil {
		return e
	}
	if len(raw) > 2*1024*1024 {
		return ErrInvalidInput
	}
	secret, e := s.sealWithAAD(string(raw), keyChangeAAD(id, *p))
	if e != nil {
		return e
	}
	p.Payload = secret
	return nil
}
func (s *Store) openKeyChange(record storedAsset) (pendingKeyChange, keyChangeData, error) {
	if record.PendingKeyChange == nil {
		return pendingKeyChange{}, keyChangeData{}, ErrNotFound
	}
	p := *record.PendingKeyChange
	if !sshclient.ValidKeyOperationID(p.OperationID) || !keyRequestPattern.MatchString(p.RequestID) || p.ExpectedRevision == 0 || p.ExpectedRevision == math.MaxUint64 || p.StartedAt.IsZero() || (p.Phase != "install" && p.Phase != "cleanup") || record.PendingRotation != nil {
		return p, keyChangeData{}, ErrInvalidInput
	}
	raw, e := s.aead.Open(nil, p.Payload.Nonce, p.Payload.Ciphertext, keyChangeAAD(record.ID, p))
	if e != nil || len(raw) > 2*1024*1024 {
		return p, keyChangeData{}, ErrInvalidInput
	}
	var data keyChangeData
	if e = json.Unmarshal(raw, &data); e != nil || data.Version != 1 || len(data.Actor) == 0 || len(data.Actor) > 128 || data.New.Password != "" || validateCredential(CredentialSSHKey, data.NewFingerprint, data.New.PrivateKey) != nil {
		return p, data, ErrInvalidInput
	}
	oldPlain := []byte(data.Old.Password)
	if data.OldType == CredentialSSHKey {
		oldPlain = data.Old.PrivateKey
		if data.Old.Password != "" {
			return p, data, ErrInvalidInput
		}
	} else if len(data.Old.PrivateKey) > 0 {
		return p, data, ErrInvalidInput
	}
	if validateCredential(data.OldType, data.OldFingerprint, oldPlain) != nil {
		return p, data, ErrInvalidInput
	}
	active, e := s.aead.Open(nil, record.Credential.Nonce, record.Credential.Ciphertext, credentialAAD(record.ID, record.CredentialType, ""))
	if e != nil {
		return p, data, ErrInvalidInput
	}
	if p.Phase == "install" && !bytes.Equal(active, oldPlain) {
		return p, data, ErrCredentialChanged
	}
	if p.Phase == "install" {
		if record.CredentialRevision != p.ExpectedRevision || credentialType(record.CredentialType) != data.OldType || record.KeyFingerprint != data.OldFingerprint {
			return p, data, ErrCredentialChanged
		}
	} else if record.CredentialRevision != p.ExpectedRevision+1 || record.CredentialType != CredentialSSHKey || record.KeyFingerprint != data.NewFingerprint {
		return p, data, ErrCredentialChanged
	}
	if data.Plan != nil {
		if sshclient.ValidateKeyPlan(*data.Plan) != nil || data.Plan.OperationID != p.OperationID {
			return p, data, ErrInvalidInput
		}
		newKey, e := xssh.ParsePublicKey(data.Plan.NewPublic)
		if e != nil || xssh.FingerprintSHA256(newKey) != data.NewFingerprint {
			return p, data, ErrInvalidInput
		}
		if data.OldType == CredentialSSHKey {
			oldKey, e := xssh.ParsePublicKey(data.Plan.OldPublic)
			if e != nil || xssh.FingerprintSHA256(oldKey) != data.OldFingerprint {
				return p, data, ErrInvalidInput
			}
		} else if len(data.Plan.OldPublic) != 0 {
			return p, data, ErrInvalidInput
		}
	}
	if p.Phase == "cleanup" && data.Plan == nil {
		return p, data, ErrInvalidInput
	}
	return p, data, nil
}
func generateSSHKey() (sshclient.Credentials, string, error) {
	_, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return sshclient.Credentials{}, "", e
	}
	block, e := xssh.MarshalPrivateKey(private, "")
	if e != nil {
		return sshclient.Credentials{}, "", e
	}
	key, fingerprint, e := sshclient.ImportPrivateKey(pem.EncodeToMemory(block), "")
	return sshclient.Credentials{PrivateKey: key}, fingerprint, e
}
func (s *Store) BeginSSHKeyChange(id, requestID string, expected uint64, actor string, candidate sshclient.Credentials, fingerprint string) (pendingKeyChange, keyChangeData, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.assets[id]
	if !ok {
		return pendingKeyChange{}, keyChangeData{}, false, ErrNotFound
	}
	if !keyRequestPattern.MatchString(requestID) || expected == 0 || len(actor) == 0 || len(actor) > 128 {
		return pendingKeyChange{}, keyChangeData{}, false, ErrInvalidInput
	}
	if record.PendingKeyChange != nil {
		p, d, e := s.openKeyChange(record)
		if e != nil {
			return p, d, false, e
		}
		if p.RequestID != requestID || p.ExpectedRevision != expected {
			return p, d, false, ErrSSHKeyPending
		}
		return p, d, false, nil
	}
	if record.LastKeyRequestID == requestID {
		if record.LastKeyRequestRevision != expected {
			return pendingKeyChange{}, keyChangeData{}, false, ErrCredentialChanged
		}
		if record.LastKeyResult == "cancelled" {
			return pendingKeyChange{}, keyChangeData{}, false, ErrSSHKeyCancelled
		}
		return pendingKeyChange{}, keyChangeData{}, true, nil
	}
	if record.PendingRotation != nil {
		return pendingKeyChange{}, keyChangeData{}, false, ErrRotationPending
	}
	if record.CredentialRevision != expected || expected == math.MaxUint64 {
		return pendingKeyChange{}, keyChangeData{}, false, ErrCredentialChanged
	}
	if candidate.Password != "" || validateCredential(CredentialSSHKey, fingerprint, candidate.PrivateKey) != nil {
		return pendingKeyChange{}, keyChangeData{}, false, ErrCredentialType
	}
	plain, e := s.aead.Open(nil, record.Credential.Nonce, record.Credential.Ciphertext, credentialAAD(id, record.CredentialType, ""))
	if e != nil {
		return pendingKeyChange{}, keyChangeData{}, false, e
	}
	var token [16]byte
	if _, e = rand.Read(token[:]); e != nil {
		return pendingKeyChange{}, keyChangeData{}, false, e
	}
	p := pendingKeyChange{OperationID: "kr-" + hex.EncodeToString(token[:]), RequestID: requestID, ExpectedRevision: expected, Phase: "install", StartedAt: time.Now().UTC()}
	data := keyChangeData{Version: 1, Actor: actor, OldType: credentialType(record.CredentialType), OldFingerprint: record.KeyFingerprint, NewFingerprint: fingerprint, Old: decodeCredentials(record.CredentialType, plain), New: candidate}
	if data.OldFingerprint == data.NewFingerprint {
		return p, data, false, ErrInvalidInput
	}
	if e = s.sealKeyChange(id, &p, data); e != nil {
		return p, data, false, e
	}
	previous := record
	record.PendingKeyChange = &p
	record.KeyLastAttemptAt = time.Now().UTC()
	record.KeyLastError = ""
	s.assets[id] = record
	if e = s.persistLocked(); e != nil {
		s.assets[id] = previous
		return p, data, false, e
	}
	return p, data, false, nil
}
func (s *Store) PendingSSHKeyChange(id string) (pendingKeyChange, keyChangeData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.assets[id]
	if !ok {
		return pendingKeyChange{}, keyChangeData{}, ErrNotFound
	}
	return s.openKeyChange(record)
}
func (s *Store) HasPendingSSHKeyChange(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.assets[id]
	return ok && record.PendingKeyChange != nil
}
func (s *Store) SaveSSHKeyPlan(id, operationID string, plan sshclient.KeyPlan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.assets[id]
	if !ok {
		return ErrNotFound
	}
	p, data, e := s.openKeyChange(record)
	if e != nil {
		return e
	}
	if p.OperationID != operationID || p.Phase != "install" || data.Plan != nil {
		return ErrCredentialChanged
	}
	if plan.OperationID != operationID || sshclient.ValidateKeyPlan(plan) != nil {
		return ErrInvalidInput
	}
	data.Plan = &plan
	previous := record
	if e = s.sealKeyChange(id, &p, data); e != nil {
		return e
	}
	record.PendingKeyChange = &p
	if _, _, e = s.openKeyChange(record); e != nil {
		return e
	}
	s.assets[id] = record
	if e = s.persistLocked(); e != nil {
		s.assets[id] = previous
	}
	return e
}
func (s *Store) CommitSSHKeyChange(id, operationID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.assets[id]
	if !ok {
		return ErrNotFound
	}
	p, data, e := s.openKeyChange(record)
	if e != nil {
		return e
	}
	if p.OperationID != operationID {
		return ErrCredentialChanged
	}
	if p.Phase == "cleanup" {
		return nil
	}
	if data.Plan == nil {
		return ErrInvalidInput
	}
	previous := record
	if _, e = s.snapshotCredentialLocked(id, &record, time.Now().UTC(), true); e != nil {
		return e
	}
	asset := record.Asset
	asset.CredentialType = CredentialSSHKey
	secret, e := s.sealCredentials(&asset, data.New)
	if e != nil {
		return e
	}
	revision, e := nextCredentialRevision(asset)
	if e != nil {
		return e
	}
	asset.CredentialRevision = revision
	asset.KeyRotatedAt = time.Now().UTC()
	asset.UpdatedAt = asset.KeyRotatedAt
	record.Asset = asset
	record.Credential = secret
	record.PasswordRotatedAt = asset.KeyRotatedAt
	record.Asset.PasswordRotatedAt = record.PasswordRotatedAt
	record.RotationLastAttemptAt = time.Time{}
	record.RotationState = ""
	record.RotationErrorCode = ""
	p.Phase = "cleanup"
	if e = s.sealKeyChange(id, &p, data); e != nil {
		return e
	}
	record.PendingKeyChange = &p
	s.assets[id] = record
	if e = s.persistLocked(); e != nil {
		s.assets[id] = previous
	}
	return e
}
func (s *Store) FinishSSHKeyChange(id, operationID string, cancelled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.assets[id]
	if !ok {
		return ErrNotFound
	}
	p, _, e := s.openKeyChange(record)
	if e != nil {
		return e
	}
	if p.OperationID != operationID {
		return ErrCredentialChanged
	}
	if cancelled && p.Phase != "install" {
		return ErrSSHKeyCommitted
	}
	if !cancelled && p.Phase != "cleanup" {
		return ErrInvalidInput
	}
	previous := record
	if cancelled {
		revision, e := nextCredentialRevision(record.Asset)
		if e != nil {
			return e
		}
		record.CredentialRevision = revision
		record.UpdatedAt = time.Now().UTC()
	}
	record.PendingKeyChange = nil
	record.LastKeyRequestID = p.RequestID
	record.LastKeyRequestRevision = p.ExpectedRevision
	record.LastKeyResult = "completed"
	if cancelled {
		record.LastKeyResult = "cancelled"
	}
	record.KeyLastError = ""
	record.KeyLastAttemptAt = time.Now().UTC()
	s.assets[id] = record
	if e = s.persistLocked(); e != nil {
		s.assets[id] = previous
	}
	return e
}
func (s *Store) RecordSSHKeyAttempt(id, errorCode string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.assets[id]
	if !ok {
		return ErrNotFound
	}
	previous := record
	record.KeyLastAttemptAt = at
	record.KeyLastError = errorCode
	s.assets[id] = record
	if e := s.persistLocked(); e != nil {
		s.assets[id] = previous
		return e
	}
	return nil
}
