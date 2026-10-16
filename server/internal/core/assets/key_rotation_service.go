package assets

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	xssh "golang.org/x/crypto/ssh"
)

const SSHKeyRotationInterval = 7 * 24 * time.Hour

type KeyUpdater interface {
	Prepare([]byte, []byte) (sshclient.KeyPlan, error)
	Install(sshclient.KeyPlan) error
	Retire(sshclient.KeyPlan) error
	Rollback(sshclient.KeyPlan) error
	Release() error
	Close() error
}
type KeyUpdaterFunc func(context.Context, sshclient.Target, sshclient.Credentials, string) (KeyUpdater, error)
type SSHKeyRotationStatus struct {
	Shared           bool       `json:"shared,omitempty"`
	State            string     `json:"state"`
	Enabled          bool       `json:"enabled"`
	Pending          bool       `json:"pending"`
	CanCancel        bool       `json:"can_cancel"`
	RequestID        string     `json:"request_id,omitempty"`
	OperationID      string     `json:"operation_id,omitempty"`
	ExpectedRevision uint64     `json:"expected_revision,omitempty"`
	LastRotatedAt    *time.Time `json:"last_rotated_at,omitempty"`
	NextRotationAt   *time.Time `json:"next_rotation_at,omitempty"`
	LastAttemptAt    *time.Time `json:"last_attempt_at,omitempty"`
	ErrorCode        string     `json:"error_code,omitempty"`
}

func (s *Service) sshKeyRotationStatus(asset Asset) *SSHKeyRotationStatus {
	s.store.mu.RLock()
	record, ok := s.store.assets[asset.ID]
	s.store.mu.RUnlock()
	if !ok || (asset.CredentialType != CredentialSSHKey && record.PendingKeyChange == nil) {
		return nil
	}
	status := SSHKeyRotationStatus{State: "disabled", Enabled: asset.KeyRotationEnabled, ErrorCode: record.KeyLastError}
	if !asset.KeyRotatedAt.IsZero() {
		last := asset.KeyRotatedAt
		status.LastRotatedAt = &last
		if asset.KeyRotationEnabled {
			next := last.Add(SSHKeyRotationInterval)
			status.NextRotationAt = &next
			status.State = "scheduled"
			if !time.Now().UTC().Before(next) {
				status.State = "due"
			}
		}
	}
	if !record.KeyLastAttemptAt.IsZero() {
		last := record.KeyLastAttemptAt
		status.LastAttemptAt = &last
	}
	if p := record.PendingKeyChange; p != nil {
		status.Pending = true
		status.CanCancel = p.Phase == "install"
		status.RequestID = p.RequestID
		status.OperationID = p.OperationID
		status.ExpectedRevision = p.ExpectedRevision
		status.State = "recovery_required"
		s.mu.RLock()
		running := s.rotationRunning[asset.ID]
		s.mu.RUnlock()
		if running {
			status.State = "installing"
			if p.Phase == "cleanup" {
				status.State = "cleanup_pending"
			}
		}
	} else if record.KeyLastError != "" {
		status.State = "failed"
	}
	shared, view := s.sharedKeyView(asset.ID)
	status.Shared = shared
	if view.OperationID != "" {
		status.Pending = true
		status.OperationID = view.OperationID
		status.RequestID = view.RequestID
		status.ExpectedRevision = view.Revision
		status.CanCancel = view.CanCancel && record.PendingKeyChange != nil
		status.State = "recovery_required"
		if _, running := s.passwordCoordinator.keys.running.Load(view.OperationID); running {
			status.State = "installing"
			if !status.CanCancel {
				status.State = "cleanup_pending"
			}
		}
	}
	return &status
}
func (s *Service) keyListItem(id string) (ListItem, error) {
	asset, e := s.Get(id)
	if e != nil {
		return ListItem{}, e
	}
	return ListItem{Asset: asset, Monitor: s.currentMonitorStatus(id), Permissions: []string{"view", "connect", "manage"}, PasswordRotation: s.passwordRotationStatus(asset), SSHKeyRotation: s.sshKeyRotationStatus(asset)}, nil
}
func (s *Service) claimKeyChange(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rotationRunning[id] {
		return ErrRotationInProgress
	}
	if a, ok := s.find(id); !ok {
		return ErrNotFound
	} else if !IsSSH(a) {
		return ErrUnsupportedProtocol
	}
	if s.store.HasPendingPasswordRotation(id) {
		return ErrRotationPending
	}
	s.rotationRunning[id] = true
	return nil
}
func (s *Service) RotateSSHKey(ctx context.Context, id, requestID string, revision uint64, actor string) (ListItem, error) {
	if c := s.passwordCoordinator; c != nil {
		return c.withKeyChange(ctx, s, id, false, func(ctx context.Context) (ListItem, error) {
			return s.rotateSSHKeyLocal(ctx, id, requestID, revision, actor)
		})
	}
	return s.rotateSSHKeyLocal(ctx, id, requestID, revision, actor)
}
func (s *Service) rotateSSHKeyLocal(ctx context.Context, id, requestID string, revision uint64, actor string) (ListItem, error) {
	if !keyRequestPattern.MatchString(requestID) || revision == 0 || len(actor) == 0 || len(actor) > 128 {
		return ListItem{}, ErrInvalidInput
	}
	if e := s.claimKeyChange(id); e != nil {
		return ListItem{}, e
	}
	defer s.releaseRotation(id)
	if e := ctx.Err(); e != nil {
		return ListItem{}, e
	}
	candidate, fingerprint, e := generateSSHKey()
	if e != nil {
		return ListItem{}, e
	}
	s.store.mu.RLock()
	record := s.store.assets[id]
	needsPreflight := record.PendingKeyChange == nil && record.LastKeyRequestID != requestID
	s.store.mu.RUnlock()
	if needsPreflight {
		if record.CredentialRevision != revision {
			return ListItem{}, ErrCredentialChanged
		}
		asset, target, current, preflightError := s.store.connection(id)
		if preflightError == nil {
			oldPublic, keyError := publicFromCredential(current)
			if keyError != nil {
				return ListItem{}, keyError
			}
			newPublic, keyError := publicFromCredential(candidate)
			if keyError != nil {
				return ListItem{}, keyError
			}
			check := s.keyPreflight
			if check == nil {
				check = sshclient.CheckSSHKeyChange
			}
			preflightError = check(ctx, target, current, oldPublic, newPublic)
		}
		if preflightError != nil {
			code := classifySSHKeyChange(preflightError)
			_ = s.store.RecordSSHKeyAttempt(id, code, time.Now().UTC())
			_ = s.appendRotationAuditDetails(asset, "ssh_key_preflight_failed", "ssh_key", "failed", code, actor, "")
			return ListItem{}, ErrSSHKeyRotationFailed
		}
	}
	p, _, done, e := s.store.BeginSSHKeyChange(id, requestID, revision, actor, candidate, fingerprint)
	if e != nil {
		return ListItem{}, e
	}
	if !done {
		e = s.continueSSHKeyChange(ctx, id, p.OperationID, actor)
	}
	item, itemError := s.keyListItem(id)
	if e != nil {
		return item, e
	}
	return item, itemError
}
func publicFromCredential(c sshclient.Credentials) ([]byte, error) {
	if len(c.PrivateKey) == 0 {
		return nil, nil
	}
	signer, e := xssh.ParsePrivateKey(c.PrivateKey)
	if e != nil {
		return nil, ErrCredentialType
	}
	return signer.PublicKey().Marshal(), nil
}
func (s *Service) openKeyUpdater(ctx context.Context, target sshclient.Target, p pendingKeyChange, data keyChangeData, current sshclient.Credentials) (KeyUpdater, error) {
	open := s.keyUpdater
	if open == nil {
		open = func(ctx context.Context, target sshclient.Target, c sshclient.Credentials, id string) (KeyUpdater, error) {
			return sshclient.OpenAuthorizedKeys(ctx, target, c, id)
		}
	}
	updater, e := open(ctx, target, current, p.OperationID)
	if e == nil {
		return updater, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	updater, nextError := open(ctx, target, data.New, p.OperationID)
	if nextError == nil {
		return updater, nil
	}
	if p.Phase == "cleanup" && ctx.Err() == nil {
		updater, oldError := open(ctx, target, data.Old, p.OperationID)
		if oldError == nil {
			return updater, nil
		}
	}
	return nil, e
}
func (s *Service) continueSSHKeyChange(ctx context.Context, id, operationID, actor string) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	p, data, e := s.store.PendingSSHKeyChange(id)
	if e != nil {
		return e
	}
	if p.OperationID != operationID {
		return ErrCredentialChanged
	}
	if c := s.passwordCoordinator; c != nil {
		if o := c.keyOperation(passwordParticipant{s.passwordScope, id}); o != nil && o.Source != (passwordParticipant{s.passwordScope, id}) {
			owner := c.keyService(o.Source.Scope)
			if owner == nil {
				return ErrNotFound
			}
			if e := owner.claimKeyChange(o.Source.AssetID); e != nil {
				return e
			}
			defer owner.releaseRotation(o.Source.AssetID)
			return owner.continueSSHKeyChange(ctx, o.Source.AssetID, o.ID, actor)
		}
		if e = c.prepareSharedKey(ctx, s, id, p, data); e != nil {
			return e
		}
		if o := c.keyOperation(passwordParticipant{s.passwordScope, id}); o != nil {
			c.keys.running.Store(o.ID, true)
			defer c.keys.running.Delete(o.ID)
		}
	}
	asset, e := s.Get(id)
	if e != nil {
		return e
	}
	fail := func(cause error) error {
		code := classifySSHKeyChange(cause)
		_ = s.store.RecordSSHKeyAttempt(id, code, time.Now().UTC())
		_ = s.appendRotationAuditDetails(asset, "ssh_key_pending", "ssh_key", "recovery_required", code, actor, "", operationID)
		return ErrSSHKeyRotationFailed
	}
	if e = s.store.RecordSSHKeyAttempt(id, "", time.Now().UTC()); e != nil {
		return e
	}
	if e = s.appendRotationAuditDetails(asset, "ssh_key_started", "ssh_key", "", "", actor, "", operationID); e != nil {
		return fail(e)
	}
	_, target, current, e := s.store.connection(id)
	if e != nil {
		return fail(e)
	}
	updater, e := s.openKeyUpdater(ctx, target, p, data, current)
	if e != nil {
		return fail(e)
	}
	defer updater.Close()
	if data.Plan == nil {
		oldPublic, e := publicFromCredential(data.Old)
		if e != nil {
			return fail(e)
		}
		newPublic, e := publicFromCredential(data.New)
		if e != nil {
			return fail(e)
		}
		plan, e := updater.Prepare(oldPublic, newPublic)
		if e != nil {
			return fail(e)
		}
		if e = s.store.SaveSSHKeyPlan(id, operationID, plan); e != nil {
			return fail(e)
		}
		data.Plan = &plan
	}
	if p.Phase == "install" {
		if e = updater.Install(*data.Plan); e != nil {
			return fail(e)
		}
		if e = s.verifyPassword(ctx, target, data.New, 8*time.Second); e != nil {
			return fail(e)
		}
		if e = s.promoteKeyChange(ctx, id, operationID, data); e != nil {
			return fail(e)
		}
		p.Phase = "cleanup"
		s.mu.Lock()
		delete(s.rotationStatus, id)
		s.mu.Unlock()
	}
	// Vault promotion precedes old-key revocation. Recovery can always retry
	// cleanup using the persisted new key and the encrypted previous credential.
	if c := s.passwordCoordinator; c != nil {
		if o := c.keyOperation(passwordParticipant{s.passwordScope, id}); o != nil && (o.Phase == "active" || o.Phase == "promote") {
			if e = s.promoteKeyChange(ctx, id, operationID, data); e != nil {
				return fail(e)
			}
		}
	}
	if e = s.verifyPassword(ctx, target, data.New, 8*time.Second); e != nil {
		if e = updater.Install(*data.Plan); e != nil {
			return fail(e)
		}
		if e = s.verifyPassword(ctx, target, data.New, 8*time.Second); e != nil {
			return fail(e)
		}
	}
	if e = updater.Retire(*data.Plan); e != nil {
		return fail(e)
	}
	if e = s.verifyPassword(ctx, target, data.New, 8*time.Second); e != nil {
		return fail(e)
	}
	if e = updater.Release(); e != nil {
		return fail(e)
	}
	if e = s.finishKeyChange(id, operationID, false); e != nil {
		return fail(e)
	}
	_ = s.appendRotationAuditDetails(asset, "ssh_key_completed", "ssh_key", "success", "", actor, "", operationID)
	return nil
}
func (s *Service) CancelSSHKeyChange(ctx context.Context, id, operationID, actor string) (ListItem, error) {
	if c := s.passwordCoordinator; c != nil {
		return c.withKeyChange(ctx, s, id, true, func(ctx context.Context) (ListItem, error) { return s.cancelSSHKeyLocal(ctx, id, operationID, actor) })
	}
	return s.cancelSSHKeyLocal(ctx, id, operationID, actor)
}
func (s *Service) cancelSSHKeyLocal(ctx context.Context, id, operationID, actor string) (ListItem, error) {
	if !sshclient.ValidKeyOperationID(operationID) || len(actor) == 0 || len(actor) > 128 {
		return ListItem{}, ErrInvalidInput
	}
	if e := s.claimKeyChange(id); e != nil {
		return ListItem{}, e
	}
	defer s.releaseRotation(id)
	p, data, e := s.store.PendingSSHKeyChange(id)
	if e != nil {
		return ListItem{}, e
	}
	if p.OperationID != operationID {
		return ListItem{}, ErrCredentialChanged
	}
	if c := s.passwordCoordinator; c != nil {
		if o := c.keyOperation(passwordParticipant{s.passwordScope, id}); o != nil && o.Source != (passwordParticipant{s.passwordScope, id}) {
			owner := c.keyService(o.Source.Scope)
			if owner == nil {
				return ListItem{}, ErrNotFound
			}
			_, e = owner.cancelSSHKeyLocal(ctx, o.Source.AssetID, o.ID, actor)
			if e != nil {
				return ListItem{}, e
			}
			return s.keyListItem(id)
		}
	}
	if p.Phase != "install" {
		return ListItem{}, ErrSSHKeyCommitted
	}
	asset, e := s.Get(id)
	if e != nil {
		return ListItem{}, e
	}
	if e = s.appendRotationAuditDetails(asset, "ssh_key_cancel_started", "ssh_key", "", "", actor, "", p.OperationID); e != nil {
		return ListItem{}, e
	}
	_, target, _, e := s.store.connection(id)
	if e != nil {
		return ListItem{}, e
	}
	if e = s.verifyPassword(ctx, target, data.Old, 8*time.Second); e != nil {
		return ListItem{}, ErrSSHKeyRotationFailed
	}
	open := s.keyUpdater
	if open == nil {
		open = func(ctx context.Context, target sshclient.Target, c sshclient.Credentials, id string) (KeyUpdater, error) {
			return sshclient.OpenAuthorizedKeys(ctx, target, c, id)
		}
	}
	updater, e := open(ctx, target, data.Old, p.OperationID)
	if e != nil {
		return ListItem{}, ErrSSHKeyRotationFailed
	}
	defer updater.Close()
	if data.Plan != nil {
		if e = updater.Rollback(*data.Plan); e != nil {
			return ListItem{}, ErrSSHKeyRotationFailed
		}
	}
	if e = s.verifyPassword(ctx, target, data.Old, 8*time.Second); e != nil {
		return ListItem{}, ErrSSHKeyRotationFailed
	}
	if e = updater.Release(); e != nil {
		return ListItem{}, ErrSSHKeyRotationFailed
	}
	if e = s.finishKeyChange(id, p.OperationID, true); e != nil {
		return ListItem{}, e
	}
	_ = s.appendRotationAuditDetails(asset, "ssh_key_cancelled", "ssh_key", "cancelled", "", actor, "", p.OperationID)
	return s.keyListItem(id)
}
func (s *Service) RecoverPendingSSHKeyChanges(ctx context.Context) {
	if c := s.passwordCoordinator; c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.recoverSharedKeys(ctx)
	}
	for _, asset := range s.store.List() {
		if c := s.passwordCoordinator; c != nil && c.keyOperation(passwordParticipant{s.passwordScope, asset.ID}) != nil {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		if !s.store.HasPendingSSHKeyChange(asset.ID) || s.keyChangeCoolingDown(asset.ID, time.Now().UTC()) {
			continue
		}
		p, _, e := s.store.PendingSSHKeyChange(asset.ID)
		if e != nil {
			continue
		}
		if e = s.claimKeyChange(asset.ID); e != nil {
			continue
		}
		_ = s.continueSSHKeyChange(ctx, asset.ID, p.OperationID, "system/ssh-key-recovery")
		s.releaseRotation(asset.ID)
	}
}
func (s *Service) RotateDueSSHKeys(ctx context.Context) {
	for _, asset := range s.store.List() {
		if ctx.Err() != nil {
			return
		}
		if asset.CredentialType != CredentialSSHKey || !asset.KeyRotationEnabled || s.store.HasPendingSSHKeyChange(asset.ID) || time.Now().UTC().Before(asset.KeyRotatedAt.Add(SSHKeyRotationInterval)) || s.keyChangeCoolingDown(asset.ID, time.Now().UTC()) {
			continue
		}
		var token [16]byte
		if _, e := rand.Read(token[:]); e != nil {
			return
		}
		_, _ = s.RotateSSHKey(ctx, asset.ID, "auto-"+hex.EncodeToString(token[:]), asset.CredentialRevision, "system/ssh-key-rotation")
	}
}
func (s *Service) keyChangeCoolingDown(id string, now time.Time) bool {
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	record, ok := s.store.assets[id]
	return ok && !record.KeyLastAttemptAt.IsZero() && now.Before(record.KeyLastAttemptAt.Add(rotationRetryInterval))
}
func classifySSHKeyChange(e error) string {
	switch {
	case errors.Is(e, sshclient.ErrAuthorizedKeysUnsafe):
		return "unsafe_permissions"
	case errors.Is(e, sshclient.ErrAuthorizedKeysUnsupported):
		return "unsupported_server"
	case errors.Is(e, sshclient.ErrAuthorizedKeysLocked):
		return "remote_locked"
	case errors.Is(e, sshclient.ErrAuthorizedKeysChanged), errors.Is(e, ErrCredentialChanged):
		return "remote_changed"
	case errors.Is(e, sshclient.ErrAuthorizedKeyMissing):
		return "active_key_missing"
	case errors.Is(e, ErrRotationPending), errors.Is(e, ErrSSHKeyPending):
		return "gateway_pending"
	case errors.Is(e, context.Canceled), errors.Is(e, context.DeadlineExceeded):
		return "timeout"
	default:
		return "ssh_key_failed"
	}
}
