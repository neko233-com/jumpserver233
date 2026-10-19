package assets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
)

const (
	PasswordRotationInterval = 7 * 24 * time.Hour
	rotationRetryInterval    = time.Hour
)

var (
	ErrPasswordRotationFailed = errors.New("SSH password rotation failed")
	ErrRotationInProgress     = errors.New("SSH password rotation is already in progress")
	errRotationNotDue         = errors.New("SSH password rotation is not due")
	errRotationCoolingDown    = errors.New("SSH password rotation is cooling down")
)

type PasswordRotationStatus struct {
	Shared         bool       `json:"shared,omitempty"`
	State          string     `json:"state"`
	LastRotatedAt  time.Time  `json:"last_rotated_at"`
	NextRotationAt time.Time  `json:"next_rotation_at"`
	LastAttemptAt  *time.Time `json:"last_attempt_at,omitempty"`
	ErrorCode      string     `json:"error_code,omitempty"`
}

type PasswordChangeFunc func(context.Context, sshclient.Target, sshclient.Credentials, string, time.Duration) error
type PasswordVerifyFunc func(context.Context, sshclient.Target, sshclient.Credentials, time.Duration) error

type rotationAuditRecord struct {
	OperationID string    `json:"operation_id,omitempty"`
	Event       string    `json:"event"`
	AssetID     string    `json:"asset_id"`
	AssetName   string    `json:"asset_name"`
	Account     string    `json:"account"`
	Trigger     string    `json:"trigger"`
	Actor       string    `json:"actor,omitempty"`
	BackupID    string    `json:"backup_id,omitempty"`
	Result      string    `json:"result,omitempty"`
	ErrorCode   string    `json:"error_code,omitempty"`
	OccurredAt  time.Time `json:"occurred_at"`
}

func NewServiceWithPasswordRotation(store *Store, probe ProbeFunc, change PasswordChangeFunc, verify PasswordVerifyFunc) *Service {
	if probe == nil {
		probe = sshclient.Probe
	}
	if change == nil {
		change = sshclient.RestorePassword
	}
	if verify == nil {
		verify = sshclient.VerifyPassword
	}
	return &Service{
		store:           store,
		probe:           probe,
		changePassword:  change,
		verifyPassword:  verify,
		status:          make(map[string]MonitorStatus),
		last:            make(map[string]previousSample),
		rotationStatus:  make(map[string]PasswordRotationStatus),
		rotationRunning: make(map[string]bool),
	}
}

func (s *Service) passwordRotationStatus(asset Asset) *PasswordRotationStatus {
	if !IsSSH(asset) {
		return nil
	}
	if credentialType(asset.CredentialType) == CredentialSSHKey && !s.store.HasPendingPasswordRotation(asset.ID) {
		return nil
	}
	if (asset.AccountDisabled || asset.PasswordRotationDisabled) && !s.store.HasPendingPasswordRotation(asset.ID) {
		status := baseRotationStatus(asset, time.Now().UTC())
		return &status
	}
	s.mu.RLock()
	status, exists := s.rotationStatus[asset.ID]
	s.mu.RUnlock()
	if exists {
		copy := status
		copy.Shared = s.sharedPassword(asset.ID)
		if c := s.passwordCoordinator; c != nil {
			if _, running := c.running.Load(passwordParticipant{s.passwordScope, asset.ID}); running {
				copy.State = "rotating"
				copy.ErrorCode = ""
			}
		}
		if status.LastAttemptAt != nil {
			lastAttempt := *status.LastAttemptAt
			copy.LastAttemptAt = &lastAttempt
		}
		return &copy
	}
	now := time.Now().UTC()
	status = baseRotationStatus(asset, now)
	attemptAt, persistedState, errorCode, err := s.store.PasswordRotationAttemptStatus(asset.ID)
	if err == nil {
		if !attemptAt.IsZero() {
			lastAttempt := attemptAt
			status.LastAttemptAt = &lastAttempt
		}
		status.ErrorCode = errorCode
		switch persistedState {
		case "failed":
			status.State = "failed"
		case "rotating", "recovery_required":
			if s.store.HasPendingPasswordRotation(asset.ID) {
				status.State = "recovery_required"
				if status.ErrorCode == "" {
					status.ErrorCode = "recovery_required"
				}
			} else {
				status.State = "failed"
				if status.ErrorCode == "" {
					status.ErrorCode = "rotation_interrupted"
				}
			}
		}
	}
	if s.store.HasPendingPasswordRotation(asset.ID) {
		status.State = "recovery_required"
		if status.ErrorCode == "" {
			status.ErrorCode = "recovery_required"
		}
	}
	status.Shared = s.sharedPassword(asset.ID)
	if c := s.passwordCoordinator; c != nil {
		if _, running := c.running.Load(passwordParticipant{s.passwordScope, asset.ID}); running {
			status.State = "rotating"
			status.ErrorCode = ""
		}
	}
	return &status
}

func (s *Service) RotatePassword(ctx context.Context, id string) (ListItem, error) {
	err := s.rotatePassword(ctx, id, "manual")
	asset, exists := s.find(id)
	if !exists {
		return ListItem{}, ErrNotFound
	}
	item := ListItem{Asset: asset, Monitor: s.currentMonitorStatus(id), Permissions: []string{"connect", "manage", "view"}, PasswordRotation: s.passwordRotationStatus(asset)}
	return item, err
}

func (s *Service) ListCredentialBackups(id string) ([]CredentialBackup, error) {
	return s.store.ListCredentialBackups(id)
}

func (s *Service) CreateCredentialBackup(id, actor string) (CredentialBackup, error) {
	if actor == "" || len(actor) > 128 {
		return CredentialBackup{}, fmt.Errorf("invalid credential backup actor")
	}
	asset, err := s.claimCredentialBackupAction(id)
	if err != nil {
		return CredentialBackup{}, err
	}
	defer s.releaseRotation(id)
	if err := s.appendRotationAuditDetails(asset, "backup_started", "manual", "", "", actor, ""); err != nil {
		return CredentialBackup{}, ErrPasswordRotationFailed
	}
	backup, err := s.store.CreateCredentialBackup(id, time.Now().UTC())
	if err != nil {
		_ = s.appendRotationAuditDetails(asset, "backup_completed", "manual", "failed", classifyRotationError(err), actor, "")
		return CredentialBackup{}, err
	}
	if err := s.appendRotationAuditDetails(asset, "backup_completed", "manual", "success", "", actor, backup.ID); err != nil {
		// The completed operation is already durable; the started audit entry remains.
	}
	return backup, nil
}

func (s *Service) DeleteCredentialBackup(id, backupID, actor string) error {
	if actor == "" || len(actor) > 128 {
		return fmt.Errorf("invalid credential backup actor")
	}
	if !validCredentialBackupID(backupID) {
		return ErrCredentialBackupNotFound
	}
	asset, err := s.claimCredentialBackupAction(id)
	if err != nil {
		return err
	}
	defer s.releaseRotation(id)
	if err := s.appendRotationAuditDetails(asset, "backup_delete_started", "manual", "", "", actor, backupID); err != nil {
		return ErrPasswordRotationFailed
	}
	if err := s.store.DeleteCredentialBackup(id, backupID); err != nil {
		_ = s.appendRotationAuditDetails(asset, "backup_delete_completed", "manual", "failed", classifyRotationError(err), actor, backupID)
		return err
	}
	if err := s.appendRotationAuditDetails(asset, "backup_delete_completed", "manual", "success", "", actor, backupID); err != nil {
		// The completed operation is already durable; the started audit entry remains.
	}
	return nil
}

func (s *Service) RestoreCredentialBackup(ctx context.Context, id, backupID, actor string) (ListItem, error) {
	if actor == "" || len(actor) > 128 {
		return ListItem{}, fmt.Errorf("invalid credential backup actor")
	}
	metadata, _, _, err := s.store.CredentialBackupForRestore(id, backupID)
	if err != nil {
		return ListItem{}, err
	}
	if metadata.CredentialType == CredentialSSHKey {
		err = s.restoreKeyBackup(ctx, id, backupID, actor)
	} else {
		err = s.rotatePasswordTo(ctx, id, "restore", actor, backupID)
	}
	asset, exists := s.find(id)
	if !exists {
		return ListItem{}, ErrNotFound
	}
	item := ListItem{Asset: asset, Monitor: s.currentMonitorStatus(id), Permissions: []string{"connect", "manage", "view"}, PasswordRotation: s.passwordRotationStatus(asset)}
	return item, err
}

func (s *Service) claimCredentialBackupAction(id string) (Asset, error) {
	if c := s.passwordCoordinator; c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.blocked(s.passwordScope, id) {
			return Asset{}, ErrRotationPending
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rotationRunning[id] {
		return Asset{}, ErrRotationInProgress
	}
	asset, exists := s.find(id)
	if !exists {
		return Asset{}, ErrNotFound
	}
	if s.store.HasPendingSSHKeyChange(id) {
		return Asset{}, ErrSSHKeyPending
	}
	if s.store.HasPendingPasswordRotation(id) {
		return Asset{}, ErrRotationPending
	}
	s.rotationRunning[id] = true
	return asset, nil
}

func (s *Service) RotateDuePasswords(ctx context.Context) {
	now := time.Now().UTC()
	assets := s.store.List()
	limit := make(chan struct{}, 4)
	var workers sync.WaitGroup
	for _, asset := range assets {
		if s.store.HasPendingPasswordRotation(asset.ID) || baseRotationStatus(asset, now).State != "due" || s.rotationAttemptCoolingDown(asset.ID, now) {
			continue
		}
		select {
		case <-ctx.Done():
			workers.Wait()
			return
		case limit <- struct{}{}:
		}
		workers.Add(1)
		go func(asset Asset) {
			defer workers.Done()
			defer func() { <-limit }()
			_ = s.rotatePassword(ctx, asset.ID, "automatic")
		}(asset)
	}
	workers.Wait()
}

func (s *Service) RecoverPendingPasswordRotations(ctx context.Context) {
	if c := s.passwordCoordinator; c != nil {
		c.Recover(ctx)
		c.mu.Lock()
		defer c.mu.Unlock()
	}
	now := time.Now().UTC()
	for _, asset := range s.store.List() {
		if c := s.passwordCoordinator; c != nil && (c.blocked(s.passwordScope, asset.ID) || len(c.participants(passwordIdentity(asset))) > 1) {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		if !s.store.HasPendingPasswordRotation(asset.ID) || s.rotationAttemptCoolingDownInProcess(asset.ID, now) {
			continue
		}
		claimedAsset, err := s.claimRotation(asset.ID, now, "recovery_required", false)
		if err != nil {
			continue
		}
		asset = claimedAsset
		_, actor, backupID, _ := s.store.PendingRotationAuditMetadata(asset.ID)
		_ = s.appendRotationAuditDetails(asset, "started", "recovery", "", "", actor, backupID)
		outcome, err := s.reconcilePendingRotation(ctx, asset, "recovery", now, "rotation_failed", actor, backupID)
		if err != nil {
			s.finishRotationStatus(asset, "recovery_required", classifyRotationError(err), now)
			_ = s.appendRotationAuditDetails(asset, "completed", "recovery", "unresolved", classifyRotationError(err), actor, backupID)
		} else if outcome == "old" {
			s.finishRotationStatus(asset, "failed", "rotation_failed", now)
			_ = s.appendRotationAuditDetails(asset, "completed", "recovery", "old_credential_restored", "rotation_failed", actor, backupID)
		}
		s.releaseRotation(asset.ID)
	}
}

func (s *Service) rotatePassword(ctx context.Context, id, trigger string) error {
	return s.rotatePasswordTo(ctx, id, trigger, "", "")
}

func (s *Service) rotatePasswordTo(ctx context.Context, id, trigger, actor, backupID string) error {
	ctx, release, admissionErr := s.store.admissionGate().Enter(ctx, "credential_operations")
	if admissionErr != nil {
		return admissionErr
	}
	defer release()
	if s.passwordCoordinator != nil {
		return s.passwordCoordinator.rotate(ctx, s, id, trigger, actor, backupID)
	}
	return s.rotatePasswordToLocal(ctx, id, trigger, actor, backupID)
}

func (s *Service) rotatePasswordToLocal(ctx context.Context, id, trigger, actor, backupID string) error {
	if a, e := s.Get(id); e != nil {
		return e
	} else if !IsSSH(a) {
		return ErrUnsupportedProtocol
	}
	if backupID != "" && !validCredentialBackupID(backupID) {
		return ErrCredentialBackupNotFound
	}
	asset, exists := s.find(id)
	if !exists {
		return ErrNotFound
	}
	if backupID == "" && credentialType(asset.CredentialType) == CredentialSSHKey {
		return ErrCredentialType
	}
	if s.store.HasPendingSSHKeyChange(id) {
		return ErrSSHKeyPending
	}
	if s.store.HasPendingPasswordRotation(id) {
		return ErrRotationPending
	}
	now := time.Now().UTC()
	claimedAsset, err := s.claimRotation(id, now, "rotating", trigger == "automatic")
	if err != nil {
		return err
	}
	asset = claimedAsset
	defer s.releaseRotation(id)
	if err := s.appendRotationAuditDetails(asset, "started", trigger, "", "", actor, backupID); err != nil {
		s.finishRotationStatus(asset, "failed", "audit_write_failed", now)
		return ErrPasswordRotationFailed
	}
	_, target, currentCredentials, err := s.store.connection(id)
	if err != nil {
		return s.failRotationDetails(asset, trigger, "credential_store_failed", now, actor, backupID)
	}
	var newPassword string
	if backupID != "" {
		newPassword, err = s.store.CredentialBackupPassword(id, backupID)
		if err != nil {
			s.finishRotationStatus(asset, "failed", "credential_backup_not_found", now)
			_ = s.appendRotationAuditDetails(asset, "completed", trigger, "failed", "credential_backup_not_found", actor, backupID)
			return ErrCredentialBackupNotFound
		}
	} else {
		newPassword, err = s.generatePassword()
		if err != nil {
			return s.failRotationDetails(asset, trigger, "password_generation_failed", now, actor, backupID)
		}
	}
	if backupID != "" {
		err = s.store.BeginCredentialRestore(id, newPassword, now, actor, backupID)
	} else {
		if p := plannedPassword(ctx); p != nil {
			err = s.store.beginPasswordRotation(id, newPassword, now, "", "", "", p)
		} else {
			err = s.store.BeginPasswordRotation(id, newPassword, now)
		}
	}
	if err != nil {
		return s.failRotationDetails(asset, trigger, "credential_store_failed", now, actor, backupID)
	}
	current := currentCredentials
	if err := s.changeManagedPassword(ctx, asset, target, current, newPassword); err != nil {
		return s.reconcileAfterRotationError(ctx, asset, trigger, now, err, actor, backupID)
	}
	if err := s.verifyPassword(ctx, target, sshclient.Credentials{Password: newPassword}, 8*time.Second); err != nil {
		return s.reconcileAfterRotationError(ctx, asset, trigger, now, err, actor, backupID)
	}
	if err := s.store.CommitPasswordRotation(id, time.Now().UTC()); err != nil {
		s.finishRotationStatus(asset, "recovery_required", "credential_store_failed", now)
		_ = s.appendRotationAuditDetails(asset, "completed", trigger, "recovery_required", "credential_store_failed", actor, backupID)
		return ErrPasswordRotationFailed
	}
	s.finishRotationStatus(asset, "scheduled", "", time.Now().UTC())
	if err := s.appendRotationAuditDetails(asset, "completed", trigger, "success", "", actor, backupID); err != nil {
		s.setRotationError(asset, "audit_write_failed")
	}
	return nil
}

func (s *Service) reconcileAfterRotationError(ctx context.Context, asset Asset, trigger string, started time.Time, cause error, actor, backupID string) error {
	outcome, err := s.reconcilePendingRotation(ctx, asset, trigger, started, classifyRotationError(cause), actor, backupID)
	if err != nil {
		code := classifyRotationError(err)
		s.finishRotationStatus(asset, "recovery_required", code, started)
		_ = s.appendRotationAuditDetails(asset, "completed", trigger, "recovery_required", code, actor, backupID)
		return ErrPasswordRotationFailed
	}
	if outcome == "new" {
		return nil
	}
	s.finishRotationStatus(asset, "failed", classifyRotationError(cause), started)
	_ = s.appendRotationAuditDetails(asset, "completed", trigger, "old_credential_retained", classifyRotationError(cause), actor, backupID)
	return ErrPasswordRotationFailed
}

func (s *Service) reconcilePendingRotation(ctx context.Context, asset Asset, trigger string, started time.Time, failureCode, actor, backupID string) (string, error) {
	newPassword, err := s.store.PendingPassword(asset.ID)
	if err != nil {
		return "", err
	}
	_, target, oldCredentials, err := s.store.connection(asset.ID)
	if err != nil {
		return "", err
	}
	if err := s.verifyPassword(ctx, target, sshclient.Credentials{Password: newPassword}, 8*time.Second); err == nil {
		if err := s.store.CommitPasswordRotation(asset.ID, time.Now().UTC()); err != nil {
			return "", err
		}
		s.finishRotationStatus(asset, "scheduled", "", time.Now().UTC())
		if err := s.appendRotationAuditDetails(asset, "completed", trigger, "new_credential_recovered", "", actor, backupID); err != nil {
			s.setRotationError(asset, "audit_write_failed")
		}
		return "new", nil
	}
	if err := s.verifyPassword(ctx, target, oldCredentials, 8*time.Second); err == nil {
		if err := s.store.AbortPasswordRotation(asset.ID); err != nil {
			return "", err
		}
		return "old", nil
	}
	return "", errors.New(failureCode)
}

func (s *Service) claimRotation(id string, at time.Time, state string, requireDue bool) (Asset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rotationRunning[id] {
		return Asset{}, ErrRotationInProgress
	}
	var asset Asset
	found := false
	for _, candidate := range s.store.List() {
		if candidate.ID == id {
			asset = candidate
			found = true
			break
		}
	}
	if !found {
		return Asset{}, ErrNotFound
	}
	pending := s.store.HasPendingPasswordRotation(id)
	if state == "rotating" && pending {
		return Asset{}, ErrRotationPending
	}
	if state == "recovery_required" && !pending {
		return Asset{}, ErrNoPendingRotation
	}
	if requireDue {
		if baseRotationStatus(asset, at).State != "due" {
			return Asset{}, errRotationNotDue
		}
		lastAttempt, _, _, err := s.store.PasswordRotationAttemptStatus(id)
		if err != nil {
			return Asset{}, err
		}
		if !lastAttempt.IsZero() && at.Before(lastAttempt.Add(rotationRetryInterval)) {
			return Asset{}, errRotationCoolingDown
		}
	}
	s.rotationRunning[id] = true
	if err := s.store.RecordPasswordRotationAttempt(id, at, state); err != nil {
		delete(s.rotationRunning, id)
		return Asset{}, fmt.Errorf("persist SSH password rotation attempt: %w", err)
	}
	status := baseRotationStatus(asset, at)
	status.State = state
	lastAttempt := at
	status.LastAttemptAt = &lastAttempt
	s.rotationStatus[id] = status
	return asset, nil
}

func (s *Service) releaseRotation(id string) {
	s.mu.Lock()
	delete(s.rotationRunning, id)
	s.mu.Unlock()
}

func (s *Service) finishRotationStatus(asset Asset, state, errorCode string, at time.Time) {
	status := baseRotationStatus(asset, at)
	if refreshed, err := s.Get(asset.ID); err == nil {
		status = baseRotationStatus(refreshed, at)
	}
	if err := s.store.SetPasswordRotationResult(asset.ID, state, errorCode); err != nil && errorCode == "" {
		errorCode = "rotation_status_persist_failed"
	}
	status.State = state
	status.ErrorCode = errorCode
	lastAttempt := at
	status.LastAttemptAt = &lastAttempt
	s.mu.Lock()
	s.rotationStatus[asset.ID] = status
	s.mu.Unlock()
}

func (s *Service) setRotationError(asset Asset, errorCode string) {
	s.mu.Lock()
	status := s.rotationStatus[asset.ID]
	status.ErrorCode = errorCode
	s.rotationStatus[asset.ID] = status
	s.mu.Unlock()
	if status.State == "scheduled" || status.State == "failed" || status.State == "recovery_required" {
		_ = s.store.SetPasswordRotationResult(asset.ID, status.State, errorCode)
	}
}

func (s *Service) rotationAttemptCoolingDown(id string, now time.Time) bool {
	s.mu.RLock()
	status, exists := s.rotationStatus[id]
	s.mu.RUnlock()
	if exists && status.LastAttemptAt != nil {
		return now.Before(status.LastAttemptAt.Add(rotationRetryInterval))
	}
	attemptAt, _, _, err := s.store.PasswordRotationAttemptStatus(id)
	if err != nil {
		return true
	}
	return !attemptAt.IsZero() && now.Before(attemptAt.Add(rotationRetryInterval))
}

func (s *Service) rotationAttemptCoolingDownInProcess(id string, now time.Time) bool {
	s.mu.RLock()
	status, exists := s.rotationStatus[id]
	s.mu.RUnlock()
	return exists && status.LastAttemptAt != nil && now.Before(status.LastAttemptAt.Add(rotationRetryInterval))
}

func (s *Service) failRotation(asset Asset, trigger, code string, started time.Time) error {
	return s.failRotationDetails(asset, trigger, code, started, "", "")
}

func (s *Service) failRotationDetails(asset Asset, trigger, code string, started time.Time, actor, backupID string) error {
	s.finishRotationStatus(asset, "failed", code, started)
	_ = s.appendRotationAuditDetails(asset, "completed", trigger, "failed", code, actor, backupID)
	return ErrPasswordRotationFailed
}

func (s *Service) appendRotationAudit(asset Asset, event, trigger, result, errorCode string) error {
	return s.appendRotationAuditDetails(asset, event, trigger, result, errorCode, "", "")
}

func (s *Service) appendRotationAuditDetails(asset Asset, event, trigger, result, errorCode, actor, backupID string, operationID ...string) error {
	record := rotationAuditRecord{
		Event: event, AssetID: asset.ID, AssetName: asset.Name, Account: asset.Username,
		Trigger: trigger, Actor: actor, BackupID: backupID, Result: result, ErrorCode: errorCode, OccurredAt: time.Now().UTC(),
	}
	if len(operationID) > 0 {
		record.OperationID = operationID[0]
	}
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode SSH password rotation audit: %w", err)
	}
	s.rotationAuditMux.Lock()
	defer s.rotationAuditMux.Unlock()
	path := filepath.Join(filepath.Dir(s.store.path), "credential-rotations", "index.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create SSH password rotation audit directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open SSH password rotation audit: %w", err)
	}
	defer file.Close()
	if _, err := file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write SSH password rotation audit: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync SSH password rotation audit: %w", err)
	}
	return nil
}

func sshTarget(asset Asset) sshclient.Target {
	return sshclient.Target{
		Host: asset.Host, Port: asset.Port, Username: asset.Username,
		HostKeyFingerprint: asset.HostKeyFingerprint,
	}
}

func classifyRotationError(err error) string {
	var gateway *sshclient.GatewayError
	if errors.As(err, &gateway) {
		return "gateway_failed"
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "fingerprint mismatch"):
		return "host_key_mismatch"
	case strings.Contains(message, "authenticate"):
		return "authentication_failed"
	case strings.Contains(message, "privilege"), strings.Contains(message, "sudo"), strings.Contains(message, "permission"):
		return "permission_denied"
	case strings.Contains(message, "connect to ssh host"):
		return "connection_failed"
	default:
		return "rotation_failed"
	}
}

func baseRotationStatus(asset Asset, at time.Time) PasswordRotationStatus {
	if asset.AccountDisabled || asset.PasswordRotationDisabled {
		return PasswordRotationStatus{State: "disabled", LastRotatedAt: asset.PasswordRotatedAt}
	}
	if !IsSSH(asset) {
		return PasswordRotationStatus{State: "not_applicable"}
	}
	if credentialType(asset.CredentialType) == CredentialSSHKey {
		return PasswordRotationStatus{State: "not_applicable"}
	}
	lastRotated := asset.PasswordRotatedAt
	if lastRotated.IsZero() {
		lastRotated = asset.CreatedAt
	}
	state := "scheduled"
	if !at.Before(lastRotated.Add(PasswordRotationInterval)) {
		state = "due"
	}
	return PasswordRotationStatus{
		State: state, LastRotatedAt: lastRotated,
		NextRotationAt: lastRotated.Add(PasswordRotationInterval),
	}
}
