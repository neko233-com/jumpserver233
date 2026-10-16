package assets

import (
	"context"
	"time"
)

// Restoring a key changes only the vault's selected credential. It never writes
// authorized_keys or assumes that a historical key remains valid remotely.
func (s *Service) restoreKeyBackup(ctx context.Context, id, backupID, actor string) error {
	asset, e := s.claimCredentialBackupAction(id)
	if e != nil {
		return e
	}
	defer s.releaseRotation(id)
	if e = s.appendRotationAuditDetails(asset, "key_restore_started", "restore", "", "", actor, backupID); e != nil {
		return ErrPasswordRotationFailed
	}
	metadata, candidate, version, e := s.store.CredentialBackupForRestore(id, backupID)
	if e != nil {
		return e
	}
	if metadata.CredentialType != CredentialSSHKey {
		return ErrCredentialType
	}
	_, target, _, e := s.store.connection(id)
	if e == nil {
		e = s.verifyPassword(ctx, target, candidate, 8*time.Second)
	}
	if e != nil {
		_ = s.appendRotationAuditDetails(asset, "key_restore_completed", "restore", "failed", classifyRotationError(e), actor, backupID)
		return ErrPasswordRotationFailed
	}
	if e = s.store.RestoreKeyCredential(id, backupID, version); e != nil {
		_ = s.appendRotationAuditDetails(asset, "key_restore_completed", "restore", "failed", "credential_changed", actor, backupID)
		return e
	}
	s.mu.Lock()
	delete(s.rotationStatus, id)
	s.mu.Unlock()
	_ = s.appendRotationAuditDetails(asset, "key_restore_completed", "restore", "success", "", actor, backupID)
	return nil
}
