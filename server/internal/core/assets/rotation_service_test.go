package assets

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
)

func TestPasswordRotationCommitsAfterNewCredentialVerification(t *testing.T) {
	service, store, asset, path := newRotationServiceTest(t)
	gateway, e := store.Create(Asset{ID: "rotation-gateway", Name: "rotation-gateway", Host: "gateway.invalid", Port: 22, Username: "gateway", HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, "synthetic-gateway-secret")
	if e != nil {
		t.Fatal(e)
	}
	asset.GatewayID = gateway.ID
	if _, e = store.Update(asset, ""); e != nil {
		t.Fatal(e)
	}
	remotePassword := "initial-credential"
	service.changePassword = func(_ context.Context, target sshclient.Target, current sshclient.Credentials, newPassword string, _ time.Duration) error {
		if len(target.Gateways) != 1 || target.Gateways[0].Credentials.Password != "synthetic-gateway-secret" {
			t.Fatal("rotation did not use the configured gateway")
		}
		if target.Username != asset.Username || current.Password != remotePassword {
			return errors.New("unexpected current credential")
		}
		remotePassword = newPassword
		return nil
	}
	service.verifyPassword = func(_ context.Context, _ sshclient.Target, credentials sshclient.Credentials, _ time.Duration) error {
		if credentials.Password != remotePassword {
			return errors.New("authentication failed")
		}
		return nil
	}

	item, err := service.RotatePassword(context.Background(), asset.ID)
	if err != nil {
		t.Fatalf("RotatePassword() error = %v", err)
	}
	storedPassword, err := store.Password(asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	if storedPassword == "initial-credential" || storedPassword != remotePassword {
		t.Fatal("vault did not commit the verified remote credential")
	}
	if store.HasPendingPasswordRotation(asset.ID) {
		t.Fatal("successful rotation left a pending credential")
	}
	if item.PasswordRotation == nil || item.PasswordRotation.State != "scheduled" || item.PasswordRotation.NextRotationAt.Sub(item.PasswordRotation.LastRotatedAt) != PasswordRotationInterval {
		t.Fatalf("rotation response status = %+v", item.PasswordRotation)
	}
	assetsFile, err := os.ReadFile(filepath.Join(filepath.Dir(path), "assets.json"))
	if err != nil {
		t.Fatal(err)
	}
	auditFile, err := os.ReadFile(filepath.Join(filepath.Dir(path), "credential-rotations", "index.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(assetsFile), remotePassword) || strings.Contains(string(auditFile), remotePassword) {
		t.Fatal("rotation password was written in plaintext to storage or audit")
	}
	if !strings.Contains(string(auditFile), `"event":"started"`) || !strings.Contains(string(auditFile), `"result":"success"`) {
		t.Fatalf("rotation audit is incomplete: %s", auditFile)
	}
}

func TestPasswordRotationReconcilesAmbiguousRemoteResult(t *testing.T) {
	service, store, asset, _ := newRotationServiceTest(t)
	remotePassword := "initial-credential"
	service.changePassword = func(_ context.Context, _ sshclient.Target, current sshclient.Credentials, newPassword string, _ time.Duration) error {
		if current.Password != remotePassword {
			return errors.New("unexpected current credential")
		}
		remotePassword = newPassword
		return errors.New("connection closed after remote change")
	}
	service.verifyPassword = func(_ context.Context, _ sshclient.Target, credentials sshclient.Credentials, _ time.Duration) error {
		if credentials.Password != remotePassword {
			return errors.New("authentication failed")
		}
		return nil
	}
	if _, err := service.RotatePassword(context.Background(), asset.ID); err != nil {
		t.Fatalf("ambiguous rotation should recover the new credential: %v", err)
	}
	storedPassword, err := store.Password(asset.ID)
	if err != nil || storedPassword != remotePassword || store.HasPendingPasswordRotation(asset.ID) {
		t.Fatalf("reconciled credential = %q, pending=%v, err=%v", storedPassword, store.HasPendingPasswordRotation(asset.ID), err)
	}
}

func TestPasswordRotationRetainsBothCredentialsWhenRemoteCannotBeVerified(t *testing.T) {
	service, store, asset, _ := newRotationServiceTest(t)
	service.changePassword = func(_ context.Context, _ sshclient.Target, _ sshclient.Credentials, _ string, _ time.Duration) error {
		return errors.New("remote command outcome unknown")
	}
	service.verifyPassword = func(context.Context, sshclient.Target, sshclient.Credentials, time.Duration) error {
		return errors.New("host unavailable")
	}
	if _, err := service.RotatePassword(context.Background(), asset.ID); !errors.Is(err, ErrPasswordRotationFailed) {
		t.Fatalf("RotatePassword() error = %v, want ErrPasswordRotationFailed", err)
	}
	if !store.HasPendingPasswordRotation(asset.ID) {
		t.Fatal("unverified rotation discarded its recovery credential")
	}
	item := service.List()[0]
	if item.PasswordRotation == nil || item.PasswordRotation.State != "recovery_required" {
		t.Fatalf("rotation status = %+v, want recovery_required", item.PasswordRotation)
	}
	active, err := store.Password(asset.ID)
	if err != nil || active != "initial-credential" {
		t.Fatalf("active credential changed before verification: %q, %v", active, err)
	}
}

func TestCredentialBackupIsEncryptedMetadataOnlyAndSurvivesReload(t *testing.T) {
	store, path, asset := createRotationStoreTest(t, time.Now().UTC())
	backup, err := store.CreateCredentialBackup(asset.ID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	metadata, err := json.Marshal(backup)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(metadata), "initial-credential") {
		t.Fatal("credential backup metadata exposed the password")
	}
	contents := string(mustReadFile(t, path))
	if strings.Contains(contents, "initial-credential") {
		t.Fatal("asset store contains a plaintext credential backup")
	}

	reopened, err := OpenStore(path, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	backups, err := reopened.ListCredentialBackups(asset.ID)
	if err != nil || len(backups) != 1 || backups[0].ID != backup.ID {
		t.Fatalf("credential backups after reload = %+v, %v", backups, err)
	}
	password, err := reopened.CredentialBackupPassword(asset.ID, backup.ID)
	if err != nil || password != "initial-credential" {
		t.Fatalf("decrypted backup = %q, %v", password, err)
	}
}

func TestCredentialBackupLimitAndAutomaticPruning(t *testing.T) {
	store, _, asset := createRotationStoreTest(t, time.Now().UTC())
	for range maxCredentialBackups {
		if _, err := store.CreateCredentialBackup(asset.ID, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.CreateCredentialBackup(asset.ID, time.Now().UTC()); !errors.Is(err, ErrCredentialBackupLimit) {
		t.Fatalf("backup past manual limit = %v, want ErrCredentialBackupLimit", err)
	}
	if _, err := store.Update(asset, "replacement-credential"); err != nil {
		t.Fatalf("credential update should prune the oldest backup: %v", err)
	}
	backups, err := store.ListCredentialBackups(asset.ID)
	if err != nil || len(backups) != maxCredentialBackups {
		t.Fatalf("backup count after automatic pruning = %d, %v", len(backups), err)
	}
}

func TestCredentialBackupRestoreChangesRemoteBeforePromotingVaultCredential(t *testing.T) {
	service, store, asset, path := newRotationServiceTest(t)
	backup, err := store.CreateCredentialBackup(asset.ID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(asset, "current-credential"); err != nil {
		t.Fatal(err)
	}
	remotePassword := "current-credential"
	service.changePassword = func(_ context.Context, target sshclient.Target, current sshclient.Credentials, next string, _ time.Duration) error {
		if target.Host != asset.Host || target.HostKeyFingerprint != asset.HostKeyFingerprint || current.Password != remotePassword || next != "initial-credential" {
			return errors.New("restore did not use the expected pinned SSH credentials")
		}
		remotePassword = next
		return nil
	}
	service.verifyPassword = func(_ context.Context, _ sshclient.Target, credentials sshclient.Credentials, _ time.Duration) error {
		active, err := store.Password(asset.ID)
		if err != nil || active != "current-credential" {
			return errors.New("vault credential was promoted before remote verification")
		}
		if credentials.Password != remotePassword {
			return errors.New("restored SSH credential did not authenticate")
		}
		return nil
	}

	item, err := service.RestoreCredentialBackup(context.Background(), asset.ID, backup.ID, "admin.user")
	if err != nil {
		t.Fatalf("RestoreCredentialBackup() error = %v", err)
	}
	active, err := store.Password(asset.ID)
	if err != nil || active != "initial-credential" || remotePassword != active {
		t.Fatalf("active/remote credential = %q/%q, %v", active, remotePassword, err)
	}
	if item.PasswordRotation == nil || item.PasswordRotation.State != "scheduled" || store.HasPendingPasswordRotation(asset.ID) {
		t.Fatalf("restore response/status = %+v, pending=%v", item.PasswordRotation, store.HasPendingPasswordRotation(asset.ID))
	}
	contents := string(mustReadFile(t, path))
	audit := string(mustReadFile(t, filepath.Join(filepath.Dir(path), "credential-rotations", "index.jsonl")))
	if strings.Contains(contents, "initial-credential") || strings.Contains(contents, "current-credential") || strings.Contains(audit, "initial-credential") || strings.Contains(audit, "current-credential") {
		t.Fatal("restore credential leaked to storage or audit")
	}
	if !strings.Contains(audit, `"actor":"admin.user"`) || !strings.Contains(audit, `"backup_id":"`+backup.ID+`"`) {
		t.Fatalf("restore audit is missing actor or backup ID: %s", audit)
	}
}

func TestUnverifiedCredentialBackupRestoreKeepsActiveCredentialAndRecoverySecret(t *testing.T) {
	service, store, asset, path := newRotationServiceTest(t)
	backup, err := store.CreateCredentialBackup(asset.ID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(asset, "current-credential"); err != nil {
		t.Fatal(err)
	}
	service.changePassword = func(context.Context, sshclient.Target, sshclient.Credentials, string, time.Duration) error {
		return errors.New("remote change result is ambiguous")
	}
	service.verifyPassword = func(context.Context, sshclient.Target, sshclient.Credentials, time.Duration) error {
		return errors.New("host cannot be verified")
	}
	if _, err := service.RestoreCredentialBackup(context.Background(), asset.ID, backup.ID, "admin.user"); !errors.Is(err, ErrPasswordRotationFailed) {
		t.Fatalf("restore error = %v, want ErrPasswordRotationFailed", err)
	}
	active, err := store.Password(asset.ID)
	if err != nil || active != "current-credential" {
		t.Fatalf("active credential changed before verification: %q, %v", active, err)
	}
	pending, err := store.PendingPassword(asset.ID)
	if err != nil || pending != "initial-credential" || !store.HasPendingPasswordRotation(asset.ID) {
		t.Fatalf("recovery credential = %q, pending=%v, err=%v", pending, store.HasPendingPasswordRotation(asset.ID), err)
	}
	trigger, actor, backupID, err := store.PendingRotationAuditMetadata(asset.ID)
	if err != nil || trigger != "credential_restore" || actor != "admin.user" || backupID != backup.ID {
		t.Fatalf("pending restore metadata = %q/%q/%q, %v", trigger, actor, backupID, err)
	}
	if strings.Contains(string(mustReadFile(t, path)), "initial-credential") {
		t.Fatal("pending restore credential was stored as plaintext")
	}

	reopened, err := OpenStore(path, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("reopen pending credential restore: %v", err)
	}
	recoveryService := NewServiceWithPasswordRotation(reopened, nil, nil,
		func(_ context.Context, _ sshclient.Target, credentials sshclient.Credentials, _ time.Duration) error {
			if credentials.Password != "initial-credential" {
				return errors.New("restored credential did not authenticate after restart")
			}
			return nil
		},
	)
	recoveryService.RecoverPendingPasswordRotations(context.Background())
	recovered, err := reopened.Password(asset.ID)
	if err != nil || recovered != "initial-credential" || reopened.HasPendingPasswordRotation(asset.ID) {
		t.Fatalf("recovered credential after restart = %q, pending=%v, err=%v", recovered, reopened.HasPendingPasswordRotation(asset.ID), err)
	}
	audit := string(mustReadFile(t, filepath.Join(filepath.Dir(path), "credential-rotations", "index.jsonl")))
	if !strings.Contains(audit, `"trigger":"recovery"`) || !strings.Contains(audit, `"actor":"admin.user"`) || !strings.Contains(audit, `"backup_id":"`+backup.ID+`"`) {
		t.Fatalf("restore recovery audit lost its actor or backup metadata: %s", audit)
	}
}

func TestAutomaticPasswordRotationRunsAfterSevenDays(t *testing.T) {
	store, path, asset := createRotationStoreTest(t, time.Now().UTC().Add(-PasswordRotationInterval-time.Minute))
	remotePassword := "initial-credential"
	change := func(_ context.Context, _ sshclient.Target, current sshclient.Credentials, newPassword string, _ time.Duration) error {
		if current.Password != remotePassword {
			return errors.New("unexpected current credential")
		}
		remotePassword = newPassword
		return nil
	}
	verify := func(_ context.Context, _ sshclient.Target, credentials sshclient.Credentials, _ time.Duration) error {
		if credentials.Password != remotePassword {
			return errors.New("authentication failed")
		}
		return nil
	}
	service := NewServiceWithPasswordRotation(store, nil, change, verify)
	service.RotateDuePasswords(context.Background())
	storedPassword, err := store.Password(asset.ID)
	if err != nil || storedPassword == "initial-credential" || storedPassword != remotePassword {
		t.Fatalf("due credential was not rotated: password=%q remote=%q err=%v", storedPassword, remotePassword, err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), "credential-rotations", "index.jsonl")); err != nil {
		t.Fatalf("automatic rotation audit file missing: %v", err)
	}
}

func TestAutomaticPasswordRotationCooldownSurvivesServiceRestart(t *testing.T) {
	store, path, asset := createRotationStoreTest(t, time.Now().UTC().Add(-PasswordRotationInterval-time.Minute))
	remotePassword := "initial-credential"
	failedService := NewServiceWithPasswordRotation(store, nil,
		func(context.Context, sshclient.Target, sshclient.Credentials, string, time.Duration) error {
			return errors.New("connect to ssh host failed")
		},
		func(_ context.Context, _ sshclient.Target, credentials sshclient.Credentials, _ time.Duration) error {
			if credentials.Password != remotePassword {
				return errors.New("authentication failed")
			}
			return nil
		},
	)
	failedService.RotateDuePasswords(context.Background())
	if status := failedService.passwordRotationStatus(asset); status.State != "failed" {
		t.Fatalf("failed rotation status = %+v, want failed", status)
	}

	reopened, err := OpenStore(path, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	changeCalls := 0
	restartedService := NewServiceWithPasswordRotation(reopened, nil,
		func(_ context.Context, _ sshclient.Target, current sshclient.Credentials, newPassword string, _ time.Duration) error {
			changeCalls++
			if current.Password != remotePassword {
				return errors.New("unexpected current credential")
			}
			remotePassword = newPassword
			return nil
		},
		func(_ context.Context, _ sshclient.Target, credentials sshclient.Credentials, _ time.Duration) error {
			if credentials.Password != remotePassword {
				return errors.New("authentication failed")
			}
			return nil
		},
	)
	restartedService.RotateDuePasswords(context.Background())
	if changeCalls != 0 {
		t.Fatalf("rotation retried immediately after restart, change calls = %d", changeCalls)
	}
	if status := restartedService.passwordRotationStatus(asset); status.State != "failed" {
		t.Fatalf("restarted rotation status = %+v, want failed", status)
	}
	if err := reopened.RecordPasswordRotationAttempt(asset.ID, time.Now().UTC().Add(-rotationRetryInterval-time.Second), "rotating"); err != nil {
		t.Fatal(err)
	}
	if err := reopened.SetPasswordRotationResult(asset.ID, "failed", "connection_failed"); err != nil {
		t.Fatal(err)
	}
	restartedService.RotateDuePasswords(context.Background())
	if changeCalls != 1 {
		t.Fatalf("rotation was not retried after the persisted cooldown expired, change calls = %d", changeCalls)
	}
}

func TestAssetMutationsAreBlockedWhilePasswordRotationIsClaimed(t *testing.T) {
	service, store, asset, _ := newRotationServiceTest(t)
	if _, err := service.claimRotation(asset.ID, time.Now().UTC(), "rotating", false); err != nil {
		t.Fatalf("claim rotation: %v", err)
	}
	defer service.releaseRotation(asset.ID)

	input := Input{
		Name: asset.Name, Host: asset.Host, Group: asset.Group, NodeID: asset.NodeID,
		Username: asset.Username, HostKeyFingerprint: asset.HostKeyFingerprint,
		Port: asset.Port, Remark: asset.Remark,
	}
	if _, err := service.Update(asset.ID, input); !errors.Is(err, ErrRotationInProgress) {
		t.Fatalf("asset update during rotation = %v, want ErrRotationInProgress", err)
	}
	if err := service.Delete(asset.ID); !errors.Is(err, ErrRotationInProgress) {
		t.Fatalf("asset delete during rotation = %v, want ErrRotationInProgress", err)
	}
	if assets := store.List(); len(assets) != 1 || assets[0].ID != asset.ID {
		t.Fatalf("asset mutation changed inventory during rotation: %+v", assets)
	}
}

func TestPasswordRotationTimestampPersistsAcrossStoreReopen(t *testing.T) {
	store, path, asset := createRotationStoreTest(t, time.Now().UTC().Add(-3*24*time.Hour))
	rotatedAt := time.Now().UTC().Truncate(time.Second)
	if err := store.BeginPasswordRotation(asset.ID, "new-generated-credential-000000000001", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitPasswordRotation(asset.ID, rotatedAt); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenStore(path, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	items := reopened.List()
	if len(items) != 1 || !items[0].PasswordRotatedAt.Equal(rotatedAt) {
		t.Fatalf("rotation timestamp after reopen = %v, want %v", items, rotatedAt)
	}
	if !strings.Contains(string(mustReadFile(t, path)), `"password_rotated_at"`) {
		t.Fatal("rotation timestamp was not persisted in the private asset store")
	}
}

func TestPendingPasswordRotationRecoversAfterServiceRestart(t *testing.T) {
	store, path, asset := createRotationStoreTest(t, time.Now().UTC())
	const pendingPassword = "new-generated-credential-000000000001"
	if err := store.BeginPasswordRotation(asset.ID, pendingPassword, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenStore(path, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	service := NewServiceWithPasswordRotation(reopened, nil, nil, func(_ context.Context, _ sshclient.Target, credentials sshclient.Credentials, _ time.Duration) error {
		if credentials.Password != pendingPassword {
			return errors.New("authentication failed")
		}
		return nil
	})
	service.RecoverPendingPasswordRotations(context.Background())

	activePassword, err := reopened.Password(asset.ID)
	if err != nil || activePassword != pendingPassword || reopened.HasPendingPasswordRotation(asset.ID) {
		t.Fatalf("recovered active credential = %q, pending=%v, err=%v", activePassword, reopened.HasPendingPasswordRotation(asset.ID), err)
	}
}

func newRotationServiceTest(t *testing.T) (*Service, *Store, Asset, string) {
	t.Helper()
	store, path, asset := createRotationStoreTest(t, time.Now().UTC())
	return NewServiceWithPasswordRotation(store, nil, nil, nil), store, asset, path
}

func createRotationStoreTest(t *testing.T, rotatedAt time.Time) (*Store, string, Asset) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "assets.json")
	store, err := OpenStore(path, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	asset := Asset{
		ID: "asset-rotation-01", Name: "rotation-host", Host: "192.0.2.15", Username: "deploy",
		HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Port: 22,
		CreatedAt: rotatedAt, UpdatedAt: rotatedAt, PasswordRotatedAt: rotatedAt,
	}
	if _, err := store.Create(asset, "initial-credential"); err != nil {
		t.Fatal(err)
	}
	return store, path, asset
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
