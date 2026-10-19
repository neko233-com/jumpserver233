package releasebundle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/maintenance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func installFixture(t *testing.T) InstallOptions {
	t.Helper()
	archive, sha := fixture(t, "install")
	parent := t.TempDir()
	root := filepath.Join(parent, "versions")
	data := filepath.Join(parent, "data")
	_, e := Stage(context.Background(), archive, sha, runtime.GOOS, runtime.GOARCH, root)
	require.NoError(t, e)
	key, e := assets.LoadOrCreateVaultKey(data, "")
	require.NoError(t, e)
	require.NoError(t, maintenance.RecordMode(data, false))
	require.NoError(t, maintenance.RecordVaultKey(data, key))
	require.NoError(t, os.WriteFile(filepath.Join(data, "sentinel"), []byte("preserve-before-upgrade"), 0600))
	return InstallOptions{Root: root, DataDir: data, ArchiveSHA256: sha, RequestID: "install-request-001", Revision: 0, SourceVersion: "v1.2.2", Passphrase: []byte("synthetic-install-checkpoint-password")}
}
func successfulChecker(ctx context.Context, executable, web, data, id string) error { return ctx.Err() }
func installRoot(t *testing.T, path string) *stagingRoot {
	t.Helper()
	s, e := openStagingRoot(path, runtime.GOOS, runtime.GOARCH, false)
	require.NoError(t, e)
	return s
}

func TestNativeInstallCheckpointSelectionIdempotenceAndRevision(t *testing.T) {
	opt := installFixture(t)
	calls := 0
	check := func(ctx context.Context, executable, web, data, id string) error {
		calls++
		g, e := maintenance.ReadUpgradeGuard(data)
		require.NoError(t, e)
		assert.Equal(t, "pending", g.Phase)
		assert.Equal(t, id, g.ID)
		assert.ErrorIs(t, maintenance.CheckUpgradeGuard(data, "", g.BinarySHA256), maintenance.ErrUpgradePending)
		assert.NoError(t, maintenance.CheckUpgradeGuard(data, id, g.BinarySHA256))
		require.NoError(t, os.WriteFile(filepath.Join(data, "migrated"), []byte("target data"), 0600))
		return nil
	}
	r, e := install(context.Background(), opt, check)
	require.NoError(t, e)
	assert.Equal(t, "selected", r.Status)
	assert.Equal(t, 1, r.Revision)
	assert.NotEmpty(t, r.Backup.BackupID)
	assert.FileExists(t, r.BackupFile)
	g, e := maintenance.ReadUpgradeGuard(opt.DataDir)
	require.NoError(t, e)
	assert.Equal(t, "active", g.Phase)
	assert.NoError(t, maintenance.CheckUpgradeGuard(opt.DataDir, "", g.BinarySHA256))
	assert.ErrorIs(t, maintenance.CheckUpgradeGuard(opt.DataDir, r.ID, g.BinarySHA256), maintenance.ErrUpgradePending)
	again, e := install(context.Background(), opt, check)
	require.NoError(t, e)
	assert.True(t, again.Unchanged)
	assert.Equal(t, r.ID, again.ID)
	assert.Equal(t, 1, calls)
	assert.FileExists(t, filepath.Join(opt.DataDir, "migrated"))
	changed := opt
	changed.ArchiveSHA256 = strings.Repeat("0", 64)
	_, e = install(context.Background(), changed, check)
	assert.ErrorIs(t, e, ErrInstallConflict)
	changed = opt
	changed.RequestID = "install-request-002"
	_, e = install(context.Background(), changed, check)
	assert.ErrorIs(t, e, ErrInstallConflict)
	changed.Revision = 1
	noOp, e := install(context.Background(), changed, check)
	require.NoError(t, e)
	assert.True(t, noOp.Unchanged)
	assert.Equal(t, 1, calls)
	state, e := InstallationStatus(context.Background(), opt.Root)
	require.NoError(t, e)
	assert.Len(t, state.Receipts, 1)
	assert.Equal(t, opt.ArchiveSHA256, state.Current.ArchiveSHA256)
}
func TestNativeInstallFailedPreflightRestoresDamagedModeAndEveryDataFile(t *testing.T) {
	opt := installFixture(t)
	check := func(context.Context, string, string, string, string) error {
		require.NoError(t, os.WriteFile(filepath.Join(opt.DataDir, "sentinel"), []byte("bad migration"), 0600))
		require.NoError(t, os.WriteFile(filepath.Join(opt.DataDir, ".jms233-storage.json"), []byte("corrupt target mode"), 0600))
		require.NoError(t, os.WriteFile(filepath.Join(opt.DataDir, "target-only"), []byte("bad"), 0600))
		return errors.New("synthetic failed target")
	}
	r, e := install(context.Background(), opt, check)
	require.ErrorIs(t, e, ErrPreflightRolledBack)
	assert.Equal(t, "rolled_back", r.Status)
	assert.Zero(t, r.Revision)
	assert.NotEmpty(t, r.PreviousDataDir)
	body, e := os.ReadFile(filepath.Join(opt.DataDir, "sentinel"))
	require.NoError(t, e)
	assert.Equal(t, "preserve-before-upgrade", string(body))
	assert.NoFileExists(t, filepath.Join(opt.DataDir, "target-only"))
	assert.FileExists(t, filepath.Join(r.PreviousDataDir, "target-only"))
	assert.NoError(t, maintenance.CheckUpgradeGuard(opt.DataDir, "", ""))
	again, e := install(context.Background(), opt, successfulChecker)
	require.ErrorIs(t, e, ErrPreflightRolledBack)
	assert.True(t, again.Unchanged)
	state, e := InstallationStatus(context.Background(), opt.Root)
	require.NoError(t, e)
	assert.Empty(t, state.Current.ArchiveSHA256)
	assert.Len(t, state.Receipts, 1)
	opt.RequestID = "install-request-003"
	_, e = install(context.Background(), opt, successfulChecker)
	require.NoError(t, e)
}
func TestNativeInstallRejectsLegacySourceClusterTargetAndDataBinding(t *testing.T) {
	t.Run("source baseline", func(t *testing.T) {
		opt := installFixture(t)
		require.NoError(t, os.WriteFile(filepath.Join(opt.DataDir, ".jms233-storage.json"), []byte(`{"version":1,"mode":"standalone"}`), 0600))
		_, e := install(context.Background(), opt, successfulChecker)
		assert.ErrorIs(t, e, maintenance.ErrInvalid)
	})
	t.Run("cluster", func(t *testing.T) {
		opt := installFixture(t)
		require.NoError(t, maintenance.RecordMode(opt.DataDir, true))
		_, e := install(context.Background(), opt, successfulChecker)
		assert.ErrorIs(t, e, maintenance.ErrCluster)
	})
	t.Run("legacy target", func(t *testing.T) {
		opt := installFixture(t)
		archive, sha := fixture(t, "install-legacy")
		_, e := Stage(context.Background(), archive, sha, runtime.GOOS, runtime.GOARCH, opt.Root)
		require.NoError(t, e)
		opt.ArchiveSHA256 = sha
		_, e = install(context.Background(), opt, successfulChecker)
		assert.ErrorIs(t, e, ErrInvalid)
	})
	t.Run("overlap", func(t *testing.T) {
		opt := installFixture(t)
		opt.DataDir = opt.Root
		_, e := install(context.Background(), opt, successfulChecker)
		assert.ErrorIs(t, e, ErrInstallConflict)
	})
	t.Run("busy", func(t *testing.T) {
		opt := installFixture(t)
		lock, e := maintenance.Acquire(opt.DataDir)
		require.NoError(t, e)
		defer lock.Close()
		_, e = install(context.Background(), opt, successfulChecker)
		assert.ErrorIs(t, e, maintenance.ErrBusy)
	})
	t.Run("different data", func(t *testing.T) {
		opt := installFixture(t)
		_, e := install(context.Background(), opt, successfulChecker)
		require.NoError(t, e)
		opt.DataDir = t.TempDir()
		opt.Revision = 1
		opt.RequestID = "different-data-01"
		_, e = install(context.Background(), opt, successfulChecker)
		assert.ErrorIs(t, e, ErrInstallConflict)
	})
}
func TestNativeInstallUpgradeKeepsGuardAndRejectsDowngradeOrSameVersionRebuild(t *testing.T) {
	opt := installFixture(t)
	initialOpt := opt
	first, e := install(context.Background(), opt, successfulChecker)
	require.NoError(t, e)
	archive, sha := fixture(t, "install-v1.2.4")
	_, e = Stage(context.Background(), archive, sha, runtime.GOOS, runtime.GOARCH, opt.Root)
	require.NoError(t, e)
	opt.ArchiveSHA256 = sha
	opt.Revision = 1
	opt.RequestID = "install-request-next"
	r, e := install(context.Background(), opt, func(context.Context, string, string, string, string) error { return errors.New("failed upgrade") })
	require.ErrorIs(t, e, ErrPreflightRolledBack)
	assert.Equal(t, first.Current, r.Current)
	state, e := InstallationStatus(context.Background(), opt.Root)
	require.NoError(t, e)
	assert.Equal(t, first.Current, state.Current)
	opt.RequestID = "install-request-next2"
	r, e = install(context.Background(), opt, successfulChecker)
	require.NoError(t, e)
	assert.Equal(t, 2, r.Revision)
	assert.Equal(t, "v1.2.3", r.Backup.Version)
	opt.Revision = 2
	opt.RequestID = "install-request-old"
	opt.ArchiveSHA256 = first.Current.ArchiveSHA256
	_, e = install(context.Background(), opt, successfulChecker)
	assert.ErrorIs(t, e, ErrInstallConflict)
	historical, e := install(context.Background(), initialOpt, func(context.Context, string, string, string, string) error {
		t.Fatal("historical receipt replay executed a target")
		return nil
	})
	require.NoError(t, e)
	assert.True(t, historical.Unchanged)
	assert.Equal(t, 1, historical.Revision)
	state, e = InstallationStatus(context.Background(), opt.Root)
	require.NoError(t, e)
	assert.Equal(t, 2, state.Revision)
	assert.Equal(t, "v1.2.4", state.Current.Version)
}

func pendingInstall(t *testing.T, opt InstallOptions, phase string) upgradeJournal {
	t.Helper()
	s := installRoot(t, opt.Root)
	defer s.close()
	before, e := s.installation()
	require.NoError(t, e)
	data, e := canonicalData(s, opt.DataDir)
	require.NoError(t, e)
	lock, e := maintenance.Acquire(data)
	require.NoError(t, e)
	defer lock.Close()
	m, e := s.inspect(context.Background(), "releases/"+opt.ArchiveSHA256, opt.ArchiveSHA256)
	require.NoError(t, e)
	id, e := stageID()
	require.NoError(t, e)
	require.NoError(t, s.root.MkdirAll("backups", 0700))
	j := upgradeJournal{Schema: 1, RootID: s.owner.ID, ID: id, Phase: phase, Before: before, Guard: maintenance.UpgradeGuard{Schema: 1, RootID: s.owner.ID, ID: id, BinarySHA256: m.Files[nativeExecutable(m)].SHA256, Phase: "pending"}, Result: InstallResult{ID: id, RequestID: opt.RequestID, ExpectedRevision: 0, DataDir: data, Current: before.Current, Target: Selection{opt.ArchiveSHA256, m.Version, m.Commit}, BackupFile: filepath.Join(s.path, "backups", id+".jmsbackup")}}
	require.NoError(t, maintenance.SetUpgradeGuard(lock, j.Guard))
	if phase != "preparing" {
		j.Result.Backup, e = maintenance.CreateLocked(context.Background(), maintenance.Options{DataDir: data, File: j.Result.BackupFile, Version: opt.SourceVersion, Passphrase: opt.Passphrase}, lock)
		require.NoError(t, e)
		require.NoError(t, os.WriteFile(filepath.Join(data, "sentinel"), []byte("interrupted target"), 0600))
	}
	if phase == "committing" {
		j.Result.Status = "selected"
		j.Result.Current = j.Result.Target
		j.Result.Revision = 1
		j.After = receiptState(before, j.Result)
		j.After.Current = j.Result.Target
		j.After.Revision = 1
	}
	require.NoError(t, s.saveUpgrade(j))
	return j
}
func TestNativeInstallRecoveryRollsBackBeforeCommitAndFinalizesDurableSelection(t *testing.T) {
	for _, phase := range []string{"preparing", "checking", "rolling_back", "committing", "committed", "rollback-recorded"} {
		t.Run(phase, func(t *testing.T) {
			opt := installFixture(t)
			actual := phase
			if phase == "committed" {
				actual = "committing"
			}
			if phase == "rollback-recorded" {
				actual = "checking"
			}
			j := pendingInstall(t, opt, actual)
			if phase == "committed" {
				s := installRoot(t, opt.Root)
				require.NoError(t, s.saveInstallation(j.After))
				s.close()
				require.NoError(t, os.WriteFile(filepath.Join(opt.DataDir, "post-commit"), []byte("preserve production writes"), 0600))
			}
			if phase == "rollback-recorded" {
				s := installRoot(t, opt.Root)
				r := j.Result
				r.Status = "rolled_back"
				require.NoError(t, s.saveInstallation(receiptState(j.Before, r)))
				s.close()
			}
			r, e := RecoverInstallation(context.Background(), opt.Root, opt.Passphrase)
			if phase == "committed" {
				require.NoError(t, e)
				assert.Equal(t, "selected", r.Status)
				assert.FileExists(t, filepath.Join(opt.DataDir, "post-commit"))
				g, e := maintenance.ReadUpgradeGuard(opt.DataDir)
				require.NoError(t, e)
				assert.Equal(t, "active", g.Phase)
			} else {
				require.NoError(t, e)
				if phase == "preparing" {
					assert.Equal(t, "aborted", r.Status)
				} else {
					assert.Equal(t, "rolled_back", r.Status)
				}
				body, e := os.ReadFile(filepath.Join(opt.DataDir, "sentinel"))
				require.NoError(t, e)
				if phase != "rollback-recorded" {
					assert.Equal(t, "preserve-before-upgrade", string(body))
				}
			}
			again, e := RecoverInstallation(context.Background(), opt.Root, opt.Passphrase)
			require.NoError(t, e)
			assert.True(t, again.Unchanged)
			assert.Equal(t, "no_pending_upgrade", again.Status)
		})
	}
}
func TestNativeInstallRecoveryWrongKeyConflictAndCancellationPreservePendingData(t *testing.T) {
	opt := installFixture(t)
	j := pendingInstall(t, opt, "checking")
	_, e := RecoverInstallation(context.Background(), opt.Root, []byte("incorrect-checkpoint-passphrase"))
	require.ErrorIs(t, e, maintenance.ErrIntegrity)
	body, e := os.ReadFile(filepath.Join(opt.DataDir, "sentinel"))
	require.NoError(t, e)
	assert.Equal(t, "interrupted target", string(body))
	assert.ErrorIs(t, maintenance.CheckUpgradeGuard(opt.DataDir, "", ""), maintenance.ErrUpgradePending)
	_, e = install(context.Background(), opt, successfulChecker)
	assert.ErrorIs(t, e, ErrInstallPending)
	s := installRoot(t, opt.Root)
	altered := j.Before
	altered.Revision = 7
	altered.DataDir = j.Result.DataDir
	altered.Current = j.Result.Target
	require.NoError(t, s.saveInstallation(altered))
	s.close()
	_, e = RecoverInstallation(context.Background(), opt.Root, opt.Passphrase)
	assert.ErrorIs(t, e, ErrInstallConflict)
	s = installRoot(t, opt.Root)
	require.NoError(t, s.saveInstallation(j.Before))
	s.close()
	_, e = RecoverInstallation(context.Background(), opt.Root, opt.Passphrase)
	require.NoError(t, e)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	opt.RequestID = "cancel-install-001"
	_, e = install(ctx, opt, successfulChecker)
	assert.ErrorIs(t, e, context.Canceled)
	state, e := InstallationStatus(context.Background(), opt.Root)
	require.NoError(t, e)
	assert.True(t, reflect.DeepEqual(state.Current, Selection{}))
}
