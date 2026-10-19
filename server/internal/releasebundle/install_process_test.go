package releasebundle

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/maintenance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNativeInstallCrashRetainsGuardAndRestoresCheckpointAfterProcessExit(t *testing.T) {
	if os.Getenv("JMS_INSTALL_CRASH_TEST") == "1" {
		opt := InstallOptions{Root: os.Getenv("JMS_INSTALL_CRASH_ROOT"), DataDir: os.Getenv("JMS_INSTALL_CRASH_DATA"), ArchiveSHA256: os.Getenv("JMS_INSTALL_CRASH_SHA"), RequestID: "crash-install-001", SourceVersion: "v1.2.2", Passphrase: []byte("synthetic-install-checkpoint-password")}
		_, _ = install(context.Background(), opt, func(context.Context, string, string, string, string) error {
			require.NoError(t, os.WriteFile(filepath.Join(opt.DataDir, "sentinel"), []byte("interrupted migration"), 0600))
			require.NoError(t, os.WriteFile(os.Getenv("JMS_INSTALL_CRASH_READY"), []byte("ready"), 0600))
			time.Sleep(time.Hour)
			return nil
		})
		return
	}
	opt := installFixture(t)
	ready := filepath.Join(t.TempDir(), "ready")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeInstallCrashRetainsGuardAndRestoresCheckpointAfterProcessExit$")
	child.Env = append(os.Environ(), "JMS_INSTALL_CRASH_TEST=1", "JMS_INSTALL_CRASH_ROOT="+opt.Root, "JMS_INSTALL_CRASH_DATA="+opt.DataDir, "JMS_INSTALL_CRASH_SHA="+opt.ArchiveSHA256, "JMS_INSTALL_CRASH_READY="+ready)
	require.NoError(t, child.Start())
	waited := false
	defer func() {
		if !waited {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	require.Eventually(t, func() bool { _, e := os.Stat(ready); return e == nil }, 10*time.Second, 20*time.Millisecond)
	assert.ErrorIs(t, maintenance.CheckUpgradeGuard(opt.DataDir, "", ""), maintenance.ErrUpgradePending)
	_, e := InstallationStatus(context.Background(), opt.Root)
	assert.ErrorIs(t, e, maintenance.ErrBusy)
	require.NoError(t, child.Process.Kill())
	require.Error(t, child.Wait())
	waited = true
	lock, e := maintenance.Acquire(opt.DataDir)
	require.NoError(t, e)
	_, e = RecoverInstallation(context.Background(), opt.Root, opt.Passphrase)
	assert.ErrorIs(t, e, maintenance.ErrBusy)
	require.NoError(t, lock.Close())
	r, e := RecoverInstallation(context.Background(), opt.Root, opt.Passphrase)
	require.NoError(t, e)
	assert.Equal(t, "rolled_back", r.Status)
	body, e := os.ReadFile(filepath.Join(opt.DataDir, "sentinel"))
	require.NoError(t, e)
	assert.Equal(t, "preserve-before-upgrade", string(body))
	_, e = RecoverInstallation(context.Background(), opt.Root, opt.Passphrase)
	require.NoError(t, e)
}
