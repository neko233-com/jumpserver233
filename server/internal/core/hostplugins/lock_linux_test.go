package hostplugins

import (
	"context"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func lockCommand(t *testing.T, location string, attempts int) *exec.Cmd {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return exec.CommandContext(ctx, "/bin/sh", "-c", "set -eu; "+directoryLock("qa_lock", location, attempts)+"trap 'rmdir \"$qa_lock\"' EXIT; printf admitted")
}
func TestDirectoryLockWaitsForExistingSupervisorAndReleasesOnlyItsOwnLock(t *testing.T) {
	location := filepath.Join(t.TempDir(), "operation.lock")
	require.NoError(t, os.Mkdir(location, 0700))
	timer := time.AfterFunc(120*time.Millisecond, func() { _ = os.Remove(location) })
	defer timer.Stop()
	out, e := lockCommand(t, location, 15).CombinedOutput()
	require.NoError(t, e, string(out))
	assert.Equal(t, "admitted", string(out))
	_, e = os.Lstat(location)
	assert.ErrorIs(t, e, os.ErrNotExist)
}
func TestDirectoryLockTimeoutPreservesTheExistingHolder(t *testing.T) {
	location := filepath.Join(t.TempDir(), "cron.lock")
	require.NoError(t, os.Mkdir(location, 0700))
	_, e := lockCommand(t, location, 2).CombinedOutput()
	var exit *exec.ExitError
	require.ErrorAs(t, e, &exit)
	assert.Equal(t, 44, exit.ExitCode())
	info, e := os.Stat(location)
	require.NoError(t, e)
	assert.True(t, info.IsDir())
}
func TestDirectoryLockRejectsLinksAndRegularFilesWithoutDeletingThem(t *testing.T) {
	for _, link := range []bool{false, true} {
		t.Run(fmt.Sprint(link), func(t *testing.T) {
			location := filepath.Join(t.TempDir(), "operation.lock")
			if link {
				require.NoError(t, os.Symlink(t.TempDir(), location))
			} else {
				require.NoError(t, os.WriteFile(location, []byte("preserve"), 0600))
			}
			_, e := lockCommand(t, location, 2).CombinedOutput()
			var exit *exec.ExitError
			require.ErrorAs(t, e, &exit)
			assert.Equal(t, 44, exit.ExitCode())
			_, e = os.Lstat(location)
			require.NoError(t, e)
		})
	}
}
