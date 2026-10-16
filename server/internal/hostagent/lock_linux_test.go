package hostagent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStateLockMatchesDaemonFlockAndRejectsSymlinks(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state.json.lock")
	unlock, e := stateLock(file)
	require.NoError(t, e)
	_, e = stateLock(file)
	require.ErrorIs(t, e, ErrBusy)
	unlock()
	unlock, e = stateLock(file)
	require.NoError(t, e)
	unlock()
	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(file, link))
	_, e = stateLock(link)
	require.ErrorIs(t, e, ErrBusy)
}
