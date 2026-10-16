package hostagent

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStateSnapshotsRemainConsistentAcrossAtomicDaemonReplacement(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "state.json")
	require.NoError(t, os.WriteFile(file, []byte(`{"bans":{}}`), 0600))
	stop := make(chan struct{})
	errors := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			next := filepath.Join(dir, "next")
			if e := os.WriteFile(next, []byte(`{"bans":{},"offsets":{}}`), 0600); e != nil {
				errors <- e
				return
			}
			if e := os.Rename(next, file); e != nil {
				errors <- e
				return
			}
		}
	}()
	defer func() {
		close(stop)
		wg.Wait()
		select {
		case e := <-errors:
			require.NoError(t, e)
		default:
		}
	}()
	for i := 0; i < 1000; i++ {
		data, e := regularRead(file, 1024)
		require.NoError(t, e)
		require.NoError(t, validateJSON(data))
	}
}

func TestStateSnapshotRejectsLinksWritableFilesAndOversizedContent(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "state.json")
	require.NoError(t, os.WriteFile(file, []byte(`{}`), 0600))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(file, link))
	_, e := regularRead(link, 1024)
	require.Error(t, e)
	_, e = regularRead(file, 1)
	require.ErrorIs(t, e, ErrState)
	require.NoError(t, os.Chmod(file, 0666))
	_, e = regularRead(file, 1024)
	require.ErrorIs(t, e, ErrState)
}
