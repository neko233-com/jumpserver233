package runtimelog

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func openTest(t *testing.T, dir string) *Writer {
	t.Helper()
	w, err := Open(Options{Dir: dir, MaxBytes: 128, Backups: 3, Days: 2})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, w.Close()) })
	return w
}

func TestRuntimeLogsBoundedConcurrentWritesAndRestart(t *testing.T) {
	dir := t.TempDir()
	w := openTest(t, dir)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			for j := 0; j < 40; j++ {
				_, err := w.Write([]byte("record-1234567890\n"))
				require.NoError(t, err)
			}
		})
	}
	wg.Wait()
	s := w.Snapshot()
	require.LessOrEqual(t, s.TotalBytes, int64(128*4))
	require.LessOrEqual(t, s.Backups, 3)
	require.NoError(t, w.Close())
	require.NoError(t, w.Close())
	next := openTest(t, dir)
	require.NotEqual(t, s.Instance, next.Snapshot().Instance)
	require.LessOrEqual(t, next.Snapshot().TotalBytes, int64(128*4))
	_, err := next.Write([]byte("after restart\n"))
	require.NoError(t, err)
}

func TestRuntimeLogsManualRotateRetriesRevisionAndEmpty(t *testing.T) {
	w := openTest(t, t.TempDir())
	s := w.Snapshot()
	in := Input{s.Instance, s.Revision, "request-0001"}
	_, err := w.Rotate(in)
	require.NoError(t, err)
	require.Equal(t, 0, w.Snapshot().Backups)
	_, err = w.Write([]byte("first\n"))
	require.NoError(t, err)
	in.RequestID = "request-0002"
	out, err := w.Rotate(in)
	require.NoError(t, err)
	require.Equal(t, 1, out.Backups)
	_, err = w.Write([]byte("second\n"))
	require.NoError(t, err)
	_, err = w.Rotate(in)
	require.NoError(t, err)
	require.Equal(t, 1, w.Snapshot().Backups)
	in.RequestID = "request-0003"
	_, err = w.Rotate(in)
	require.ErrorIs(t, err, ErrConflict)
	in.Revision = out.Revision
	in.Instance = "stale"
	_, err = w.Rotate(in)
	require.ErrorIs(t, err, ErrConflict)
	in.Instance = out.Instance
	in.RequestID = "x"
	_, err = w.Rotate(in)
	require.ErrorIs(t, err, ErrInvalid)
}

func TestRuntimeLogsDailyRotationQuietExpiryAndUnrelatedFiles(t *testing.T) {
	dir := t.TempDir()
	w := openTest(t, dir)
	_, err := w.Write([]byte("yesterday\n"))
	require.NoError(t, err)
	future := time.Now().Add(25 * time.Hour)
	w.mu.Lock()
	w.now = func() time.Time { return future }
	w.mu.Unlock()
	_, err = w.Write([]byte("today\n"))
	require.NoError(t, err)
	require.Equal(t, 1, w.Snapshot().Backups)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "audit.json"), []byte("business audit"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "server-old.log"), []byte("unowned"), 0600))
	w.mu.Lock()
	w.now = func() time.Time { return future.Add(72 * time.Hour) }
	err = w.prune()
	w.mu.Unlock()
	require.NoError(t, err)
	require.Zero(t, w.Snapshot().Backups)
	for _, name := range []string{"audit.json", "server-old.log"} {
		_, err := os.Stat(filepath.Join(dir, name))
		require.NoError(t, err)
	}
}

func TestRuntimeLogsOversizedRecordIsBounded(t *testing.T) {
	w := openTest(t, t.TempDir())
	n, err := w.Write([]byte(strings.Repeat("x", 4096)))
	require.NoError(t, err)
	require.Equal(t, 4096, n)
	require.Equal(t, int64(128), w.Snapshot().CurrentBytes)
	require.EqualValues(t, 1, w.Snapshot().TruncatedRecords)
	b, err := os.ReadFile(filepath.Join(w.opts.Dir, "server.log"))
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(string(b), " [record truncated]\n"))
}

func TestRuntimeLogsStartupExpiresAndBoundsExistingArchives(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 7; i++ {
		name := fmt.Sprintf("server-20260101T00000%d.000000000Z-0123456789abcdef.log", i)
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte("old"), 0600))
		old := time.Now().Add(-72 * time.Hour)
		require.NoError(t, os.Chtimes(p, old, old))
	}
	w := openTest(t, dir)
	require.Zero(t, w.Snapshot().Backups)
}

func TestRuntimeLogsRejectsSymlinksAndKeepsArchiveTargets(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "kept")
	require.NoError(t, os.WriteFile(outside, []byte("preserve"), 0600))
	if err := os.Symlink(outside, filepath.Join(dir, "server.log")); err != nil {
		t.Skip("symlink privilege unavailable")
	}
	_, err := Open(Options{dir, 128, 3, 2})
	require.Error(t, err)
	require.NoError(t, os.Remove(filepath.Join(dir, "server.log")))
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, "server-20260101T000000.000000000Z-0123456789abcdef.log")))
	w := openTest(t, dir)
	require.Zero(t, w.Snapshot().Backups)
	b, err := os.ReadFile(outside)
	require.NoError(t, err)
	require.Equal(t, "preserve", string(b))
}

func TestRuntimeLogsInvalidOptionsAndClosedWriter(t *testing.T) {
	_, err := Open(Options{t.TempDir(), 127, 3, 2})
	require.ErrorIs(t, err, ErrInvalid)
	w := openTest(t, t.TempDir())
	require.NoError(t, w.Close())
	_, err = w.Write([]byte("closed"))
	require.ErrorIs(t, err, os.ErrClosed)
}

func TestRuntimeLogsCrashOutputRebindsAcrossRotation(t *testing.T) {
	w := openTest(t, t.TempDir())
	require.NoError(t, w.CaptureCrashes())
	for i := 0; i < 4; i++ {
		_, err := w.Write([]byte(strings.Repeat("a", 90)))
		require.NoError(t, err)
	}
	s := w.Snapshot()
	require.Equal(t, 3, s.Backups)
	_, err := w.Rotate(Input{s.Instance, s.Revision, "crash-rebind-request"})
	require.NoError(t, err)
	require.Empty(t, w.Snapshot().ErrorCode)
}
