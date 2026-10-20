package replayarchive

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReplayArchiveCacheBoundsLeasesAndIdempotentOwnedCleanup(t *testing.T) {
	root := t.TempDir()
	foreign := filepath.Join(root, "unrelated.txt")
	require.NoError(t, os.WriteFile(foreign, []byte("preserved"), 0600))
	cache := newCipherCache(root)
	defer cache.close()
	load := func(ctx context.Context, w io.Writer) error { _, e := w.Write([]byte("cipher")); return e }
	readers := []SeekCloser{}
	for _, key := range []string{"one", "two", "three", "four"} {
		r, e := cache.open(context.Background(), key, 6, load)
		require.NoError(t, e)
		readers = append(readers, r)
	}
	_, e := cache.open(context.Background(), "five", 6, load)
	assert.ErrorIs(t, e, ErrCapacity)
	require.NoError(t, readers[0].Close())
	fifth, e := cache.open(context.Background(), "five", 6, load)
	require.NoError(t, e)
	cache.close()
	cache.close()
	_, readError := readers[1].Read(make([]byte, 1))
	assert.Error(t, readError)
	assert.FileExists(t, foreign)
	for _, r := range readers[1:] {
		require.NoError(t, r.Close())
		require.NoError(t, r.Close())
	}
	require.NoError(t, fifth.Close())
	entries, e := os.ReadDir(root)
	require.NoError(t, e)
	require.Len(t, entries, 1)
	assert.Equal(t, "unrelated.txt", entries[0].Name())
}
func TestReplayArchiveFailedDownloadAndCanceledWaitCleanOnlyTheirTemporaryFile(t *testing.T) {
	cache := newCipherCache(t.TempDir())
	defer cache.close()
	sentinel := errors.New("readback integrity failure")
	_, e := cache.open(context.Background(), "bad", 6, func(ctx context.Context, w io.Writer) error { _, _ = w.Write([]byte("partial")); return sentinel })
	assert.ErrorIs(t, e, sentinel)
	entries, e := os.ReadDir(cache.root)
	require.NoError(t, e)
	assert.Empty(t, entries)
	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		r, e := cache.open(context.Background(), "waiting", 6, func(ctx context.Context, w io.Writer) error {
			close(started)
			<-release
			_, e := w.Write([]byte("cipher"))
			return e
		})
		if r != nil {
			_ = r.Close()
		}
		done <- e
	}()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = cache.open(ctx, "waiting", 6, nil)
	assert.ErrorIs(t, e, context.Canceled)
	close(release)
	require.NoError(t, <-done)
}

func TestReplayArchiveOfflineOpenPreservesCacheAndStartCleansOnlyKnownFiles(t *testing.T) {
	s, _ := archiveStore(t)
	root := s.cache.root
	require.NoError(t, os.MkdirAll(root, 0700))
	for _, name := range []string{".replay-cipher-1234", ".replay-pack-5678", "unrelated.txt", ".replay-cipher-custom"} {
		require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte("preserved-until-owned-cleanup"), 0600))
	}
	reopened, e := Open(s.path, s.hashKey, nil, s.source, s.factory)
	require.NoError(t, e)
	defer reopened.Close()
	assert.FileExists(t, filepath.Join(root, ".replay-cipher-1234"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, reopened.Start(ctx))
	require.NoError(t, reopened.Start(ctx))
	assert.NoFileExists(t, filepath.Join(root, ".replay-cipher-1234"))
	assert.NoFileExists(t, filepath.Join(root, ".replay-pack-5678"))
	assert.FileExists(t, filepath.Join(root, "unrelated.txt"))
	assert.FileExists(t, filepath.Join(root, ".replay-cipher-custom"))
}
