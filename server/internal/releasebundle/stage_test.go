package releasebundle

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/maintenance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func stagedFixture(t *testing.T) (Staged, string, string, string) {
	t.Helper()
	archive, sha := fixture(t, "")
	root := filepath.Join(t.TempDir(), "versions")
	result, e := Stage(context.Background(), archive, sha, "linux", "amd64", root)
	require.NoError(t, e)
	return result, root, archive, sha
}
func TestNativeStageIdempotentAndInspectsEveryByte(t *testing.T) {
	result, root, archive, sha := stagedFixture(t)
	assert.False(t, result.Unchanged)
	assert.Equal(t, sha, result.ArchiveSHA256)
	canonical, e := filepath.EvalSymlinks(root)
	require.NoError(t, e)
	assert.Equal(t, filepath.Join(canonical, "releases", sha), result.Directory)
	_, e = os.Stat(filepath.Join(result.Directory, "web", "index.html"))
	require.NoError(t, e)
	again, e := Stage(context.Background(), archive, sha, "linux", "amd64", root)
	require.NoError(t, e)
	assert.True(t, again.Unchanged)
	assert.Equal(t, result.Manifest, again.Manifest)
	checked, e := InspectStage(context.Background(), root, sha, "linux", "amd64")
	require.NoError(t, e)
	assert.Equal(t, result.Manifest, checked.Manifest)
	rows, e := os.ReadDir(root)
	require.NoError(t, e)
	for _, row := range rows {
		assert.False(t, stageName.MatchString(row.Name()), row.Name())
	}
	count, e := CleanStages(context.Background(), root, "linux", "amd64")
	require.NoError(t, e)
	assert.Zero(t, count)
}
func TestNativeStageRejectsChangedOrExtraPublishedFiles(t *testing.T) {
	for _, kind := range []string{"changed", "missing", "extra-file", "extra-dir", "manifest", "receipt", "permission"} {
		t.Run(kind, func(t *testing.T) {
			result, root, archive, sha := stagedFixture(t)
			name := filepath.Join(result.Directory, "web", "index.html")
			switch kind {
			case "changed":
				require.NoError(t, os.WriteFile(name, []byte("different"), 0600))
			case "missing":
				require.NoError(t, os.Remove(name))
			case "extra-file":
				require.NoError(t, os.WriteFile(filepath.Join(result.Directory, "unknown"), []byte("unexpected"), 0600))
			case "extra-dir":
				require.NoError(t, os.Mkdir(filepath.Join(result.Directory, "unknown"), 0700))
			case "manifest":
				body, e := os.ReadFile(filepath.Join(result.Directory, "manifest.json"))
				require.NoError(t, e)
				require.NoError(t, os.WriteFile(filepath.Join(result.Directory, "manifest.json"), []byte(strings.Replace(string(body), "v1.2.3", "v9.9.9", 1)), 0600))
			case "receipt":
				require.NoError(t, os.WriteFile(filepath.Join(result.Directory, stageReceiptFile), []byte(`{"schema":2}`), 0600))
			case "permission":
				if runtime.GOOS == "windows" {
					t.Skip("Unix permission bits are not a Windows ACL")
				}
				require.NoError(t, os.Chmod(name, 0644))
			}
			_, e := InspectStage(context.Background(), root, sha, "linux", "amd64")
			assert.ErrorIs(t, e, ErrStageConflict)
			_, e = Stage(context.Background(), archive, sha, "linux", "amd64", root)
			assert.ErrorIs(t, e, ErrStageConflict)
			assert.DirExists(t, result.Directory)
		})
	}
}
func TestNativeStageRefusesUnmanagedDataAndSourceRoots(t *testing.T) {
	archive, sha := fixture(t, "")
	for _, name := range []string{"assets.json", ".git", ".jms233-storage.json", "web"} {
		root := t.TempDir()
		sentinel := filepath.Join(root, name)
		require.NoError(t, os.WriteFile(sentinel, []byte("retain"), 0600))
		_, e := Stage(context.Background(), archive, sha, "linux", "amd64", root)
		assert.ErrorIs(t, e, ErrStageConflict)
		body, e := os.ReadFile(sentinel)
		require.NoError(t, e)
		assert.Equal(t, "retain", string(body))
		assert.NoDirExists(t, filepath.Join(root, ".jms233-maintenance"))
	}
}
func TestNativeStageRefusesInvalidArchiveAndDifferentTarget(t *testing.T) {
	for _, kind := range []string{"traversal", "symlink", "case-collision", "wrong-binary", "hash", "missing-file", "trailing", "future"} {
		t.Run(kind, func(t *testing.T) {
			archive, sha := fixture(t, kind)
			root := filepath.Join(t.TempDir(), "versions")
			_, e := Stage(context.Background(), archive, sha, "linux", "amd64", root)
			require.Error(t, e)
			rows, e := os.ReadDir(root)
			require.NoError(t, e)
			for _, row := range rows {
				assert.False(t, stageName.MatchString(row.Name()))
			}
			entries, e := os.ReadDir(filepath.Join(root, "releases"))
			require.NoError(t, e)
			assert.Empty(t, entries)
		})
	}
	_, root, archive, sha := stagedFixture(t)
	_, e := Stage(context.Background(), archive, sha, "linux", "arm64", root)
	assert.ErrorIs(t, e, ErrStageConflict)
	_, e = Stage(context.Background(), archive, strings.Repeat("0", 64), "linux", "amd64", root)
	assert.ErrorIs(t, e, ErrInvalid)
	_, e = InspectStage(context.Background(), root, strings.Repeat("0", 64), "linux", "amd64")
	assert.ErrorIs(t, e, os.ErrNotExist)
}
func TestNativeStageCancellationAndSharedProcessLock(t *testing.T) {
	archive, sha := fixture(t, "")
	root := filepath.Join(t.TempDir(), "versions")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e := Stage(ctx, archive, sha, "linux", "amd64", root)
	assert.ErrorIs(t, e, context.Canceled)
	assert.NoDirExists(t, root)
	_, e = Stage(context.Background(), archive, sha, "linux", "amd64", root)
	require.NoError(t, e)
	lock, e := maintenance.Acquire(root)
	require.NoError(t, e)
	_, e = Stage(context.Background(), archive, sha, "linux", "amd64", root)
	assert.ErrorIs(t, e, maintenance.ErrBusy)
	_, e = InspectStage(context.Background(), root, sha, "linux", "amd64")
	assert.ErrorIs(t, e, maintenance.ErrBusy)
	_, e = CleanStages(context.Background(), root, "linux", "amd64")
	assert.ErrorIs(t, e, maintenance.ErrBusy)
	require.NoError(t, lock.Close())
	_, e = Stage(context.Background(), archive, sha, "linux", "amd64", root)
	require.NoError(t, e)
}
func TestNativeStageCleansOnlyOwnedInterruptedDirectories(t *testing.T) {
	_, root, archive, sha := stagedFixture(t)
	s, e := openStagingRoot(root, "linux", "amd64", false)
	require.NoError(t, e)
	id, e := stageID()
	require.NoError(t, e)
	name := ".jms233-stage-" + id
	require.NoError(t, s.root.Mkdir(name, 0700))
	require.NoError(t, writeStageJSON(s.root, name+"/"+stageReceiptFile, stageReceipt{Schema: 1, Owner: s.owner.ID, Token: id, ArchiveSHA256: sha}, true))
	require.NoError(t, s.root.WriteFile(name+"/partial", []byte("partial archive"), 0600))
	s.close()
	result, e := Stage(context.Background(), archive, sha, "linux", "amd64", root)
	require.NoError(t, e)
	assert.Equal(t, 1, result.CleanedStages)
	assert.True(t, result.Unchanged)
	assert.NoDirExists(t, filepath.Join(root, name))
	assert.DirExists(t, result.Directory)
	n, e := CleanStages(context.Background(), root, "linux", "amd64")
	require.NoError(t, e)
	assert.Zero(t, n)
	// A known-shaped name alone never proves this process owns a directory.
	unknown := filepath.Join(root, ".jms233-stage-"+strings.Repeat("a", 32))
	require.NoError(t, os.Mkdir(unknown, 0700))
	sentinel := filepath.Join(unknown, "retain")
	require.NoError(t, os.WriteFile(sentinel, []byte("foreign"), 0600))
	_, e = CleanStages(context.Background(), root, "linux", "amd64")
	assert.ErrorIs(t, e, ErrStageConflict)
	assert.FileExists(t, sentinel)
}
func TestNativeStageRefusesForeignOwnershipAndDirectoryLinks(t *testing.T) {
	for _, kind := range []string{"foreign-owner", "bad-token", "link"} {
		t.Run(kind, func(t *testing.T) {
			_, root, _, sha := stagedFixture(t)
			s, e := openStagingRoot(root, "linux", "amd64", false)
			require.NoError(t, e)
			id, e := stageID()
			require.NoError(t, e)
			name := ".jms233-stage-" + id
			require.NoError(t, s.root.Mkdir(name, 0700))
			receipt := stageReceipt{Schema: 1, Owner: s.owner.ID, Token: id, ArchiveSHA256: sha}
			if kind == "foreign-owner" {
				receipt.Owner = strings.Repeat("0", 32)
			}
			if kind == "bad-token" {
				receipt.Token = strings.Repeat("0", 32)
			}
			require.NoError(t, writeStageJSON(s.root, name+"/"+stageReceiptFile, receipt, true))
			s.close()
			outside := t.TempDir()
			sentinel := filepath.Join(outside, "retain")
			require.NoError(t, os.WriteFile(sentinel, []byte("foreign"), 0600))
			if kind == "link" {
				if e = os.Symlink(outside, filepath.Join(root, name, "escape")); e != nil {
					t.Skip("link creation unavailable")
				}
			}
			_, e = CleanStages(context.Background(), root, "linux", "amd64")
			assert.ErrorIs(t, e, ErrStageConflict)
			assert.FileExists(t, sentinel)
			assert.DirExists(t, filepath.Join(root, name))
		})
	}
}
func TestNativeStageReceiptChangeCannotReplaceExistingPublishedBytes(t *testing.T) {
	result, root, archive, sha := stagedFixture(t)
	var m Manifest
	body, e := os.ReadFile(filepath.Join(result.Directory, "manifest.json"))
	require.NoError(t, e)
	require.NoError(t, json.Unmarshal(body, &m))
	m.Version = "v1.2.4"
	body, e = json.Marshal(m)
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(filepath.Join(result.Directory, "manifest.json"), body, 0600))
	_, e = Stage(context.Background(), archive, sha, "linux", "amd64", root)
	assert.True(t, errors.Is(e, ErrStageConflict))
}

func TestNativeStageConcurrentRetriesNeverPublishPartialTrees(t *testing.T) {
	archive, sha := fixture(t, "")
	root := filepath.Join(t.TempDir(), "versions")
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Go(func() { _, e := Stage(context.Background(), archive, sha, "linux", "amd64", root); results <- e })
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		} else {
			assert.ErrorIs(t, e, maintenance.ErrBusy)
		}
	}
	assert.Greater(t, success, 0)
	_, e := InspectStage(context.Background(), root, sha, "linux", "amd64")
	require.NoError(t, e)
	n, e := CleanStages(context.Background(), root, "linux", "amd64")
	require.NoError(t, e)
	assert.Zero(t, n)
}

func TestNativeStageDoesNotFollowReleaseDirectoryLinks(t *testing.T) {
	result, root, archive, sha := stagedFixture(t)
	saved := filepath.Join(t.TempDir(), "original")
	require.NoError(t, os.Rename(result.Directory, saved))
	if e := os.Symlink(saved, result.Directory); e != nil {
		t.Skip("link creation unavailable")
	}
	_, e := Stage(context.Background(), archive, sha, "linux", "amd64", root)
	assert.ErrorIs(t, e, ErrStageConflict)
	_, e = InspectStage(context.Background(), root, sha, "linux", "amd64")
	assert.ErrorIs(t, e, ErrStageConflict)
	assert.FileExists(t, filepath.Join(saved, "web", "index.html"))
}
