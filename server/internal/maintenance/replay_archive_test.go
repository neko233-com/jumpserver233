package maintenance

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/connector/replaystore"
	"github.com/neko233-com/jumpserver233/server/internal/core/replayarchive"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStandaloneBackupReplayArchiveEncryptedHistoryAndCacheExclusion(t *testing.T) {
	opt := fixture(t)
	key, e := os.ReadFile(filepath.Join(opt.DataDir, "vault.key"))
	require.NoError(t, e)
	source, e := replayarchive.NewRecordings(opt.DataDir, key)
	require.NoError(t, e)
	factory := func(context.Context, replayarchive.Config) (replaystore.Objects, error) {
		t.Error("backup must not connect to replay storage")
		return nil, replayarchive.ErrUnavailable
	}
	store, e := replayarchive.Open(filepath.Join(opt.DataDir, "replay-archive.json"), key, nil, source, factory)
	require.NoError(t, e)
	in := replayarchive.Input{Config: replayarchive.Config{Provider: "s3", Enabled: true, Cloud: &replaystore.CloudConfig{Provider: "s3", Endpoint: "https://backup-replay.example.com", Region: "us-east-1", Bucket: "replays", AccessKeyID: "synthetic-backup-key", SecretAccessKey: "synthetic-replay-backup-secret"}}, RequestID: "backup-replay-config-001"}
	config, e := store.Save("backup-operator", in)
	require.NoError(t, e)
	store.Close()
	original, e := os.ReadFile(filepath.Join(opt.DataDir, "replay-archive.json"))
	require.NoError(t, e)
	for _, name := range []string{"replay-cache", "organizations/org-test/replay-cache"} {
		dir := filepath.Join(opt.DataDir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(dir, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, ".replay-cipher-1234"), []byte("disposable-ciphertext-cache"), 0600))
	}
	_, e = Create(context.Background(), opt)
	require.NoError(t, e)
	manifest, _, e := readArchive(context.Background(), opt, nil)
	require.NoError(t, e)
	found := false
	for _, entry := range manifest.Entries {
		assert.False(t, replayCacheDirectory(entry.Name), entry.Name)
		if entry.Name == "replay-archive.json" {
			found = true
		}
	}
	assert.True(t, found)
	opt.DataDir = filepath.Join(filepath.Dir(opt.DataDir), "restored-replay")
	_, e = Restore(context.Background(), opt)
	require.NoError(t, e)
	restored, e := os.ReadFile(filepath.Join(opt.DataDir, "replay-archive.json"))
	require.NoError(t, e)
	assert.Equal(t, original, restored)
	assert.NoDirExists(t, filepath.Join(opt.DataDir, "replay-cache"))
	assert.NoDirExists(t, filepath.Join(opt.DataDir, "organizations", "org-test", "replay-cache"))
	source, e = replayarchive.NewRecordings(opt.DataDir, key)
	require.NoError(t, e)
	reopened, e := replayarchive.Open(filepath.Join(opt.DataDir, "replay-archive.json"), key, nil, source, factory)
	require.NoError(t, e)
	defer reopened.Close()
	same, e := reopened.Save("backup-operator", in)
	require.NoError(t, e)
	assert.Equal(t, config, same)
	_, e = Restore(context.Background(), opt)
	require.NoError(t, e)
	for _, name := range []string{"replay-cache", "organizations/org-test/replay-cache"} {
		assert.True(t, replayCacheDirectory(name))
	}
	assert.False(t, replayCacheDirectory("organizations/org-test/recordings/replay-cache"))
}
