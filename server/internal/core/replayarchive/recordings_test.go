package replayarchive

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/replaystore"
	"github.com/neko233-com/jumpserver233/server/internal/recorder"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReplayArchiveTerminalAuthenticatesFinalizedRecordingAndKeepsAsciinema(t *testing.T) {
	root := t.TempDir()
	key := bytes.Repeat([]byte{27}, 32)
	id := terminalRef.SessionID
	path := filepath.Join(root, "sessions", id+".json.gz.enc")
	r, e := recorder.NewAsciinema(path, id, "asset-test", 80, 24, time.Now(), key)
	require.NoError(t, e)
	require.NoError(t, r.Record('o', []byte("synthetic terminal output")))
	require.NoError(t, r.Close())
	source, e := NewRecordings(root, key)
	require.NoError(t, e)
	started := []byte(fmt.Sprintf("{\"session_id\":%q,\"event\":\"started\"}\n", id))
	ended := []byte(fmt.Sprintf("{\"session_id\":%q,\"event\":\"ended\"}\n", id))
	index := filepath.Join(root, "sessions", "index.jsonl")
	require.NoError(t, os.WriteFile(index, started, 0600))
	_, e = source.Prepare(context.Background(), terminalRef)
	require.Error(t, e)
	require.NoError(t, os.WriteFile(index, append(started, ended...), 0600))
	objects := &memoryObjects{data: map[string][]byte{}}
	s, e := Open(filepath.Join(root, "replay-archive.json"), key, nil, source, func(context.Context, Config) (replaystore.Objects, error) { return objects, nil })
	require.NoError(t, e)
	defer s.Close()
	archiveConfig(t, s)
	require.NoError(t, s.Enqueue(terminalRef))
	_, e = s.ProcessNext(context.Background())
	require.NoError(t, e)
	for _, data := range objects.data {
		assert.True(t, bytes.HasPrefix(data, []byte("JMSREC1\n")))
		assert.NotContains(t, string(data), "synthetic terminal output")
	}
	local, e := os.ReadFile(path)
	require.NoError(t, e)
	evicted, e := s.Evict(context.Background(), terminalRef, "operator", "evict-terminal-001")
	require.NoError(t, e)
	assert.False(t, evicted.LocalEvictedAt.IsZero())
	assert.NoFileExists(t, path)
	assert.FileExists(t, index)
	again, e := s.Evict(context.Background(), terminalRef, "operator", "evict-terminal-001")
	require.NoError(t, e)
	assert.Equal(t, evicted, again)
	reader, e := s.OpenReplay(context.Background(), id, key)
	require.NoError(t, e)
	plain, e := io.ReadAll(reader)
	require.NoError(t, e)
	require.NoError(t, reader.Close())
	assert.Contains(t, string(plain), "synthetic terminal output")
	assert.Contains(t, string(plain), `"version":2`)
	// Broken ciphertext is refused before upload, with the original kept intact.
	local[len(local)-1] ^= 1
	require.NoError(t, os.WriteFile(path, local, 0600))
	_, e = source.Prepare(context.Background(), terminalRef)
	assert.ErrorIs(t, e, ErrIntegrity)
}
func TestReplayArchiveDesktopBundlesCiphertextDeterministicallyAndAuthenticatesFrame(t *testing.T) {
	root := t.TempDir()
	id := "desktop-session-0001"
	key := bytes.Repeat([]byte{28}, 32)
	dir := filepath.Join(root, "desktop-sessions", id)
	desktop, e := recorder.NewDesktop(dir, id, key)
	require.NoError(t, e)
	frame := recorder.DesktopFrame{Index: 0, AtMS: 1, Sequence: 1, Width: 8, Height: 8}
	png := []byte{137, 80, 78, 71, 13, 10, 26, 10}
	require.NoError(t, desktop.Record(frame, png))
	second := frame
	second.Index = 1
	second.Sequence = 2
	second.AtMS = 2
	require.NoError(t, desktop.Record(second, png))
	index := struct {
		ID     string                  `json:"session_id"`
		Status string                  `json:"status"`
		Frames []recorder.DesktopFrame `json:"frames"`
	}{id, "ended", []recorder.DesktopFrame{frame, second}}
	raw, e := json.Marshal(index)
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.json"), raw, 0600))
	source, e := NewRecordings(root, key)
	require.NoError(t, e)
	ref := Ref{Kind: "desktop", SessionID: id}
	var first []byte
	for range 2 {
		f, e := source.Prepare(context.Background(), ref)
		require.NoError(t, e)
		data, e := io.ReadAll(f)
		require.NoError(t, e)
		require.NoError(t, f.Close())
		if first == nil {
			first = data
		} else {
			assert.Equal(t, first, data)
		}
	}
	assert.NotContains(t, string(first), string(png))
	assert.NotContains(t, string(first), "index.json")
	o := &memoryObjects{data: map[string][]byte{}}
	s, e := Open(filepath.Join(root, "replay-archive.json"), key, nil, source, func(context.Context, Config) (replaystore.Objects, error) { return o, nil })
	require.NoError(t, e)
	defer s.Close()
	archiveConfig(t, s)
	require.NoError(t, s.Enqueue(ref))
	_, e = s.ProcessNext(context.Background())
	require.NoError(t, e)
	require.NoError(t, os.Remove(filepath.Join(dir, "000000.png.enc")))
	for range 2 {
		data, e := s.DesktopFrame(context.Background(), id, frame, key)
		require.NoError(t, e)
		assert.Equal(t, png, data)
	}
	assert.Equal(t, 2, o.gets)
	// Resume an interrupted cleanup with one local frame already missing.
	evicted, e := s.Evict(context.Background(), ref, "operator", "evict-desktop-001")
	require.NoError(t, e)
	assert.False(t, evicted.LocalEvictedAt.IsZero())
	assert.NoFileExists(t, filepath.Join(dir, "000001.png.enc"))
	assert.Equal(t, 3, o.gets)
	again, e := s.Evict(context.Background(), ref, "operator", "evict-desktop-001")
	require.NoError(t, e)
	assert.Equal(t, evicted, again)
	assert.Equal(t, 3, o.gets)
	assert.FileExists(t, filepath.Join(dir, "index.json"))
	frame.Width++
	_, e = s.DesktopFrame(context.Background(), id, frame, key)
	require.Error(t, e)
	entries, e := os.ReadDir(filepath.Join(root, "replay-cache"))
	require.NoError(t, e)
	for _, entry := range entries {
		assert.NotContains(t, entry.Name(), "replay-pack")
	}
}
func TestReplayArchivePostgresScopedMetadataTakeoverAndLocatorIsolation(t *testing.T) {
	database := os.Getenv("JMS_TEST_DATABASE_URL")
	if database == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for replay archive metadata takeover")
	}
	ctx := context.Background()
	namespace := fmt.Sprintf("replay-archive-%d", time.Now().UnixNano())
	docs, e := storage.OpenPostgres(ctx, database, namespace)
	require.NoError(t, e)
	defer docs.Close()
	a, e := docs.Scoped("tenant-a")
	require.NoError(t, e)
	b, e := docs.Scoped("tenant-b")
	require.NoError(t, e)
	source := memorySource{[]byte("opaque tenant ciphertext")}
	factory := func(context.Context, Config) (replaystore.Objects, error) { return replaystore.NewDatabase(a) }
	path := filepath.Join(t.TempDir(), "replay-archive.json")
	s, e := Open(path, make([]byte, 32), a, source, factory)
	require.NoError(t, e)
	archiveConfig(t, s)
	require.NoError(t, s.Enqueue(terminalRef))
	_, e = s.ProcessNext(ctx)
	require.NoError(t, e)
	key := s.data.Records[refKey(terminalRef)].Key
	defer a.DeleteReplayBlob(ctx, key)
	s.Close()
	reopened, e := Open(path, make([]byte, 32), a, source, factory)
	require.NoError(t, e)
	defer reopened.Close()
	assert.True(t, reopened.Available(terminalRef))
	reader, e := reopened.OpenCiphertext(ctx, terminalRef)
	require.NoError(t, e)
	data, e := io.ReadAll(reader)
	require.NoError(t, e)
	require.NoError(t, reader.Close())
	assert.Equal(t, source.data, data)
	other, e := Open(filepath.Join(t.TempDir(), "replay-archive.json"), make([]byte, 32), b, source, factory)
	require.NoError(t, e)
	defer other.Close()
	assert.False(t, other.Available(terminalRef))
	_, e = b.OpenReplayBlob(ctx, key)
	assert.ErrorIs(t, e, storage.ErrReplayBlobNotFound)
}
