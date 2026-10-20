package replayarchive

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/replaystore"
	"github.com/neko233-com/jumpserver233/server/internal/recorder"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReplayArchiveEvictionRefusesChangedLocalOrCorruptRemoteCopies(t *testing.T) {
	root := t.TempDir()
	key := make([]byte, 32)
	path := filepath.Join(root, "sessions", terminalRef.SessionID+".json.gz.enc")
	recording, e := recorder.NewAsciinema(path, terminalRef.SessionID, "asset", 80, 24, time.Now(), key)
	require.NoError(t, e)
	require.NoError(t, recording.Close())
	audit := fmt.Sprintf("{\"session_id\":%q,\"event\":\"started\"}\n{\"session_id\":%q,\"event\":\"ended\"}\n", terminalRef.SessionID, terminalRef.SessionID)
	require.NoError(t, os.WriteFile(filepath.Join(root, "sessions", "index.jsonl"), []byte(audit), 0600))
	source, e := NewRecordings(root, key)
	require.NoError(t, e)
	objects := &memoryObjects{data: map[string][]byte{}}
	s, e := Open(filepath.Join(root, "replay-archive.json"), key, nil, source, func(context.Context, Config) (replaystore.Objects, error) { return objects, nil })
	require.NoError(t, e)
	defer s.Close()
	archiveConfig(t, s)
	require.NoError(t, s.Enqueue(terminalRef))
	_, e = s.ProcessNext(context.Background())
	require.NoError(t, e)
	original, e := os.ReadFile(path)
	require.NoError(t, e)
	modified := bytes.Clone(original)
	modified[len(modified)-1] ^= 1
	require.NoError(t, os.WriteFile(path, modified, 0600))
	_, e = s.Evict(context.Background(), terminalRef, "operator", "evict-changed-local-001")
	assert.ErrorIs(t, e, ErrIntegrity)
	current, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.Equal(t, modified, current)
	require.NoError(t, os.WriteFile(path, original, 0600))
	objects.corrupt = true
	_, e = s.Evict(context.Background(), terminalRef, "operator", "evict-corrupt-remote-001")
	assert.ErrorIs(t, e, ErrIntegrity)
	assert.FileExists(t, path)
	objects.corrupt = false
	out, e := s.Evict(context.Background(), terminalRef, "operator", "evict-recovered-001")
	require.NoError(t, e)
	assert.False(t, out.LocalEvictedAt.IsZero())
	assert.NoFileExists(t, path)
	gets := objects.gets
	again, e := s.Evict(context.Background(), terminalRef, "operator", "evict-recovered-001")
	require.NoError(t, e)
	assert.Equal(t, out, again)
	assert.Equal(t, gets, objects.gets)
}
