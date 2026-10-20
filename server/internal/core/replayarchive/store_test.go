package replayarchive

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/replaystore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type memorySource struct{ data []byte }
type memorySeekCloser struct{ *bytes.Reader }

func (r memorySeekCloser) Close() error { return nil }
func (m memorySource) Prepare(context.Context, Ref) (SeekCloser, error) {
	return memorySeekCloser{bytes.NewReader(m.data)}, nil
}

type memoryObjects struct {
	mu           sync.Mutex
	data         map[string][]byte
	puts, gets   int
	lostResponse bool
	corrupt      bool
	block        chan struct{}
}

func (m *memoryObjects) Put(ctx context.Context, key string, r io.Reader, size int64, digest string) error {
	if m.block != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.block:
		}
	}
	data, e := io.ReadAll(r)
	if e != nil {
		return e
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.puts++
	if _, ok := m.data[key]; ok {
		return replaystore.ErrExists
	}
	if int64(len(data)) != size {
		return replaystore.ErrIntegrity
	}
	m.data[key] = bytes.Clone(data)
	if m.lostResponse {
		m.lostResponse = false
		return replaystore.ErrUnavailable
	}
	return nil
}
func (m *memoryObjects) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gets++
	data, ok := m.data[key]
	if !ok {
		return nil, replaystore.ErrNotFound
	}
	data = bytes.Clone(data)
	if m.corrupt {
		data = append(data, 1)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}
func (m *memoryObjects) Close() error { return nil }
func archiveStore(t *testing.T) (*Store, *memoryObjects) {
	t.Helper()
	objects := &memoryObjects{data: map[string][]byte{}}
	s, e := Open(filepath.Join(t.TempDir(), "replay-archive.json"), make([]byte, 32), nil, memorySource{[]byte("synthetic opaque ciphertext")}, func(context.Context, Config) (replaystore.Objects, error) { return objects, nil })
	require.NoError(t, e)
	t.Cleanup(s.Close)
	return s, objects
}
func archiveConfig(t *testing.T, s *Store) Config {
	t.Helper()
	c, e := s.Save("operator", Input{Config: Config{Provider: "postgres", Enabled: true}, RequestID: "configure-0001"})
	require.NoError(t, e)
	return c
}

var terminalRef = Ref{Kind: "terminal", SessionID: "terminal-session-0001"}

func TestReplayArchiveEncryptedHistoryReceiptsAndDefaultOffline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay-archive.json")
	var calls atomic.Int32
	factory := func(context.Context, Config) (replaystore.Objects, error) {
		calls.Add(1)
		return nil, errors.New("private endpoint failure")
	}
	key := make([]byte, 32)
	s, e := Open(path, key, nil, memorySource{[]byte("cipher")}, factory)
	require.NoError(t, e)
	defer s.Close()
	c, e := s.Config()
	require.NoError(t, e)
	assert.Equal(t, "local", c.Provider)
	require.NoError(t, s.Enqueue(terminalRef))
	assert.NoFileExists(t, path)
	assert.Zero(t, calls.Load())
	in := Input{Config: Config{Provider: "s3", Enabled: true, Cloud: &replaystore.CloudConfig{Provider: "s3", Endpoint: "https://storage.example.com", Region: "us-east-1", Bucket: "replays", AccessKeyID: "synthetic-key", SecretAccessKey: "synthetic-secret", SessionToken: "synthetic-token"}}, RequestID: "cloud-config-001"}
	c, e = s.Save("operator", in)
	require.NoError(t, e)
	assert.True(t, c.HasSecret)
	assert.True(t, c.HasSessionToken)
	assert.Empty(t, c.Cloud.SecretAccessKey)
	assert.Empty(t, c.Cloud.SessionToken)
	same, e := s.Save("operator", in)
	require.NoError(t, e)
	assert.Equal(t, c, same)
	changed := in
	changed.Enabled = false
	_, e = s.Save("operator", changed)
	assert.ErrorIs(t, e, ErrConflict)
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "synthetic-secret")
	assert.NotContains(t, string(raw), "synthetic-token")
	assert.NotContains(t, string(raw), "storage.example.com")
	// An unrelated mutation does not change the result of a retried request.
	next := Input{Config: c, RequestID: "cloud-rotate-001"}
	next.Cloud = cloneConfig(c).Cloud
	next.Cloud.SecretAccessKey = "rotated-secret"
	next.ClearSessionToken = true
	rotated, e := s.Save("operator", next)
	require.NoError(t, e)
	assert.Equal(t, 2, rotated.Revision)
	assert.False(t, rotated.HasSessionToken)
	again, e := s.Save("operator", in)
	require.NoError(t, e)
	assert.Equal(t, c, again)
	s.Close()
	s, e = Open(path, key, nil, memorySource{[]byte("cipher")}, factory)
	require.NoError(t, e)
	defer s.Close()
	current, e := s.Config()
	require.NoError(t, e)
	assert.Equal(t, rotated, current)
	assert.Zero(t, calls.Load())
	assert.Len(t, s.data.History, 2)
	_, e = Open(path, bytes.Repeat([]byte{9}, 32), nil, memorySource{[]byte("cipher")}, factory)
	assert.ErrorIs(t, e, ErrInvalid)
}
func TestReplayArchiveLostUploadResponseDuplicateCompletionAndRestart(t *testing.T) {
	s, o := archiveStore(t)
	archiveConfig(t, s)
	require.NoError(t, s.Enqueue(terminalRef))
	require.NoError(t, s.Enqueue(terminalRef))
	_, n, e := s.List(0, 100)
	require.NoError(t, e)
	assert.Equal(t, 1, n)
	o.lostResponse = true
	worked, e := s.ProcessNext(context.Background())
	assert.True(t, worked)
	require.Error(t, e)
	r, e := s.Get(terminalRef)
	require.NoError(t, e)
	assert.Equal(t, "queued", r.Status)
	assert.Equal(t, 1, r.Attempts)
	assert.False(t, s.Available(terminalRef))
	reset, e := s.Retry(terminalRef, "operator", "retry-upload-001")
	require.NoError(t, e)
	same, e := s.Retry(terminalRef, "operator", "retry-upload-001")
	require.NoError(t, e)
	assert.Equal(t, reset, same)
	worked, e = s.ProcessNext(context.Background())
	require.NoError(t, e)
	assert.True(t, worked)
	assert.True(t, s.Available(terminalRef))
	assert.Equal(t, 2, o.puts)
	assert.Equal(t, 1, o.gets)
	// No second upload after a duplicate terminal close, including after reopen.
	require.NoError(t, s.Enqueue(terminalRef))
	worked, e = s.ProcessNext(context.Background())
	require.NoError(t, e)
	assert.False(t, worked)
	s.Close()
	reopened, e := Open(s.path, make([]byte, 32), nil, s.source, s.factory)
	require.NoError(t, e)
	defer reopened.Close()
	assert.True(t, reopened.Available(terminalRef))
	worked, e = reopened.ProcessNext(context.Background())
	require.NoError(t, e)
	assert.False(t, worked)
	for range 2 {
		f, e := reopened.OpenCiphertext(context.Background(), terminalRef)
		require.NoError(t, e)
		data, e := io.ReadAll(f)
		require.NoError(t, e)
		require.NoError(t, f.Close())
		assert.Equal(t, []byte("synthetic opaque ciphertext"), data)
	}
	assert.Equal(t, 2, o.gets)
}
func TestReplayArchiveRemoteCorruptionNeverMarksStoredAndVerifyBypassesCache(t *testing.T) {
	s, o := archiveStore(t)
	archiveConfig(t, s)
	require.NoError(t, s.Enqueue(terminalRef))
	o.corrupt = true
	_, e := s.ProcessNext(context.Background())
	assert.ErrorIs(t, e, ErrIntegrity)
	r, e := s.Get(terminalRef)
	require.NoError(t, e)
	assert.Equal(t, "integrity_mismatch", r.ErrorCode)
	assert.False(t, s.Available(terminalRef))
	o.corrupt = false
	_, e = s.Retry(terminalRef, "operator", "retry-integrity-001")
	require.NoError(t, e)
	_, e = s.ProcessNext(context.Background())
	require.NoError(t, e)
	f, e := s.OpenCiphertext(context.Background(), terminalRef)
	require.NoError(t, e)
	require.NoError(t, f.Close())
	o.corrupt = true
	_, e = s.Verify(context.Background(), terminalRef, "operator")
	assert.ErrorIs(t, e, ErrIntegrity)
	audit, n, e := s.Audit(0, 100)
	require.NoError(t, e)
	assert.Equal(t, 2, n)
	for _, a := range audit {
		assert.NotEqual(t, "verify", a.Action)
	}
	// A verified local cache does not make a failed remote readback succeed.
	o.corrupt = false
	_, e = s.Verify(context.Background(), terminalRef, "operator")
	require.NoError(t, e)
	audit, _, e = s.Audit(0, 100)
	require.NoError(t, e)
	assert.Equal(t, "verify", audit[0].Action)
}
func TestReplayArchiveConfigurationChangeCancelsInflightWorkAndPreservesHistory(t *testing.T) {
	s, o := archiveStore(t)
	c := archiveConfig(t, s)
	require.NoError(t, s.Enqueue(terminalRef))
	o.block = make(chan struct{})
	entered := make(chan struct{})
	s.factory = func(ctx context.Context, c Config) (replaystore.Objects, error) { close(entered); return o, nil }
	done := make(chan error, 1)
	go func() { _, e := s.ProcessNext(context.Background()); done <- e }()
	<-entered
	next := Input{Config: c, RequestID: "disable-storage-001"}
	next.Enabled = false
	_, e := s.Save("operator", next)
	require.NoError(t, e)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("configuration did not cancel upload")
	}
	r, e := s.Get(terminalRef)
	require.NoError(t, e)
	assert.Equal(t, "queued", r.Status)
	assert.Equal(t, 0, r.Attempts)
	worked, e := s.ProcessNext(context.Background())
	require.NoError(t, e)
	assert.False(t, worked)
	assert.Equal(t, 1, r.ConfigRevision)
}
func TestReplayArchiveConcurrentNotificationsClaimsAndCacheDownloadsAreSingle(t *testing.T) {
	s, o := archiveStore(t)
	archiveConfig(t, s)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); assert.NoError(t, s.Enqueue(terminalRef)) }()
	}
	wg.Wait()
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := s.ProcessNext(context.Background()); assert.NoError(t, e) }()
	}
	wg.Wait()
	assert.Equal(t, 1, o.puts)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, e := s.OpenCiphertext(context.Background(), terminalRef)
			if !assert.NoError(t, e) {
				return
			}
			_, e = io.Copy(io.Discard, f)
			assert.NoError(t, e)
			assert.NoError(t, f.Close())
		}()
	}
	wg.Wait()
	assert.Equal(t, 2, o.gets)
	s.Close()
	s.Close()
	entries, e := os.ReadDir(filepath.Join(filepath.Dir(s.path), "replay-cache"))
	require.NoError(t, e)
	assert.Empty(t, entries)
}
func TestReplayArchiveHistoricalLocatorAndSecretRotation(t *testing.T) {
	s, _ := archiveStore(t)
	first := Input{Config: Config{Provider: "s3", Enabled: true, Cloud: &replaystore.CloudConfig{Provider: "s3", Endpoint: "https://old.example.com", Region: "us-east-1", Bucket: "replays", AccessKeyID: "key-1", SecretAccessKey: "secret-1"}}, RequestID: "locator-initial-001"}
	c, e := s.Save("operator", first)
	require.NoError(t, e)
	rotate := Input{Config: c, RequestID: "locator-rotate-001"}
	rotate.Cloud = cloneConfig(c).Cloud
	rotate.Cloud.SecretAccessKey = "secret-2"
	c, e = s.Save("operator", rotate)
	require.NoError(t, e)
	s.mu.Lock()
	resolved := s.credentials(1)
	s.mu.Unlock()
	assert.Equal(t, "secret-2", resolved.Cloud.SecretAccessKey)
	move := Input{Config: c, RequestID: "locator-move-001"}
	move.Cloud = cloneConfig(c).Cloud
	move.Cloud.Endpoint = "https://new.example.com"
	_, e = s.Save("operator", move)
	assert.ErrorIs(t, e, ErrInvalid)
	move.Cloud.SecretAccessKey = "secret-3"
	_, e = s.Save("operator", move)
	require.NoError(t, e)
	s.mu.Lock()
	resolved = s.credentials(1)
	s.mu.Unlock()
	assert.Equal(t, "https://old.example.com", resolved.Cloud.Endpoint)
	assert.Equal(t, "secret-2", resolved.Cloud.SecretAccessKey)
}
