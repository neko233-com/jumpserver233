package updates

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdatePolicyIdempotenceRevisionAuditAndRestart(t *testing.T) {
	var calls atomic.Int32
	feed := feedFor(t, metadata([]byte("archive")), nil, &calls)
	path := filepath.Join(t.TempDir(), "updates.json")
	s, e := Open(path, nil, feed)
	require.NoError(t, e)
	assert.False(t, s.Snapshot().Settings.Automatic)
	first := s.Snapshot().Settings
	saved, e := s.Save(first, "admin", "admin")
	require.NoError(t, e)
	assert.Equal(t, first, saved)
	assert.Empty(t, s.Audit())
	first.Automatic = true
	saved, e = s.Save(first, "admin", "admin")
	require.NoError(t, e)
	assert.Equal(t, 2, saved.Revision)
	_, e = s.Save(first, "admin", "admin")
	assert.ErrorIs(t, e, ErrConflict)
	r, e := s.Check(context.Background(), 2, "request-0001", "admin", "admin")
	require.NoError(t, e)
	assert.Equal(t, "update_available", r.Status)
	repeat, e := s.Check(context.Background(), 2, "request-0001", "admin", "admin")
	require.NoError(t, e)
	assert.Equal(t, r, repeat)
	assert.EqualValues(t, 1, calls.Load())
	_, e = s.Check(context.Background(), 3, "request-0001", "admin", "admin")
	assert.ErrorIs(t, e, ErrConflict)
	_, e = s.Check(context.Background(), 2, "request-0002", "admin", "admin")
	assert.ErrorIs(t, e, ErrLimited)
	opened, e := Open(path, nil, feed)
	require.NoError(t, e)
	assert.Equal(t, s.Snapshot(), opened.Snapshot())
	assert.Len(t, opened.Audit(), 2)
	rows := opened.Audit()
	rows[0].After.Automatic = false
	assert.True(t, opened.Audit()[0].After.Automatic)
	feed.current = "v1.2.3"
	assert.Equal(t, "up_to_date", opened.Snapshot().Result.Status)
	feed.arch = "arm64"
	assert.Nil(t, opened.Snapshot().Result.Artifact)
}
func TestFailedChecksRetainSuccessfulEvidenceAndPersistenceFailuresAreNotApplied(t *testing.T) {
	var calls atomic.Int32
	feed := feedFor(t, metadata([]byte("archive")), nil, &calls)
	s, e := Open(filepath.Join(t.TempDir(), "updates.json"), nil, feed)
	require.NoError(t, e)
	_, e = s.Check(context.Background(), 1, "request-0001", "admin", "admin")
	require.NoError(t, e)
	success := s.Snapshot().LastSuccess
	s.mu.Lock()
	s.data.LastAttempt = time.Now().Add(-time.Hour)
	s.mu.Unlock()
	feed.client = transport(func(*http.Request) (*http.Response, error) { return respond(500, nil), nil })
	_, e = s.Check(context.Background(), 1, "request-0002", "admin", "admin")
	assert.ErrorIs(t, e, ErrNetwork)
	assert.Equal(t, success, s.Snapshot().LastSuccess)
	assert.Equal(t, "update_available", s.Snapshot().Result.Status)
	assert.Equal(t, "network", s.Snapshot().Error)
	_, e = s.Check(context.Background(), 1, "request-0002", "admin", "admin")
	assert.ErrorIs(t, e, ErrNetwork)
	before := s.Snapshot()
	s.saveHook = func([]byte) error { return errors.New("synthetic save failure") }
	in := before.Settings
	in.Automatic = true
	_, e = s.Save(in, "admin", "admin")
	assert.Error(t, e)
	assert.Equal(t, before, s.Snapshot())
}
func TestAutomaticCheckingHasAnExplicitLifecycleAndDoesNotOverlap(t *testing.T) {
	var calls atomic.Int32
	s, e := Open(filepath.Join(t.TempDir(), "updates.json"), nil, feedFor(t, metadata([]byte("archive")), nil, &calls))
	require.NoError(t, e)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	<-done
	assert.Zero(t, calls.Load())
	in := s.Snapshot().Settings
	in.Automatic = true
	_, e = s.Save(in, "admin", "admin")
	require.NoError(t, e)
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	require.Eventually(t, func() bool { return !s.Snapshot().LastSuccess.IsZero() }, time.Second, time.Millisecond)
	cancel()
	<-done
	assert.EqualValues(t, 1, calls.Load())
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	<-done
	assert.EqualValues(t, 1, calls.Load())
}

func TestUpdatePostgresTakeoverRetainsPolicyAuditAndRequestReceipts(t *testing.T) {
	db := os.Getenv("JMS_TEST_DATABASE_URL")
	if db == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for real shared update state")
	}
	namespace := "updates-" + time.Now().Format("20060102150405.000000000")
	docs, e := storage.OpenPostgres(context.Background(), db, namespace)
	require.NoError(t, e)
	defer docs.Close()
	defer func() { require.NoError(t, docs.Delete("updates")) }()
	var calls atomic.Int32
	feed := feedFor(t, metadata([]byte("archive")), nil, &calls)
	s, e := Open(filepath.Join(t.TempDir(), "updates.json"), docs, feed)
	require.NoError(t, e)
	in := s.Snapshot().Settings
	in.IntervalHours = 48
	_, e = s.Save(in, "admin", "admin")
	require.NoError(t, e)
	_, e = s.Check(context.Background(), 2, "takeover-request-0001", "admin", "admin")
	require.NoError(t, e)
	second, e := storage.OpenPostgres(context.Background(), db, namespace)
	require.NoError(t, e)
	defer second.Close()
	takeover, e := Open(filepath.Join(t.TempDir(), "updates.json"), second, feed)
	require.NoError(t, e)
	assert.Equal(t, s.Snapshot(), takeover.Snapshot())
	assert.Equal(t, s.Audit(), takeover.Audit())
	_, e = takeover.Check(context.Background(), 2, "takeover-request-0001", "admin", "admin")
	require.NoError(t, e)
	assert.EqualValues(t, 1, calls.Load())
}
