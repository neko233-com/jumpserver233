package loginaudit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func reviewBatch(start, n int, at time.Time) SourceBatch {
	b := SourceBatch{Cursor: fmt.Sprintf("native-%d", start+n), Events: make([]Input, n)}
	for i := range b.Events {
		b.Events[i] = Input{ID: fmt.Sprintf("review-event-%d", start+i), At: at, Method: "oidc", Stage: "review", Outcome: "review_pending", UserID: "synthetic-user", Username: "synthetic.operator", SourceIP: "192.0.2.1", ReviewID: fmt.Sprintf("review-%d", start+i)}
	}
	return b
}
func TestBatchCursorCommitFailureRestartAndDedup(t *testing.T) {
	s, dir := openTest(t)
	b := reviewBatch(0, 600, time.Now().UTC())
	s.saveHook = func(key string, _ []byte) error {
		if key == "index" {
			return errors.New("synthetic fault")
		}
		return nil
	}
	require.Error(t, s.Import(b))
	assert.Empty(t, s.reviewCursor())
	assert.Zero(t, s.Health().Records)
	s.Close()
	peer, e := Open(dir, make([]byte, 32), nil)
	require.NoError(t, e)
	defer peer.Close()
	require.NoError(t, peer.Import(b))
	assert.Equal(t, b.Cursor, peer.reviewCursor())
	assert.Equal(t, 600, peer.Health().Records)
	writes := 0
	peer.saveHook = func(string, []byte) error { writes++; return nil }
	require.NoError(t, peer.Import(b))
	assert.Zero(t, writes)
	require.NoError(t, peer.Import(SourceBatch{Cursor: b.Cursor, Gap: true}))
	assert.True(t, peer.Health().ReviewGap)
	peer.Close()
	restored, e := Open(dir, make([]byte, 32), nil)
	require.NoError(t, e)
	defer restored.Close()
	assert.True(t, restored.Health().ReviewGap)
	assert.Equal(t, b.Cursor, restored.reviewCursor())
	page, e := restored.List(Filter{Limit: 1}, nil)
	require.NoError(t, e)
	assert.Equal(t, uint64(600), page.Results[0].Sequence)
}
func TestCapacityRetentionAndCorruption(t *testing.T) {
	s, dir := openTest(t)
	at := time.Now().UTC()
	s.now = func() time.Time { return at }
	for start := 0; start < 110000; start += 10000 {
		require.NoError(t, s.Import(reviewBatch(start, 10000, at)))
	}
	h := s.Health()
	assert.LessOrEqual(t, h.Records, MaxRecords)
	assert.Greater(t, h.FirstSequence, uint64(1))
	_, e := s.Get("review-event-0")
	assert.ErrorIs(t, e, ErrNotFound)
	s.Close()
	peer, e := Open(dir, make([]byte, 32), nil)
	require.NoError(t, e)
	defer peer.Close()
	assert.Equal(t, h.Records, peer.Health().Records)
	peer.now = func() time.Time { return at.Add(Retention + time.Hour) }
	p, e := peer.List(Filter{Limit: 25}, nil)
	require.NoError(t, e)
	assert.Zero(t, p.Total)
	_, e = peer.Get("review-event-109999")
	assert.ErrorIs(t, e, ErrNotFound)
	require.NoError(t, peer.Import(reviewBatch(110000, 1, peer.now())))
	assert.LessOrEqual(t, peer.Health().Records, SegmentSize)
	// Reader TTL applies even while deletion of old full segments is catching up.
	p, e = peer.List(Filter{Limit: 25}, nil)
	require.NoError(t, e)
	assert.Equal(t, 1, p.Total)
	peer.Close()
	raw, e := os.ReadFile(filepath.Join(dir, "index.json"))
	require.NoError(t, e)
	raw[len(raw)-3] ^= 1
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.json"), raw, 0600))
	_, e = Open(dir, make([]byte, 32), nil)
	require.Error(t, e)
}
func TestConcurrentAppendShutdownAndSourceCancellation(t *testing.T) {
	s, _ := openTest(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 8 {
				_, e := s.Append(input())
				assert.NoError(t, e)
				_, e = s.List(Filter{Limit: 1}, nil)
				assert.NoError(t, e)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 64, s.Health().Records)
	entered, exited := make(chan struct{}), make(chan struct{})
	s.Start(context.Background(), func(ctx context.Context, _ string) (SourceBatch, error) {
		close(entered)
		<-ctx.Done()
		close(exited)
		return SourceBatch{}, ctx.Err()
	})
	<-entered
	s.Close()
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("source did not join")
	}
	require.ErrorIs(t, s.Import(SourceBatch{}), ErrClosed)
	_, e := s.Append(input())
	require.ErrorIs(t, e, ErrClosed)
}
func TestInvalidBatchesAndIndexCursor(t *testing.T) {
	s, dir := openTest(t)
	for _, b := range []SourceBatch{{Cursor: "../escape"}, {Events: []Input{{ID: "bad"}}}} {
		assert.ErrorIs(t, s.Import(b), ErrInvalid)
	}
	d := s.data
	d.ReviewCursor = "../escape"
	require.NoError(t, s.save("index", d))
	s.Close()
	_, e := Open(dir, make([]byte, 32), nil)
	assert.ErrorIs(t, e, ErrInvalid)
}
func TestPostgresPlatformScopeAndTakeover(t *testing.T) {
	dsn := os.Getenv("JMS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for platform audit takeover")
	}
	docs, e := storage.OpenPostgres(context.Background(), dsn, fmt.Sprintf("login-audit-test-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	defer docs.Close()
	platform, e := docs.Scoped("platform-identity")
	require.NoError(t, e)
	s, e := Open(t.TempDir(), make([]byte, 32), platform)
	require.NoError(t, e)
	r, e := s.Append(input())
	require.NoError(t, e)
	s.Close()
	peer, e := Open(t.TempDir(), make([]byte, 32), platform)
	require.NoError(t, e)
	defer peer.Close()
	got, e := peer.Get(r.ID)
	require.NoError(t, e)
	assert.Equal(t, r, got)
	org, e := docs.Scoped("organization-a")
	require.NoError(t, e)
	isolated, e := Open(t.TempDir(), make([]byte, 32), org)
	require.NoError(t, e)
	defer isolated.Close()
	assert.Zero(t, isolated.Health().Records)
}
func BenchmarkReviewFeedIdle(b *testing.B) {
	s, e := Open(b.TempDir(), make([]byte, 32), nil)
	if e != nil {
		b.Fatal(e)
	}
	defer s.Close()
	if e = s.Import(reviewBatch(0, 10000, time.Now().UTC())); e != nil {
		b.Fatal(e)
	}
	anchor := s.events[len(s.events)-1].ID
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, e = s.NotificationFeed(context.Background(), anchor, time.Time{}, 100); e != nil {
			b.Fatal(e)
		}
	}
}
