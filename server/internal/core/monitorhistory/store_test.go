package monitorhistory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testAt = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
var testBinding = strings.Repeat("a", 64)

func historyEnv(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, e := Open(dir, make([]byte, 32), nil)
	require.NoError(t, e)
	s.now = func() time.Time { return testAt.Add(time.Hour) }
	t.Cleanup(s.Close)
	return s, dir
}
func point(at time.Time, value float64) Sample {
	return Sample{At: at, Binding: testBinding, State: "online", Values: map[string]float64{"cpu_percent": value}}
}

func TestMinuteSamplesIdempotencyConflictsMissingAndAggregation(t *testing.T) {
	s, _ := historyEnv(t)
	p := point(testAt.Add(2*time.Second), 0)
	wrote, e := s.Record("host1", p)
	require.NoError(t, e)
	assert.True(t, wrote)
	p = point(testAt.Add(30*time.Second), 20)
	wrote, e = s.Record("host1", p)
	require.NoError(t, e)
	assert.True(t, wrote)
	wrote, e = s.Record("host1", p)
	require.NoError(t, e)
	assert.False(t, wrote)
	wrote, e = s.Record("host1", point(testAt.Add(10*time.Second), 99))
	require.NoError(t, e)
	assert.False(t, wrote)
	_, e = s.Record("host1", point(p.At, 21))
	require.ErrorIs(t, e, ErrConflict)
	_, e = s.Record("host1", Sample{At: testAt.Add(75 * time.Second), Binding: testBinding, State: "offline", Values: map[string]float64{}})
	require.NoError(t, e)
	p = point(testAt.Add(195*time.Second), 80)
	p.Values["network_rx_bps"] = 0
	_, e = s.Record("host1", p)
	require.NoError(t, e)
	page, e := s.Query("host1", testBinding, testAt, testAt.Add(5*time.Minute), 300)
	require.NoError(t, e)
	require.Len(t, page.Results, 1)
	r := page.Results[0]
	assert.Equal(t, "mixed", r.State)
	assert.Equal(t, 3, r.Samples)
	assert.Equal(t, 2, r.Online)
	assert.Equal(t, 1, r.Offline)
	assert.Equal(t, Statistic{Mean: 50, Min: 20, Max: 80, Samples: 2}, r.Values["cpu_percent"])
	assert.Equal(t, Statistic{Samples: 1}, r.Values["network_rx_bps"])
	assert.NotContains(t, r.Values, "network_tx_bps")
	page, e = s.Query("host1", testBinding, testAt, testAt.Add(5*time.Minute), 60)
	require.NoError(t, e)
	assert.Equal(t, "offline", page.Results[1].State)
	assert.Empty(t, page.Results[1].Values)
	assert.Equal(t, "no_data", page.Results[2].State)
	assert.Empty(t, page.Results[2].Values)
	page, e = s.Query("host1", strings.Repeat("b", 64), testAt, testAt.Add(5*time.Minute), 60)
	require.NoError(t, e)
	for _, p := range page.Results {
		assert.Equal(t, "no_data", p.State)
		assert.Empty(t, p.Values)
	}
	raw, e := json.Marshal(page)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), testBinding)
}

func TestEncryptedRestartWrongKeyCorruptionAndCacheBound(t *testing.T) {
	s, dir := historyEnv(t)
	for i := 0; i < 12; i++ {
		_, e := s.Record(fmt.Sprint("host", i), point(testAt, 10))
		require.NoError(t, e)
	}
	assert.LessOrEqual(t, len(s.cache), cacheSize)
	for _, entry := range mustEntries(t, dir) {
		raw, e := os.ReadFile(filepath.Join(dir, entry.Name()))
		require.NoError(t, e)
		assert.NotContains(t, string(raw), "cpu_percent")
		assert.NotContains(t, string(raw), testBinding)
		assert.NotContains(t, string(raw), "host1")
	}
	s.Close()
	other, e := Open(dir, make([]byte, 32), nil)
	require.NoError(t, e)
	defer other.Close()
	other.now = s.now
	page, e := other.Query("host1", testBinding, testAt, testAt.Add(time.Minute), 60)
	require.NoError(t, e)
	assert.Equal(t, 10.0, page.Results[0].Values["cpu_percent"].Mean)
	key := make([]byte, 32)
	key[0] = 1
	_, e = Open(dir, key, nil)
	require.ErrorIs(t, e, ErrCorrupt)
	path := filepath.Join(dir, segmentKey("host1", testAt)+".json")
	require.NoError(t, os.WriteFile(path, []byte(`{"Version":1,"Nonce":"broken","Data":"broken"}`), 0600))
	other.cache = map[string]segment{}
	_, e = other.Query("host1", testBinding, testAt, testAt.Add(time.Minute), 60)
	require.ErrorIs(t, e, ErrCorrupt)
	assert.Equal(t, "history_unavailable", other.Health().ErrorCode)
}
func mustEntries(t *testing.T, dir string) []os.DirEntry {
	t.Helper()
	entries, e := os.ReadDir(dir)
	require.NoError(t, e)
	return entries
}

func TestPersistenceFailureDoesNotAdvanceMemoryAndRetryIsSafe(t *testing.T) {
	s, _ := historyEnv(t)
	s.saveHook = func(string, []byte) error { return errors.New("synthetic storage fault") }
	p := point(testAt, 12)
	_, e := s.Record("host1", p)
	require.Error(t, e)
	assert.Empty(t, s.cache)
	assert.Empty(t, s.keys)
	assert.Equal(t, "history_unavailable", s.Health().ErrorCode)
	s.saveHook = nil
	wrote, e := s.Record("host1", p)
	require.NoError(t, e)
	assert.True(t, wrote)
	wrote, e = s.Record("host1", p)
	require.NoError(t, e)
	assert.False(t, wrote)
	assert.Empty(t, s.Health().ErrorCode)
}

func TestCancelledQueryDoesNotReadOrInventData(t *testing.T) {
	s, _ := historyEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e := s.QueryContext(ctx, "host1", testBinding, testAt, testAt.Add(time.Hour), 60)
	require.ErrorIs(t, e, context.Canceled)
	assert.Empty(t, s.keys)
}

func TestRetentionPhysicallyPrunesOwnedSegmentsAndRepeats(t *testing.T) {
	s, dir := historyEnv(t)
	_, e := s.Record("host1", point(testAt, 12))
	require.NoError(t, e)
	s.now = func() time.Time { return testAt.Add(Retention + 2*time.Hour) }
	require.NoError(t, s.Prune(true))
	require.NoError(t, s.Prune(true))
	assert.Empty(t, s.keys)
	assert.Empty(t, s.cache)
	entries := mustEntries(t, dir)
	require.Len(t, entries, 1)
	assert.Equal(t, "meta.json", entries[0].Name())
	wrote, e := s.Record("host1", point(testAt, 12))
	require.NoError(t, e)
	assert.False(t, wrote)
}

func TestInputRangeCapacityAndConcurrentObservations(t *testing.T) {
	s, _ := historyEnv(t)
	for _, bad := range []Sample{point(testAt, math.NaN()), point(testAt, math.Inf(1)), point(testAt, 101), point(testAt, -1), point(s.now().Add(time.Minute+time.Second), 12), {At: testAt, Binding: "bad", State: "online"}, {At: testAt, Binding: testBinding, State: "offline", Values: map[string]float64{"cpu_percent": 0}}} {
		_, e := s.Record("host1", bad)
		require.ErrorIs(t, e, ErrInvalid)
	}
	_, e := s.Record("../escape", point(testAt, 12))
	require.ErrorIs(t, e, ErrInvalid)
	for _, step := range []int{0, 59, 61, 3601} {
		_, e := s.Query("host1", testBinding, testAt, testAt.Add(time.Hour), step)
		require.ErrorIs(t, e, ErrInvalid)
	}
	_, e = s.Query("host1", testBinding, testAt.Add(-Retention), testAt, 60)
	require.ErrorIs(t, e, ErrInvalid)
	var wg sync.WaitGroup
	errorsOut := make(chan error, 60)
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, e := s.Record("host1", point(testAt.Add(time.Duration(i)*time.Minute), float64(i)))
			errorsOut <- e
		}(i)
	}
	wg.Wait()
	close(errorsOut)
	for e := range errorsOut {
		require.NoError(t, e)
	}
	page, e := s.Query("host1", testBinding, testAt, testAt.Add(time.Hour), 60)
	require.NoError(t, e)
	require.Len(t, page.Results, 60)
	for _, p := range page.Results {
		assert.Equal(t, 1, p.Samples)
	}
	for len(s.keys) < MaxSegments {
		s.keys[fmt.Sprint("capacity", len(s.keys))] = true
	}
	_, e = s.Record("other-host", point(testAt, 1))
	require.ErrorIs(t, e, ErrCapacity)
	assert.Equal(t, "history_capacity", s.Health().ErrorCode)
	s.Close()
	_, e = s.Record("host1", point(testAt, 1))
	require.ErrorIs(t, e, ErrClosed)
}

func TestSharedHistorySurvivesReopenScopeIsolationAndPruning(t *testing.T) {
	dbURL := os.Getenv("JMS_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for real PostgreSQL monitoring history")
	}
	docs, e := storage.OpenPostgres(context.Background(), dbURL, fmt.Sprintf("history-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	leftName, rightName := strings.Repeat("a", 40), "other"
	t.Cleanup(func() {
		for _, prefix := range []string{leftName + ":", rightName + ":"} {
			keys, e := docs.Keys(prefix, MaxSegments+1)
			require.NoError(t, e)
			for _, key := range keys {
				require.NoError(t, docs.Delete(key))
			}
		}
		require.NoError(t, docs.Close())
	})
	left, e := docs.Scoped(leftName)
	require.NoError(t, e)
	right, e := docs.Scoped(rightName)
	require.NoError(t, e)
	s, e := Open(t.TempDir(), make([]byte, 32), left)
	require.NoError(t, e)
	s.now = func() time.Time { return testAt.Add(time.Hour) }
	_, e = s.Record("host1", point(testAt, 12))
	require.NoError(t, e)
	s.Close()
	next, e := Open(t.TempDir(), make([]byte, 32), left)
	require.NoError(t, e)
	defer next.Close()
	next.now = s.now
	p, e := next.Query("host1", testBinding, testAt, testAt.Add(time.Minute), 60)
	require.NoError(t, e)
	assert.Equal(t, 12.0, p.Results[0].Values["cpu_percent"].Mean)
	other, e := Open(t.TempDir(), make([]byte, 32), right)
	require.NoError(t, e)
	defer other.Close()
	other.now = s.now
	p, e = other.Query("host1", testBinding, testAt, testAt.Add(time.Minute), 60)
	require.NoError(t, e)
	assert.Equal(t, "no_data", p.Results[0].State)
	next.now = func() time.Time { return testAt.Add(Retention + 2*time.Hour) }
	require.NoError(t, next.Prune(true))
	require.NoError(t, next.Prune(true))
	keys, e := left.Keys("mh:", MaxSegments+1)
	require.NoError(t, e)
	assert.Equal(t, []string{"mh:meta"}, keys)
}
