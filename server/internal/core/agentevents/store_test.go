package agentevents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func eventPage(stream string, first, count int, prior string, requested hostagent.EventCursor) hostagent.EventSnapshot {
	s := hostagent.EventSnapshot{Format: hostagent.EventFormat, Stream: stream, FirstSequence: uint64(first), LastSequence: uint64(first + count - 1), AnchorHash: prior, Requested: requested, Events: []hostagent.Event{}}
	for i := 0; i < count; i++ {
		e := hostagent.Event{Sequence: uint64(first + i), ID: fmt.Sprintf("%032x", first+i), Attempt: fmt.Sprintf("%032x", 1), At: time.Now().UTC(), Kind: "repair_completed", Trigger: "supervisor", ConfigSHA: hostagent.SHA([]byte("configuration")), PreviousHash: prior}
		e.Hash = hostagent.EventHash(e)
		prior = e.Hash
		s.Events = append(s.Events, e)
	}
	return s
}

var src = Source{AssetID: "asset-a", AssetName: "QA host", Account: "ops"}
var col = Collector{ID: "u", Name: "collector", JobID: "job-qa"}

func open(t *testing.T) *Store {
	t.Helper()
	s, e := Open(t.TempDir(), make([]byte, 32), nil)
	require.NoError(t, e)
	t.Cleanup(s.Close)
	return s
}
func TestEventImportDeduplicatesAcrossRestartAndEncryptsSegments(t *testing.T) {
	s := open(t)
	p := eventPage(fmt.Sprintf("%032x", 1), 1, 4, hostagent.SHA(nil), hostagent.EventCursor{})
	n, e := s.Import(src, col, p.Requested, p)
	require.NoError(t, e)
	require.Equal(t, 4, n)
	n, e = s.Import(src, col, p.Requested, p)
	require.NoError(t, e)
	require.Zero(t, n)
	cursor, e := s.Cursor(src)
	require.NoError(t, e)
	require.Equal(t, uint64(4), cursor.Sequence)
	raw, e := os.ReadFile(filepath.Join(s.dir, "segment-000000000000.json"))
	require.NoError(t, e)
	require.NotContains(t, string(raw), "QA host")
	require.NotContains(t, string(raw), "repair_completed")
	s.Close()
	reopened, e := Open(s.dir, make([]byte, 32), nil)
	require.NoError(t, e)
	defer reopened.Close()
	page, e := reopened.List(0, 2, func(v Source) bool { return v.Account == "ops" })
	require.NoError(t, e)
	require.Len(t, page.Results, 2)
	require.Equal(t, uint64(4), page.Results[0].Index)
	older, e := reopened.List(page.NextBefore, 2, func(Source) bool { return true })
	require.NoError(t, e)
	require.Equal(t, uint64(2), older.Results[0].Index)
	foreign, e := reopened.List(0, 50, func(v Source) bool { return v.AssetID == "other" })
	require.NoError(t, e)
	require.Empty(t, foreign.Results)
	_, e = Open(s.dir, []byte("another-key-32-bytes-long-padding"), nil)
	require.Error(t, e)
}
func TestEventImportReportsGapsResetAndMissingAndRejectsRollback(t *testing.T) {
	s := open(t)
	p := eventPage(fmt.Sprintf("%032x", 1), 1, 2, hostagent.SHA(nil), hostagent.EventCursor{})
	_, e := s.Import(src, col, p.Requested, p)
	require.NoError(t, e)
	c, _ := s.Cursor(src)
	gap := eventPage(p.Stream, 7, 2, hostagent.SHA([]byte("lost")), c)
	_, e = s.Import(src, col, c, gap)
	require.NoError(t, e)
	c, _ = s.Cursor(src)
	require.Equal(t, uint64(8), c.Sequence)
	reset := eventPage(fmt.Sprintf("%032x", 2), 1, 2, hostagent.SHA(nil), c)
	_, e = s.Import(src, col, c, reset)
	require.NoError(t, e)
	_, e = s.Import(src, col, p.Requested, p)
	require.ErrorIs(t, e, ErrConflict)
	c, _ = s.Cursor(src)
	missing := hostagent.EventSnapshot{Format: hostagent.EventFormat, Missing: true, Requested: c, Events: []hostagent.Event{}}
	n, e := s.Import(src, col, c, missing)
	require.NoError(t, e)
	require.Equal(t, 1, n)
	n, e = s.Import(src, col, c, missing)
	require.NoError(t, e)
	require.Zero(t, n)
	rollback := eventPage(reset.Stream, 1, 1, hostagent.SHA(nil), c)
	rollback.Events = nil
	_, e = s.Import(src, col, c, rollback)
	require.ErrorIs(t, e, ErrConflict)
	page, e := s.List(0, 50, func(Source) bool { return true })
	require.NoError(t, e)
	kinds := map[string]int{}
	for _, r := range page.Results {
		kinds[r.Kind]++
	}
	require.Equal(t, 1, kinds["history_gap"])
	require.Equal(t, 1, kinds["stream_changed"])
	require.Equal(t, 1, kinds["journal_missing"])
}
func TestEventImportIndexFailureKeepsCursorAndIgnoresUncommittedTail(t *testing.T) {
	s := open(t)
	p := eventPage(fmt.Sprintf("%032x", 1), 1, 4, hostagent.SHA(nil), hostagent.EventCursor{})
	s.saveHook = func(k string, _ []byte) error {
		if k == "index" {
			return errors.New("synthetic disk failure")
		}
		return nil
	}
	_, e := s.Import(src, col, p.Requested, p)
	require.Error(t, e)
	c, e := s.Cursor(src)
	require.NoError(t, e)
	require.Empty(t, c.Stream)
	s.saveHook = nil
	_, e = s.Import(src, col, p.Requested, p)
	require.NoError(t, e)
	page, e := s.List(0, 50, func(Source) bool { return true })
	require.NoError(t, e)
	require.Len(t, page.Results, 4)
}
func TestEventImportConcurrentReplayIsIdempotent(t *testing.T) {
	s := open(t)
	p := eventPage(fmt.Sprintf("%032x", 1), 1, 3, hostagent.SHA(nil), hostagent.EventCursor{})
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := s.Import(src, col, p.Requested, p)
			if e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	page, e := s.List(0, 50, func(Source) bool { return true })
	require.NoError(t, e)
	require.Len(t, page.Results, 3)
}
func TestArchiveCrossesThousandReceiptsWithoutHotHistoryLimit(t *testing.T) {
	s := open(t)
	for i := 1; i <= 1005; i++ {
		r := Receipt{PlanID: "plan", Sequence: uint64(i), RunID: fmt.Sprintf("run-%d", i), OwnerID: "u", State: "succeeded", Run: json.RawMessage(`{"state":"succeeded"}`)}
		require.NoError(t, s.Archive(src, col, r))
		require.NoError(t, s.Archive(src, col, r))
	}
	require.Equal(t, uint64(1005), s.data.Total)
	seen := 0
	before := uint64(0)
	for {
		page, e := s.List(before, 100, func(Source) bool { return true })
		require.NoError(t, e)
		seen += len(page.Results)
		if page.NextBefore == 0 {
			break
		}
		before = page.NextBefore
	}
	require.Equal(t, 1005, seen)
	host, e := s.List(0, 10, func(Source) bool { return true }, "host")
	require.NoError(t, e)
	require.Empty(t, host.Results)
	receipts, e := s.List(0, 10, func(Source) bool { return true }, "collection")
	require.NoError(t, e)
	require.Len(t, receipts.Results, 10)
	_, e = s.List(0, 10, func(Source) bool { return true }, "unknown")
	require.ErrorIs(t, e, ErrInvalid)
	ctx, cancel := context.WithCancel(context.Background())
	s.BindOwner(ctx)
	cancel()
	require.ErrorIs(t, s.Archive(src, col, Receipt{}), ErrClosed)
}
func TestAgentEventsPostgresOrganizationIsolationAndRestart(t *testing.T) {
	url := os.Getenv("JMS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for agent event PostgreSQL integration")
	}
	docs, e := storage.OpenPostgres(context.Background(), url, "agent-events-test-"+time.Now().Format("150405.000000000"))
	require.NoError(t, e)
	defer docs.Close()
	scoped, e := docs.Scoped("org-qa")
	require.NoError(t, e)
	s, e := Open(t.TempDir(), make([]byte, 32), scoped)
	require.NoError(t, e)
	p := eventPage(fmt.Sprintf("%032x", 1), 1, 2, hostagent.SHA(nil), hostagent.EventCursor{})
	_, e = s.Import(src, col, p.Requested, p)
	require.NoError(t, e)
	s.Close()
	s, e = Open(t.TempDir(), make([]byte, 32), scoped)
	require.NoError(t, e)
	defer s.Close()
	c, e := s.Cursor(src)
	require.NoError(t, e)
	require.Equal(t, uint64(2), c.Sequence)
	alerts, e := s.NotificationFeed(context.Background(), "", time.Time{}, 100)
	require.NoError(t, e)
	require.Len(t, alerts.Events, 2)
	source, e := s.NotificationSource(alerts.Events[0].ResourceID)
	require.NoError(t, e)
	require.Equal(t, src, source.Source)
	other, e := Open(t.TempDir(), make([]byte, 32), docs)
	require.NoError(t, e)
	defer other.Close()
	c, e = other.Cursor(src)
	require.NoError(t, e)
	require.Empty(t, c.Stream)
	empty, e := other.NotificationFeed(context.Background(), "", time.Time{}, 100)
	require.NoError(t, e)
	require.Empty(t, empty.Events)
}

func TestReceiptCopiesMutablePayloads(t *testing.T) {
	s := open(t)
	r := Receipt{PlanID: "p", Sequence: 1, RunID: "run", OwnerID: "u", State: "succeeded", Run: json.RawMessage(`{"state":"succeeded"}`)}
	require.NoError(t, s.Archive(src, col, r))
	r.Run[0] = 'x'
	saved, ok := s.LatestReceipt("run")
	require.True(t, ok)
	require.True(t, json.Valid(saved.Run))
	saved.Run[0] = 'x'
	saved, ok = s.LatestReceipt("run")
	require.True(t, ok)
	require.True(t, json.Valid(saved.Run))
}
func TestAgentEventsStandaloneImportsIntoPostgresWithoutLosingCursor(t *testing.T) {
	url := os.Getenv("JMS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for agent history migration")
	}
	dir := t.TempDir()
	key := make([]byte, 32)
	s, e := Open(dir, key, nil)
	require.NoError(t, e)
	p := eventPage(fmt.Sprintf("%032x", 1), 1, 2, hostagent.SHA(nil), hostagent.EventCursor{})
	_, e = s.Import(src, col, p.Requested, p)
	require.NoError(t, e)
	s.Close()
	docs, e := storage.OpenPostgres(context.Background(), url, "agent-events-migrate-"+time.Now().Format("150405.000000000"))
	require.NoError(t, e)
	defer docs.Close()
	s, e = Open(dir, key, docs)
	require.NoError(t, e)
	defer s.Close()
	c, e := s.Cursor(src)
	require.NoError(t, e)
	require.Equal(t, uint64(2), c.Sequence)
	page, e := s.List(0, 50, func(Source) bool { return true })
	require.NoError(t, e)
	require.Len(t, page.Results, 2)
}
