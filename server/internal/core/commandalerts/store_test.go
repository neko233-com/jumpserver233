package commandalerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func alertRecord(id string) Record {
	return Record{ID: id, SessionID: "session-1", AssetID: "asset-1", AssetName: "Synthetic host", Account: "ops", OwnerID: "owner-1", ActorID: "sharer-1", Actor: "Synthetic sharer", State: "command_denied", Rule: "Synthetic policy", At: time.Now().UTC()}
}
func TestAlertEncryptedReloadIdempotencyAndCommitFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.json")
	key := make([]byte, 32)
	s, e := Open(path, key, nil)
	require.NoError(t, e)
	record := alertRecord("command-event-a")
	require.NoError(t, s.Publish(record))
	require.NoError(t, s.Publish(record))
	conflict := record
	conflict.State = "command_input_blocked"
	require.ErrorIs(t, s.Publish(conflict), ErrInvalid)
	before, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.NotContains(t, string(before), record.AssetName)
	broken := errors.New("synthetic commit failure")
	s.saveHook = func([]byte) error { return broken }
	require.ErrorIs(t, s.Publish(alertRecord("command-event-b")), broken)
	_, e = s.Get("command-event-b")
	require.ErrorIs(t, e, ErrNotFound)
	after, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.Equal(t, before, after)
	batch, e := s.NotificationFeed(context.Background(), "", time.Time{}, 100)
	require.NoError(t, e)
	require.Len(t, batch.Events, 1)
	assert.Equal(t, "sharer-1", batch.Events[0].ActorID)
	s.Close()
	require.ErrorIs(t, s.Publish(record), ErrClosed)
	peer, e := Open(path, key, nil)
	require.NoError(t, e)
	defer peer.Close()
	got, e := peer.Get(record.ID)
	require.NoError(t, e)
	assert.Equal(t, record, got)
	_, e = Open(path, bytesKey(1), nil)
	require.ErrorIs(t, e, ErrInvalid)
}
func bytesKey(v byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = v
	}
	return b
}
func TestAlertValidationRetentionAndGap(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "alerts.json"), make([]byte, 32), nil)
	require.NoError(t, e)
	defer s.Close()
	for _, mutate := range []func(*Record){func(r *Record) { r.ID = "../x" }, func(r *Record) { r.State = "allowed" }, func(r *Record) { r.AssetName = "bad\nlabel" }, func(r *Record) { r.At = time.Time{} }, func(r *Record) { r.ActorID = "" }} {
		r := alertRecord("invalid")
		mutate(&r)
		require.ErrorIs(t, s.Publish(r), ErrInvalid)
	}
	old := alertRecord("old")
	old.At = time.Now().UTC().Add(-31 * 24 * time.Hour)
	require.NoError(t, s.Publish(old))
	require.NoError(t, s.Publish(alertRecord("new")))
	_, e = s.Get("old")
	require.ErrorIs(t, e, ErrNotFound)
	batch, e := s.NotificationFeed(context.Background(), eventfeed.Digest(old.ID), time.Time{}, 1)
	require.NoError(t, e)
	assert.True(t, batch.Gap)
	require.Len(t, batch.Events, 1)
	assert.Equal(t, "new", batch.Events[0].ResourceID)
	idle, e := s.NotificationFeed(context.Background(), batch.Cursor, time.Time{}, 1)
	require.NoError(t, e)
	assert.Empty(t, idle.Events)
	assert.Equal(t, batch.Cursor, idle.Cursor)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = s.NotificationFeed(ctx, "", time.Time{}, 1)
	require.ErrorIs(t, e, context.Canceled)
	raw, e := json.Marshal(batch.Events)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "command text")
}
func TestAlertPostgresTakeoverAndOrganizationIsolation(t *testing.T) {
	url := os.Getenv("JMS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for command alert takeover")
	}
	docs, e := storage.OpenPostgres(context.Background(), url, "command-alert-"+fmt.Sprint(time.Now().UnixNano()))
	require.NoError(t, e)
	defer docs.Close()
	scoped, e := docs.Scoped("org-security")
	require.NoError(t, e)
	s, e := Open(filepath.Join(t.TempDir(), "a"), make([]byte, 32), scoped)
	require.NoError(t, e)
	r := alertRecord("command-event-pg")
	require.NoError(t, s.Publish(r))
	s.Close()
	peer, e := Open(filepath.Join(t.TempDir(), "b"), make([]byte, 32), scoped)
	require.NoError(t, e)
	defer peer.Close()
	got, e := peer.Get(r.ID)
	require.NoError(t, e)
	assert.Equal(t, r, got)
	other, e := Open(filepath.Join(t.TempDir(), "c"), make([]byte, 32), docs)
	require.NoError(t, e)
	defer other.Close()
	_, e = other.Get(r.ID)
	require.ErrorIs(t, e, ErrNotFound)
}
func BenchmarkAlertIdleTwentyThousand(b *testing.B) {
	s, e := Open(filepath.Join(b.TempDir(), "a"), make([]byte, 32), nil)
	if e != nil {
		b.Fatal(e)
	}
	defer s.Close()
	for i := range MaxRecords {
		s.data.Records = append(s.data.Records, alertRecord(fmt.Sprint(i)))
	}
	anchor := eventfeed.Digest(s.data.Records[MaxRecords-1].ID)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, e := s.NotificationFeed(context.Background(), anchor, time.Time{}, 64); e != nil {
			b.Fatal(e)
		}
	}
}
