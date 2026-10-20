package executionhistory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleRecord(id, owner, request string, at time.Time) Record {
	return Record{Kind: "job", ID: id, Owner: owner, RequestOwner: owner, RequestID: request, CreatedAt: at, Summary: json.RawMessage(`{"state":"succeeded"}`), Payload: json.RawMessage(`{"output":"confidential-history-output"}`)}
}

func TestEncryptedHistoryReopenImmutableIdentityAndReceipt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "execution-history.sqlite")
	key := bytes.Repeat([]byte{7}, 32)
	s, err := Open(path, key, nil)
	require.NoError(t, err)
	r := sampleRecord("job-001", "private-operator", "request-one", time.Now().UTC())
	require.NoError(t, s.Put(context.Background(), r))
	require.NoError(t, s.Put(context.Background(), r), "retry reuses immutable evidence")
	changed := r
	changed.Payload = json.RawMessage(`{"output":"changed"}`)
	assert.ErrorIs(t, s.Put(context.Background(), changed), ErrConflict)
	changed = r
	changed.ID = "job-002"
	assert.ErrorIs(t, s.Put(context.Background(), changed), ErrConflict, "same actor request cannot create another record")
	changed = r
	changed.ID = "job-003"
	changed.RequestOwner = "another-actor"
	require.NoError(t, s.Put(context.Background(), changed), "administrative trigger identity is separate from visibility owner")
	loaded, err := s.FindRequest(context.Background(), "job", r.RequestOwner, r.RequestID)
	require.NoError(t, err)
	assert.JSONEq(t, string(r.Payload), string(loaded.Payload))
	rows, total, err := s.Query(context.Background(), Query{Kind: "job", Owner: r.Owner, Limit: 10})
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	require.Len(t, rows, 2)
	assert.Empty(t, rows[0].Payload)
	rows, total, err = s.Query(context.Background(), Query{Kind: "job", Owner: "foreign", Limit: 10})
	require.NoError(t, err)
	assert.Zero(t, total)
	assert.Empty(t, rows)
	require.NoError(t, s.Close())
	require.NoError(t, s.Close())
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	for _, secret := range []string{"confidential-history-output", "private-operator", "request-one"} {
		assert.NotContains(t, string(raw), secret)
	}
	_, err = Open(path, bytes.Repeat([]byte{8}, 32), nil)
	require.Error(t, err)
	s, err = Open(path, key, nil)
	require.NoError(t, err)
	defer s.Close()
	loaded, err = s.Get(context.Background(), r.Kind, r.ID)
	require.NoError(t, err)
	assert.JSONEq(t, string(r.Payload), string(loaded.Payload))
	assert.Equal(t, int64(2), s.Health().Records)
}

func TestHistoryAuthenticatesIndexesBodyAndSummary(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "execution-history.sqlite"), make([]byte, 32), nil)
	require.NoError(t, err)
	defer s.Close()
	r := sampleRecord("job-one", "owner", "retry", time.Now().UTC())
	row, err := s.row(r)
	require.NoError(t, err)
	for _, full := range []bool{false, true} {
		_, err = s.decode(row, full)
		require.NoError(t, err)
		for _, field := range []string{"id", "kind", "owner", "receipt", "time", "ciphertext"} {
			t.Run(fmt.Sprintf("%v-%s", full, field), func(t *testing.T) {
				bad := row
				bad.Summary = bytes.Clone(row.Summary)
				bad.Body = bytes.Clone(row.Body)
				switch field {
				case "id":
					bad.ID = "job-swapped"
				case "kind":
					bad.Kind = "run"
				case "owner":
					bad.Owner = strings.Repeat("0", 64)
				case "receipt":
					bad.Receipt = strings.Repeat("1", 64)
				case "time":
					bad.Created++
				case "ciphertext":
					if full {
						bad.Body[len(bad.Body)-1] ^= 1
					} else {
						bad.Summary[len(bad.Summary)-1] ^= 1
					}
				}
				_, err := s.decode(bad, full)
				assert.ErrorIs(t, err, ErrInvalid)
			})
		}
	}
	bad := row
	bad.Digest = strings.Repeat("1", 64)
	_, err = s.decode(bad, true)
	assert.ErrorIs(t, err, ErrInvalid)
}

func TestHistoryPaginationAtomicBatchBoundsAndCancellation(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "execution-history.sqlite"), make([]byte, 32), nil)
	require.NoError(t, err)
	defer s.Close()
	at := time.Now().UTC()
	for base := 0; base < 2048; base += 64 {
		batch := make([]Record, 0, 64)
		for n := base; n < base+64; n++ {
			owner := "a"
			if n%2 != 0 {
				owner = "b"
			}
			batch = append(batch, sampleRecord(fmt.Sprintf("job-%05d", n), owner, fmt.Sprintf("request-%d", n), at.Add(time.Duration(n)*time.Nanosecond)))
		}
		require.NoError(t, s.Put(context.Background(), batch...))
	}
	rows, total, err := s.Query(context.Background(), Query{Kind: "job", Owner: "a", Offset: 999, Limit: 20, Exclude: []string{"job-00000"}})
	require.NoError(t, err)
	assert.Equal(t, 1023, total)
	require.Len(t, rows, 20)
	assert.Equal(t, "job-00048", rows[0].ID)
	existing := sampleRecord("job-00000", "a", "request-0", at)
	fresh := sampleRecord("job-uncommitted", "a", "fresh", at)
	existing.Payload = json.RawMessage(`{"changed":true}`)
	assert.ErrorIs(t, s.Put(context.Background(), fresh, existing), ErrConflict)
	_, err = s.Get(context.Background(), "job", fresh.ID)
	assert.ErrorIs(t, err, ErrNotFound, "batch must roll back on a later conflict")
	bad := fresh
	bad.Summary = json.RawMessage(`invalid`)
	assert.ErrorIs(t, s.Put(context.Background(), bad), ErrInvalid)
	bad = fresh
	bad.RequestOwner = ""
	assert.ErrorIs(t, s.Put(context.Background(), bad), ErrInvalid)
	bad = fresh
	bad.Payload = append(json.RawMessage(`"`), []byte(strings.Repeat("x", MaxPayload))...)
	bad.Payload = append(bad.Payload, '"')
	assert.ErrorIs(t, s.Put(context.Background(), bad), ErrInvalid)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.Error(t, s.Put(ctx, fresh))
	_, _, err = s.Query(context.Background(), Query{Kind: "job", Limit: 2001})
	assert.Error(t, err)
}

func TestPostgresHistoryOrganizationScopesAndTakeover(t *testing.T) {
	dsn := os.Getenv("JMS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for PostgreSQL history")
	}
	docs, err := storage.OpenPostgres(context.Background(), dsn, fmt.Sprintf("history-%d", time.Now().UnixNano()))
	require.NoError(t, err)
	defer docs.Close()
	a, err := docs.Scoped("organization-a")
	require.NoError(t, err)
	b, err := docs.Scoped("organization-b")
	require.NoError(t, err)
	key := bytes.Repeat([]byte{9}, 32)
	s, err := Open("unused", key, a)
	require.NoError(t, err)
	defer s.Close()
	r := sampleRecord("job-shared-id", "owner", "same-request", time.Now().UTC())
	require.NoError(t, s.Put(context.Background(), r))
	peer, err := Open("unused", key, a)
	require.NoError(t, err)
	defer peer.Close()
	loaded, err := peer.FindRequest(context.Background(), "job", "owner", "same-request")
	require.NoError(t, err)
	assert.Equal(t, r.ID, loaded.ID)
	other, err := Open("unused", key, b)
	require.NoError(t, err)
	defer other.Close()
	_, err = other.Get(context.Background(), "job", r.ID)
	assert.ErrorIs(t, err, ErrNotFound)
	require.NoError(t, other.Put(context.Background(), r))
}
