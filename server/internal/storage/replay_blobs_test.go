package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func replayDocuments(t *testing.T) *Documents {
	t.Helper()
	database := os.Getenv("JMS_TEST_DATABASE_URL")
	if database == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for encrypted replay blob PostgreSQL cases")
	}
	d, e := OpenPostgres(context.Background(), database, fmt.Sprintf("replay-blobs-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	t.Cleanup(func() { require.NoError(t, d.Close()) })
	return d
}
func blobDigest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func TestReplayStorageDatabaseChunkTransactionsIsolationAndIdempotency(t *testing.T) {
	root := replayDocuments(t)
	a, e := root.Scoped("replay-a")
	require.NoError(t, e)
	b, e := root.Scoped("replay-b")
	require.NoError(t, e)
	ctx := context.Background()
	key := "archive/session/cipher.enc"
	defer a.DeleteReplayBlob(ctx, key)
	defer b.DeleteReplayBlob(ctx, key)
	payload := bytes.Repeat([]byte{37}, 2*replayChunkBytes+317)
	hash := blobDigest(payload)
	var wg sync.WaitGroup
	results := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- a.PutReplayBlob(ctx, key, bytes.NewReader(payload), int64(len(payload)), hash)
		}()
	}
	wg.Wait()
	close(results)
	success, duplicates := 0, 0
	for e := range results {
		if e == nil {
			success++
		} else {
			assert.ErrorIs(t, e, ErrReplayBlobExists)
			duplicates++
		}
	}
	assert.Equal(t, 1, success)
	assert.Equal(t, 5, duplicates)
	read := func(d *Documents, expected []byte) {
		t.Helper()
		r, e := d.OpenReplayBlob(ctx, key)
		require.NoError(t, e)
		data, e := io.ReadAll(r)
		require.NoError(t, e)
		require.NoError(t, r.Close())
		assert.Equal(t, expected, data)
	}
	read(a, payload)
	_, e = b.OpenReplayBlob(ctx, key)
	assert.ErrorIs(t, e, ErrReplayBlobNotFound)
	_, e = root.OpenReplayBlob(ctx, key)
	assert.ErrorIs(t, e, ErrReplayBlobNotFound)
	other := []byte("another organization's encrypted replay")
	require.NoError(t, b.PutReplayBlob(ctx, key, bytes.NewReader(other), int64(len(other)), blobDigest(other)))
	read(a, payload)
	read(b, other)
	q, e := a.replayBlobKey(key)
	require.NoError(t, e)
	var chunks int
	require.NoError(t, root.db.QueryRowContext(ctx, `SELECT count(*) FROM jms233_replay_chunks WHERE namespace=$1 AND object_key=$2`, a.namespace, q).Scan(&chunks))
	assert.Equal(t, 3, chunks)
	require.NoError(t, a.DeleteReplayBlob(ctx, key))
	require.NoError(t, a.DeleteReplayBlob(ctx, key))
	_, e = a.OpenReplayBlob(ctx, key)
	assert.ErrorIs(t, e, ErrReplayBlobNotFound)
	read(b, other)
}
func TestReplayStorageDatabaseFailedDigestAndCanceledWritesLeaveNoPartialObject(t *testing.T) {
	d := replayDocuments(t)
	ctx := context.Background()
	key := "archive/atomic/cipher.enc"
	defer d.DeleteReplayBlob(ctx, key)
	data := []byte("encrypted fixture")
	require.ErrorIs(t, d.PutReplayBlob(ctx, key, bytes.NewReader(data), int64(len(data)), blobDigest([]byte("different"))), ErrReplayBlobIntegrity)
	_, e := d.OpenReplayBlob(ctx, key)
	assert.ErrorIs(t, e, ErrReplayBlobNotFound)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	assert.Error(t, d.PutReplayBlob(canceled, key, bytes.NewReader(data), int64(len(data)), blobDigest(data)))
	require.NoError(t, d.PutReplayBlob(ctx, key, bytes.NewReader(data), int64(len(data)), blobDigest(data)))
	r, e := d.OpenReplayBlob(ctx, key)
	require.NoError(t, e)
	require.NoError(t, r.Close())
	q, e := d.replayBlobKey(key)
	require.NoError(t, e)
	_, e = d.db.ExecContext(ctx, `DELETE FROM jms233_replay_chunks WHERE namespace=$1 AND object_key=$2 AND chunk_index=0`, d.namespace, q)
	require.NoError(t, e)
	r, e = d.OpenReplayBlob(ctx, key)
	require.NoError(t, e)
	defer r.Close()
	_, e = io.ReadAll(r)
	assert.ErrorIs(t, e, ErrReplayBlobIntegrity)
}
