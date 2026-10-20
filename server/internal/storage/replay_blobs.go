package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"regexp"
	"sync"
	"time"
)

var (
	ErrReplayBlobExists    = errors.New("replay blob exists")
	ErrReplayBlobNotFound  = errors.New("replay blob not found")
	ErrReplayBlobInvalid   = errors.New("invalid replay blob")
	ErrReplayBlobIntegrity = errors.New("replay blob integrity mismatch")
)

const maxReplayBlob int64 = 1 << 30
const replayChunkBytes = 1 << 20

var replayBlobDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

type replayBlobSchema struct {
	mu    sync.Mutex
	ready bool
}

func (d *Documents) EnsureReplayBlobs(ctx context.Context) error {
	if d == nil || d.db == nil {
		return ErrReplayBlobInvalid
	}
	if d.blobs != nil {
		d.blobs.mu.Lock()
		defer d.blobs.mu.Unlock()
		if d.blobs.ready {
			return nil
		}
	}
	tx, e := d.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 1))`, "jms233-replay-blobs-schema-v1"); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS jms233_replay_objects (
 namespace TEXT NOT NULL, object_key TEXT NOT NULL, size_bytes BIGINT NOT NULL CHECK(size_bytes > 0 AND size_bytes <= 1073741824), sha256 TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(namespace,object_key))`)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS jms233_replay_chunks (
 namespace TEXT NOT NULL, object_key TEXT NOT NULL, chunk_index INTEGER NOT NULL CHECK(chunk_index >= 0), body BYTEA NOT NULL CHECK(octet_length(body) <= 1048576),
 PRIMARY KEY(namespace,object_key,chunk_index), FOREIGN KEY(namespace,object_key) REFERENCES jms233_replay_objects(namespace,object_key) ON DELETE CASCADE)`)
	if e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	if d.blobs != nil {
		d.blobs.ready = true
	}
	return nil
}
func (d *Documents) replayBlobKey(key string) (string, error) {
	if d == nil || d.db == nil || len(key) < 1 || len(key) > 1024 {
		return "", ErrReplayBlobInvalid
	}
	h := sha256.Sum256([]byte("jms233/replay-object/v1\x00" + d.prefix + "\x00" + key))
	return "replay-" + hex.EncodeToString(h[:]), nil
}

// PutReplayBlob commits metadata and bounded ciphertext chunks in one transaction.
// A duplicate key never overwrites existing data, including after a lost response.
func (d *Documents) PutReplayBlob(ctx context.Context, key string, r io.Reader, size int64, digest string) error {
	qualified, e := d.replayBlobKey(key)
	if e != nil || r == nil || size < 1 || size > maxReplayBlob || !replayBlobDigest.MatchString(digest) {
		return ErrReplayBlobInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if e = d.EnsureReplayBlobs(ctx); e != nil {
		return e
	}
	tx, e := d.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	inserted, e := tx.ExecContext(ctx, `INSERT INTO jms233_replay_objects(namespace,object_key,size_bytes,sha256) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, d.namespace, qualified, size, digest)
	if e != nil {
		return e
	}
	n, e := inserted.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrReplayBlobExists
	}
	reader := io.LimitReader(r, size+1)
	buffer := make([]byte, replayChunkBytes)
	h := sha256.New()
	var total int64
	index := 0
	for {
		if e = ctx.Err(); e != nil {
			return e
		}
		n, re := io.ReadFull(reader, buffer)
		if n > 0 {
			total += int64(n)
			if total > size {
				return ErrReplayBlobIntegrity
			}
			_, _ = h.Write(buffer[:n])
			if _, e = tx.ExecContext(ctx, `INSERT INTO jms233_replay_chunks(namespace,object_key,chunk_index,body) VALUES($1,$2,$3,$4)`, d.namespace, qualified, index, buffer[:n]); e != nil {
				return e
			}
			index++
		}
		if re == io.EOF || re == io.ErrUnexpectedEOF {
			break
		}
		if re != nil {
			return re
		}
	}
	if total != size || hex.EncodeToString(h.Sum(nil)) != digest {
		return ErrReplayBlobIntegrity
	}
	return tx.Commit()
}

type replayBlobReader struct {
	reader *io.PipeReader
	cancel context.CancelFunc
}

func (r *replayBlobReader) Read(p []byte) (int, error) { return r.reader.Read(p) }
func (r *replayBlobReader) Close() error               { r.cancel(); return r.reader.Close() }
func (d *Documents) OpenReplayBlob(ctx context.Context, key string) (io.ReadCloser, error) {
	qualified, e := d.replayBlobKey(key)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	if e = d.EnsureReplayBlobs(ctx); e != nil {
		cancel()
		return nil, e
	}
	var size int64
	var expected string
	e = d.db.QueryRowContext(ctx, `SELECT size_bytes,sha256 FROM jms233_replay_objects WHERE namespace=$1 AND object_key=$2`, d.namespace, qualified).Scan(&size, &expected)
	if errors.Is(e, sql.ErrNoRows) {
		cancel()
		return nil, ErrReplayBlobNotFound
	}
	if e != nil {
		cancel()
		return nil, e
	}
	if size < 1 || size > maxReplayBlob || !replayBlobDigest.MatchString(expected) {
		cancel()
		return nil, ErrReplayBlobIntegrity
	}
	rows, e := d.db.QueryContext(ctx, `SELECT chunk_index,body FROM jms233_replay_chunks WHERE namespace=$1 AND object_key=$2 ORDER BY chunk_index`, d.namespace, qualified)
	if e != nil {
		cancel()
		return nil, e
	}
	reader, writer := io.Pipe()
	go func() {
		defer cancel()
		defer rows.Close()
		h := sha256.New()
		var total int64
		index := 0
		var result error
		for rows.Next() {
			var i int
			var b []byte
			if e := rows.Scan(&i, &b); e != nil {
				result = e
				break
			}
			if i != index || len(b) < 1 || len(b) > replayChunkBytes || total+int64(len(b)) > size {
				result = ErrReplayBlobIntegrity
				break
			}
			index++
			total += int64(len(b))
			_, _ = h.Write(b)
			if _, e := writer.Write(b); e != nil {
				result = e
				break
			}
		}
		if result == nil {
			result = rows.Err()
		}
		if result == nil && (total != size || hex.EncodeToString(h.Sum(nil)) != expected) {
			result = ErrReplayBlobIntegrity
		}
		_ = writer.CloseWithError(result)
	}()
	return &replayBlobReader{reader: reader, cancel: cancel}, nil
}

// DeleteReplayBlob is used only for explicitly owned object cleanup.
func (d *Documents) DeleteReplayBlob(ctx context.Context, key string) error {
	qualified, e := d.replayBlobKey(key)
	if e != nil {
		return e
	}
	if e = d.EnsureReplayBlobs(ctx); e != nil {
		return e
	}
	_, e = d.db.ExecContext(ctx, `DELETE FROM jms233_replay_objects WHERE namespace=$1 AND object_key=$2`, d.namespace, qualified)
	return e
}
