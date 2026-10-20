package replaystore

import (
	"context"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"io"
)

type Database struct{ docs *storage.Documents }

func NewDatabase(docs *storage.Documents) (*Database, error) {
	if docs == nil {
		return nil, ErrInvalid
	}
	return &Database{docs: docs}, nil
}
func (d *Database) Put(ctx context.Context, key string, r io.Reader, size int64, digest string) error {
	if !ValidKey(key) || size < 1 || size > MaxObjectBytes || !ValidDigest(digest) {
		return ErrInvalid
	}
	e := d.docs.PutReplayBlob(ctx, key, r, size, digest)
	switch {
	case errors.Is(e, storage.ErrReplayBlobExists):
		return ErrExists
	case errors.Is(e, storage.ErrReplayBlobIntegrity):
		return ErrIntegrity
	case e != nil:
		return ErrUnavailable
	}
	return nil
}
func (d *Database) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	if !ValidKey(key) {
		return nil, ErrInvalid
	}
	r, e := d.docs.OpenReplayBlob(ctx, key)
	if errors.Is(e, storage.ErrReplayBlobNotFound) {
		return nil, ErrNotFound
	}
	if e != nil {
		return nil, ErrUnavailable
	}
	return r, nil
}
func (d *Database) Close() error { return nil }
