package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"

	"github.com/neko233-com/jumpserver233/server/internal/core/executionhistory"
	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
)

// checkHistory runs only behind the standalone OS data lock, before listeners
// and workers. Include disabled/archived organizations: their data must survive
// an upgrade even though no live organization runtime is initialized for them.
func (r *organizationRuntimes) checkHistory(ctx context.Context) error {
	for _, org := range r.store.List(true) {
		if e := ctx.Err(); e != nil {
			return e
		}
		path := filepath.Join(r.cfg.DataDir, "execution-history.sqlite")
		key := r.key
		if org.ID != organizations.DefaultID {
			path = filepath.Join(r.cfg.DataDir, "organizations", org.ID, "execution-history.sqlite")
			mac := hmac.New(sha256.New, r.key)
			mac.Write([]byte("jms233/organization-vault/v1\x00" + org.ID))
			key = mac.Sum(nil)
		}
		if _, e := os.Lstat(path); errors.Is(e, os.ErrNotExist) {
			for _, suffix := range []string{"-wal", "-shm"} {
				if _, sideErr := os.Lstat(path + suffix); sideErr == nil || !errors.Is(sideErr, os.ErrNotExist) {
					return executionhistory.ErrInvalid
				}
			}
			continue
		} else if e != nil {
			return executionhistory.ErrUnavailable
		}
		store, e := executionhistory.Open(path, key, nil)
		if e != nil {
			return e
		}
		e = store.Verify(ctx)
		closeErr := store.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return executionhistory.ErrUnavailable
		}
	}
	return nil
}
