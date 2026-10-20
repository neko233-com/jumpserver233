package executionhistory

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

// Verify validates every authenticated summary/body envelope, including
// archived output not touched by ordinary startup. It neither replays work nor
// establishes business semantics for unknown future payloads. Use offline with
// the installation lock; memory is bounded by one encrypted/decompressed row.
func (s *Store) Verify(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	return historyError(s.index.VerifyHistory(ctx, func(row storage.HistoryRow) error {
		summary, e := s.decode(row, false)
		if e != nil {
			return e
		}
		full, e := s.decode(row, true)
		if e != nil {
			return e
		}
		if summary.Owner != full.Owner || summary.RequestOwner != full.RequestOwner || summary.RequestID != full.RequestID {
			return ErrInvalid
		}
		return nil
	}))
}
