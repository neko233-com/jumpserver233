package executionhistory

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

// ReadSummaries requires the producer's snapshot lock for a stable collection.
// Only one page is decrypted in memory; result bodies are never loaded.
func (s *Store) ReadSummaries(ctx context.Context, q Query, emit func(Record) error) error {
	if emit == nil {
		return ErrInvalid
	}
	owner := ""
	if q.Owner != "" {
		owner = s.tag("owner", q.Owner)
	}
	var after storage.HistoryCursor
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		rows, e := s.index.ScanHistory(ctx, storage.HistoryQuery{Kind: q.Kind, Owner: owner, Limit: 2000, Exclude: q.Exclude}, after)
		if e != nil {
			return historyError(e)
		}
		if len(rows) == 0 {
			return nil
		}
		for _, row := range rows {
			v, e := s.decode(row, false)
			if e != nil {
				return e
			}
			if q.Owner != "" && v.Owner != q.Owner {
				return ErrInvalid
			}
			if e = emit(v); e != nil {
				return e
			}
			after = storage.HistoryCursor{Created: row.Created, ID: row.ID}
		}
	}
}
