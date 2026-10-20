package storage

import (
	"context"
	"fmt"
	"strings"
)

type HistoryCursor struct {
	Created int64
	ID      string
}

// ScanHistory reads summaries with the indexed time/identity key. Producers
// hold their hot snapshot lock for the scan, so no same-kind retirement can
// shift the stream. This avoids a repeated COUNT and growing OFFSET prefix.
func (s *HistoryIndex) ScanHistory(ctx context.Context, q HistoryQuery, after HistoryCursor) ([]HistoryRow, error) {
	if !historyText(q.Kind, 32) || q.Owner != "" && len(q.Owner) != 64 || q.Limit < 1 || q.Limit > 2000 || len(q.Exclude) > 1000 || after.ID != "" && (!historyText(after.ID, 128) || after.Created <= 0) {
		return nil, ErrHistoryInvalid
	}
	args := []any{s.scope, q.Kind}
	where := "scope=$1 AND kind=$2"
	if q.Owner != "" {
		args = append(args, q.Owner)
		where += " AND owner_tag=$" + fmt.Sprint(len(args))
	}
	if len(q.Exclude) > 0 {
		holders := make([]string, 0, len(q.Exclude))
		for _, id := range q.Exclude {
			if !historyText(id, 128) {
				return nil, ErrHistoryInvalid
			}
			args = append(args, id)
			holders = append(holders, "$"+fmt.Sprint(len(args)))
		}
		where += " AND id NOT IN (" + strings.Join(holders, ",") + ")"
	}
	if after.ID != "" {
		args = append(args, after.Created, after.ID)
		timeArg := "$" + fmt.Sprint(len(args)-1)
		idArg := "$" + fmt.Sprint(len(args))
		where += " AND (created_ns<" + timeArg + " OR (created_ns=" + timeArg + " AND id<" + idArg + "))"
	}
	args = append(args, q.Limit)
	rows, e := s.db.QueryContext(ctx, "SELECT "+historyColumns+" FROM jms233_history_records WHERE "+where+" ORDER BY created_ns DESC,id DESC LIMIT $"+fmt.Sprint(len(args)), args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []HistoryRow{}
	for rows.Next() {
		v, e := scanHistory(rows, false)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
