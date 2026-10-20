package storage

import "context"

// VerifyHistory walks one row at a time during offline preflight. Visitors must
// not query this index: the local database deliberately owns only one connection.
// Native startup owns the data-directory lock, so no live writer can race it.
func (s *HistoryIndex) VerifyHistory(ctx context.Context, record func(HistoryRow) error) error {
	if record == nil {
		return ErrHistoryInvalid
	}
	// Check lengths inside SQL before materializing ciphertext from a damaged
	// database; a normal row is bounded by the same limits as Put.
	projection := "kind,id,owner_tag,receipt_tag,digest,created_ns,CASE WHEN length(summary)<=1048576 THEN summary ELSE NULL END,CASE WHEN length(body)<=20971520 THEN body ELSE NULL END"
	rows, e := s.db.QueryContext(ctx, "SELECT "+projection+" FROM jms233_history_records WHERE scope=$1 ORDER BY kind,id", s.scope)
	if e != nil {
		return e
	}
	for rows.Next() {
		if e = ctx.Err(); e != nil {
			rows.Close()
			return e
		}
		row, err := scanHistory(rows, true)
		if err != nil {
			rows.Close()
			return err
		}
		if !validHistoryRow(row) {
			rows.Close()
			return ErrHistoryInvalid
		}
		if e = record(row); e != nil {
			rows.Close()
			return e
		}
	}
	e = rows.Err()
	rows.Close()
	return e
}
