package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"modernc.org/sqlite"
)

var ErrHistoryConflict = errors.New("history identity conflicts")
var ErrHistoryMissing = errors.New("history record not found")
var ErrHistoryInvalid = errors.New("invalid history index")
var ErrHistoryUnavailable = errors.New("history index unavailable")

// HistoryRow carries opaque authenticated ciphertext. Only indexed times and
// one-way owner/receipt tags are visible to the persistence adapter.
type HistoryRow struct {
	Kind, ID, Owner, Receipt, Digest string
	Created                          int64
	Summary, Body                    []byte
}
type HistoryQuery struct {
	Kind, Owner   string
	Offset, Limit int
	Exclude       []string
}
type HistoryStats struct{ Records, Bytes int64 }
type HistoryIndex struct {
	db    *sql.DB
	scope string
	local bool
}

func OpenLocalHistory(ctx context.Context, path string) (*HistoryIndex, error) {
	if !filepath.IsAbs(path) {
		var e error
		path, e = filepath.Abs(path)
		if e != nil {
			return nil, e
		}
	}
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	existing := false
	if st, e := os.Lstat(path); e == nil {
		if !st.Mode().IsRegular() {
			return nil, ErrHistoryInvalid
		}
		existing = st.Size() > 0
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	// An orphan WAL may contain the only committed copy of recent history.
	// Never initialize a new database over it or follow a sidecar symlink.
	for _, suffix := range []string{"-wal", "-shm"} {
		if st, e := os.Lstat(path + suffix); e == nil {
			if !existing || !st.Mode().IsRegular() {
				return nil, ErrHistoryInvalid
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
	}
	uriPath := filepath.ToSlash(path)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	uri := url.URL{Scheme: "file", Path: uriPath}
	values := url.Values{}
	values.Add("_pragma", "busy_timeout(5000)")
	values.Add("_pragma", "foreign_keys(ON)")
	values.Add("_pragma", "synchronous(FULL)")
	values.Add("_pragma", "secure_delete(ON)")
	uri.RawQuery = values.Encode()
	connector, e := sqlite.NewConnector(uri.String())
	if e != nil {
		return nil, ErrHistoryInvalid
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	fail := func(err error) (*HistoryIndex, error) { _ = db.Close(); return nil, err }
	var applicationID int
	if e = db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&applicationID); e != nil {
		return fail(ErrHistoryInvalid)
	}
	if existing && applicationID != 0x4a4d5333 {
		return fail(ErrHistoryInvalid)
	}
	var version int
	if e = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); e != nil {
		return fail(e)
	}
	if existing && version != 1 {
		return fail(ErrHistoryInvalid)
	}
	if !existing {
		if _, e = db.ExecContext(ctx, "PRAGMA application_id=1246581555"); e != nil {
			return fail(e)
		}
		if _, e = db.ExecContext(ctx, "PRAGMA user_version=1"); e != nil {
			return fail(e)
		}
	}
	index := &HistoryIndex{db: db, scope: "local", local: true}
	if e = index.initialize(ctx, false); e != nil {
		return fail(e)
	}
	if _, e = db.ExecContext(ctx, "PRAGMA journal_mode=WAL"); e != nil {
		return fail(e)
	}
	if e = os.Chmod(path, 0600); e != nil {
		return fail(e)
	}
	return index, nil
}

func (d *Documents) OpenHistory(ctx context.Context) (*HistoryIndex, error) {
	if d == nil || d.db == nil {
		return nil, ErrHistoryInvalid
	}
	h := sha256.Sum256([]byte("jms233/history-scope/v1\x00" + d.namespace + "\x00" + d.prefix))
	index := &HistoryIndex{db: d.db, scope: hex.EncodeToString(h[:])}
	if e := index.initialize(ctx, true); e != nil {
		return nil, e
	}
	return index, nil
}
func (s *HistoryIndex) initialize(ctx context.Context, postgres bool) error {
	binaryType := "BLOB"
	if postgres {
		binaryType = "BYTEA"
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if postgres {
		if _, e = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,1))", "jms233-history-schema-v1"); e != nil {
			return e
		}
	}
	for _, statement := range []string{
		"CREATE TABLE IF NOT EXISTS jms233_history_meta(scope TEXT PRIMARY KEY,format INTEGER NOT NULL,proof " + binaryType + " NOT NULL)",
		"CREATE TABLE IF NOT EXISTS jms233_history_records(scope TEXT NOT NULL,kind TEXT NOT NULL,id TEXT NOT NULL,owner_tag TEXT NOT NULL,receipt_tag TEXT,digest TEXT NOT NULL,created_ns BIGINT NOT NULL,summary " + binaryType + " NOT NULL,body " + binaryType + " NOT NULL,PRIMARY KEY(scope,kind,id))",
		"CREATE UNIQUE INDEX IF NOT EXISTS jms233_history_receipts ON jms233_history_records(scope,kind,receipt_tag) WHERE receipt_tag IS NOT NULL",
		"CREATE INDEX IF NOT EXISTS jms233_history_owner_time ON jms233_history_records(scope,kind,owner_tag,created_ns DESC,id DESC)",
		"CREATE INDEX IF NOT EXISTS jms233_history_time ON jms233_history_records(scope,kind,created_ns DESC,id DESC)",
	} {
		if _, e = tx.ExecContext(ctx, statement); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *HistoryIndex) Meta(ctx context.Context) (int, []byte, error) {
	var version int
	var proof []byte
	e := s.db.QueryRowContext(ctx, "SELECT format,proof FROM jms233_history_meta WHERE scope=$1", s.scope).Scan(&version, &proof)
	if errors.Is(e, sql.ErrNoRows) {
		e = ErrHistoryMissing
	}
	return version, proof, e
}
func (s *HistoryIndex) CreateMeta(ctx context.Context, version int, proof []byte) error {
	if version != 1 || len(proof) < 16 || len(proof) > 1024 {
		return ErrHistoryInvalid
	}
	_, e := s.db.ExecContext(ctx, "INSERT INTO jms233_history_meta(scope,format,proof) VALUES($1,$2,$3) ON CONFLICT(scope) DO NOTHING", s.scope, version, proof)
	return e
}
func validHistoryRow(r HistoryRow) bool {
	return historyText(r.Kind, 32) && historyText(r.ID, 128) && len(r.Owner) == 64 && (r.Receipt == "" || len(r.Receipt) == 64) && len(r.Digest) == 64 && r.Created > 0 && len(r.Summary) > 0 && len(r.Summary) <= 1<<20 && len(r.Body) > 0 && len(r.Body) <= 20<<20
}
func historyText(v string, max int) bool {
	if v == "" || len(v) > max {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
func (s *HistoryIndex) Put(ctx context.Context, rows []HistoryRow) error {
	if len(rows) == 0 || len(rows) > 64 {
		return ErrHistoryInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for _, r := range rows {
		if !validHistoryRow(r) {
			return ErrHistoryInvalid
		}
		var receipt any
		if r.Receipt != "" {
			receipt = r.Receipt
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO jms233_history_records(scope,kind,id,owner_tag,receipt_tag,digest,created_ns,summary,body) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(scope,kind,id) DO NOTHING", s.scope, r.Kind, r.ID, r.Owner, receipt, r.Digest, r.Created, r.Summary, r.Body); e != nil {
			var local *sqlite.Error
			var state interface{ SQLState() string }
			if errors.As(e, &local) && (local.Code() == 1555 || local.Code() == 2067) || errors.As(e, &state) && state.SQLState() == "23505" {
				return ErrHistoryConflict
			}
			return ErrHistoryUnavailable
		}
		var digest, owner string
		var created int64
		var storedReceipt sql.NullString
		if e = tx.QueryRowContext(ctx, "SELECT digest,owner_tag,receipt_tag,created_ns FROM jms233_history_records WHERE scope=$1 AND kind=$2 AND id=$3", s.scope, r.Kind, r.ID).Scan(&digest, &owner, &storedReceipt, &created); e != nil {
			return e
		}
		if digest != r.Digest || owner != r.Owner || storedReceipt.String != r.Receipt || created != r.Created {
			return ErrHistoryConflict
		}
	}
	return tx.Commit()
}
func scanHistory(row interface{ Scan(...any) error }, body bool) (HistoryRow, error) {
	var r HistoryRow
	var receipt sql.NullString
	var e error
	if body {
		e = row.Scan(&r.Kind, &r.ID, &r.Owner, &receipt, &r.Digest, &r.Created, &r.Summary, &r.Body)
	} else {
		e = row.Scan(&r.Kind, &r.ID, &r.Owner, &receipt, &r.Digest, &r.Created, &r.Summary)
	}
	r.Receipt = receipt.String
	if errors.Is(e, sql.ErrNoRows) {
		e = ErrHistoryMissing
	}
	return r, e
}

const historyColumns = "kind,id,owner_tag,receipt_tag,digest,created_ns,summary"

func (s *HistoryIndex) Get(ctx context.Context, kind, id string) (HistoryRow, error) {
	if !historyText(kind, 32) || !historyText(id, 128) {
		return HistoryRow{}, ErrHistoryInvalid
	}
	return scanHistory(s.db.QueryRowContext(ctx, "SELECT "+historyColumns+",body FROM jms233_history_records WHERE scope=$1 AND kind=$2 AND id=$3", s.scope, kind, id), true)
}
func (s *HistoryIndex) FindReceipt(ctx context.Context, kind, receipt string) (HistoryRow, error) {
	if !historyText(kind, 32) || len(receipt) != 64 {
		return HistoryRow{}, ErrHistoryInvalid
	}
	return scanHistory(s.db.QueryRowContext(ctx, "SELECT "+historyColumns+",body FROM jms233_history_records WHERE scope=$1 AND kind=$2 AND receipt_tag=$3", s.scope, kind, receipt), true)
}
func (s *HistoryIndex) Query(ctx context.Context, q HistoryQuery) ([]HistoryRow, int, error) {
	if !historyText(q.Kind, 32) || q.Owner != "" && len(q.Owner) != 64 || q.Offset < 0 || q.Limit < 1 || q.Limit > 2000 || len(q.Exclude) > 1000 {
		return nil, 0, ErrHistoryInvalid
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
				return nil, 0, ErrHistoryInvalid
			}
			args = append(args, id)
			holders = append(holders, "$"+fmt.Sprint(len(args)))
		}
		where += " AND id NOT IN (" + strings.Join(holders, ",") + ")"
	}
	var count int
	if e := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM jms233_history_records WHERE "+where, args...).Scan(&count); e != nil {
		return nil, 0, e
	}
	args = append(args, q.Limit, q.Offset)
	query := "SELECT " + historyColumns + " FROM jms233_history_records WHERE " + where + " ORDER BY created_ns DESC,id DESC LIMIT $" + fmt.Sprint(len(args)-1) + " OFFSET $" + fmt.Sprint(len(args))
	rows, e := s.db.QueryContext(ctx, query, args...)
	if e != nil {
		return nil, 0, e
	}
	defer rows.Close()
	out := []HistoryRow{}
	for rows.Next() {
		r, e := scanHistory(rows, false)
		if e != nil {
			return nil, 0, e
		}
		out = append(out, r)
	}
	return out, count, rows.Err()
}
func (s *HistoryIndex) Stats(ctx context.Context) (HistoryStats, error) {
	var v HistoryStats
	e := s.db.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(length(summary)+length(body)),0) FROM jms233_history_records WHERE scope=$1", s.scope).Scan(&v.Records, &v.Bytes)
	return v, e
}
func (s *HistoryIndex) Close() error {
	if !s.local {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	return s.db.Close()
}
