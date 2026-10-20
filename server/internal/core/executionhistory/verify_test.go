package executionhistory

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"modernc.org/sqlite"
)

func TestHistoryFutureSQLiteVersionCannotBeRewrittenOnOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.sqlite")
	s, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	require.NoError(t, s.Close())
	db := openRawHistory(t, path)
	_, e = db.Exec("PRAGMA user_version=2")
	require.NoError(t, e)
	require.NoError(t, db.Close())
	before, e := os.ReadFile(path)
	require.NoError(t, e)
	_, e = Open(path, make([]byte, 32), nil)
	require.Error(t, e)
	after, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.Equal(t, before, after)
}

func openRawHistory(t *testing.T, path string) *sql.DB {
	t.Helper()
	p := filepath.ToSlash(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	uri := url.URL{Scheme: "file", Path: p}
	connector, e := sqlite.NewConnector(uri.String())
	require.NoError(t, e)
	db := sql.OpenDB(connector)
	t.Cleanup(func() { _ = db.Close() })
	return db
}
func TestOfflineHistoryVerificationReadsUnlistedBodiesAndSummaries(t *testing.T) {
	for _, field := range []string{"body", "summary", "oversized-body", "future-packed"} {
		t.Run(field, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "history.sqlite")
			s, e := Open(path, make([]byte, 32), nil)
			require.NoError(t, e)
			defer s.Close()
			ctx := t.Context()
			at := time.Now().UTC()
			require.NoError(t, s.Put(ctx, sampleRecord("old-job", "owner", "request-one", at)))
			require.NoError(t, s.Verify(ctx))
			db := openRawHistory(t, path)
			switch field {
			case "body", "summary":
				_, e = db.Exec("UPDATE jms233_history_records SET " + field + "=zeroblob(64) WHERE id='old-job'")
			case "oversized-body":
				_, e = db.Exec("UPDATE jms233_history_records SET body=zeroblob(20971521) WHERE id='old-job'")
			case "future-packed":
				row, e := s.row(sampleRecord("old-job", "owner", "request-one", at))
				require.NoError(t, e)
				plain, e := s.open(row.Body, "job/old-job/body")
				require.NoError(t, e)
				require.Contains(t, string(plain), `"version":1`)
				plain = []byte(strings.Replace(string(plain), `"version":1`, `"version":999`, 1))
				sealed, e := s.seal(plain, "job/old-job/body")
				require.NoError(t, e)
				_, e = db.Exec("UPDATE jms233_history_records SET body=$1,digest=$2 WHERE id='old-job'", sealed, s.tag("record", string(plain)))
				require.NoError(t, e)
			}
			require.NoError(t, e)
			assert.ErrorIs(t, s.Verify(ctx), ErrInvalid)
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s, e := Open(filepath.Join(t.TempDir(), "empty.sqlite"), make([]byte, 32), nil)
	require.NoError(t, e)
	defer s.Close()
	assert.ErrorIs(t, s.Verify(ctx), context.Canceled)
}
