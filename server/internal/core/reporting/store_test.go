package reporting

import (
	"context"
	"errors"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testReport(t *testing.T) Report {
	t.Helper()
	r, e := Build(context.Background(), testQuery(), []Source{source("ssh_jobs", nil)}, time.Now())
	require.NoError(t, e)
	return r
}
func TestEncryptedLedgerCommitFailureRestartAndScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.json")
	s, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	defer s.Close()
	r := testReport(t)
	receipt, e := s.Commit("synthetic-user", r, []byte("synthetic aggregate CSV"))
	require.NoError(t, e)
	s.saveHook = func([]byte) error { return errors.New("synthetic disk fault") }
	_, e = s.Commit("synthetic-user", r, []byte("not committed"))
	require.Error(t, e)
	rows, total, e := s.List("synthetic-user", false, 0, 100)
	require.NoError(t, e)
	assert.Equal(t, 1, total)
	require.Len(t, rows, 1)
	rows[0].Sources[0].ID = "changed"
	peer, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	defer peer.Close()
	rows, total, e = peer.List("synthetic-user", false, 0, 100)
	require.NoError(t, e)
	assert.Equal(t, receipt.ID, rows[0].ID)
	assert.Equal(t, "ssh_jobs", rows[0].Sources[0].ID)
	_, total, e = peer.List("other", false, 0, 100)
	require.NoError(t, e)
	assert.Zero(t, total)
	_, total, e = peer.List("other", true, 0, 100)
	require.NoError(t, e)
	assert.Equal(t, 1, total)
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "synthetic-user")
	assert.NotContains(t, string(raw), "synthetic aggregate")
	_, e = Open(path, []byte(strings.Repeat("x", 32)), nil)
	require.Error(t, e)
	peer.Close()
	_, e = peer.Commit("synthetic-user", r, []byte("closed"))
	assert.ErrorIs(t, e, ErrClosed)
}
func TestConcurrentLedgerAndPostgresTakeoverIsolation(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "ledger.json"), make([]byte, 32), nil)
	require.NoError(t, e)
	defer s.Close()
	r := testReport(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := s.Commit("synthetic-user", r, []byte("CSV")); assert.NoError(t, e) }()
	}
	wg.Wait()
	_, n, e := s.List("synthetic-user", false, 0, 100)
	require.NoError(t, e)
	assert.Equal(t, 8, n)
	dsn := os.Getenv("JMS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for report ledger takeover")
	}
	docs, e := storage.OpenPostgres(context.Background(), dsn, fmt.Sprintf("reports-test-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	defer docs.Close()
	orgA, e := docs.Scoped("organization-a")
	require.NoError(t, e)
	orgB, e := docs.Scoped("organization-b")
	require.NoError(t, e)
	a, e := Open(filepath.Join(t.TempDir(), "a.json"), make([]byte, 32), orgA)
	require.NoError(t, e)
	_, e = a.Commit("synthetic-user", r, []byte("CSV"))
	require.NoError(t, e)
	a.Close()
	takeover, e := Open(filepath.Join(t.TempDir(), "a.json"), make([]byte, 32), orgA)
	require.NoError(t, e)
	defer takeover.Close()
	_, n, e = takeover.List("synthetic-user", false, 0, 100)
	require.NoError(t, e)
	assert.Equal(t, 1, n)
	b, e := Open(filepath.Join(t.TempDir(), "b.json"), make([]byte, 32), orgB)
	require.NoError(t, e)
	defer b.Close()
	_, n, e = b.List("synthetic-user", true, 0, 100)
	require.NoError(t, e)
	assert.Zero(t, n)
}

func TestReportLedgerEvictsExpiredAndByteBudgetAndRejectsCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.json")
	s, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	r := testReport(t)
	r.Sources = nil
	for i := range MaxSources {
		id := fmt.Sprintf("source_%02d_%s", i, strings.Repeat("x", 35))
		r.Sources = append(r.Sources, Stats{ID: id, Scope: "platform_all", Status: "ok"})
		r.Query.Sources = append(r.Query.Sources, id)
	}
	seed, e := s.Commit("synthetic-owner", r, []byte("CSV"))
	require.NoError(t, e)
	s.data.Receipts = nil
	for i := range MaxReceipts {
		v := cloneReceipt(seed)
		v.ID = fmt.Sprintf("report-export-%032x", i)
		if i == 0 {
			v.At = time.Now().Add(-366 * 24 * time.Hour)
		}
		s.data.Receipts = append(s.data.Receipts, v)
	}
	newest, e := s.Commit("synthetic-owner", r, []byte("CSV"))
	require.NoError(t, e)
	rows, total, e := s.List("synthetic-owner", false, 0, 100)
	require.NoError(t, e)
	assert.Less(t, total, MaxReceipts)
	assert.Equal(t, newest.ID, rows[0].ID)
	reopened, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	reopened.Close()
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	raw[len(raw)/2] ^= 1
	require.NoError(t, os.WriteFile(path, raw, 0600))
	_, e = Open(path, make([]byte, 32), nil)
	require.Error(t, e)
	s.Close()
}
