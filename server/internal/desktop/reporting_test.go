package desktop

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/reporting"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReportDesktopMetadataInterruptedAndCorruption(t *testing.T) {
	b, e := New(t.TempDir(), make([]byte, 32))
	require.NoError(t, e)
	id := strings.Repeat("a", 32)
	dir := filepath.Join(b.root, id)
	require.NoError(t, os.MkdirAll(dir, 0700))
	path := filepath.Join(dir, "index.json")
	raw := `{"session_id":"` + id + `","operator_id":"owner","started_at":"2026-01-02T01:00:00Z","status":"active","password":"synthetic-private"}`
	require.NoError(t, os.WriteFile(path, []byte(raw), 0600))
	var rows []reporting.Entry
	emit := func(v reporting.Entry) error { rows = append(rows, v); return nil }
	require.NoError(t, b.ReportMetadata(context.Background(), "other", false, emit))
	assert.Empty(t, rows)
	require.NoError(t, b.ReportMetadata(context.Background(), "owner", false, emit))
	require.Len(t, rows, 1)
	assert.Equal(t, "interrupted", rows[0].State)
	require.NoError(t, os.WriteFile(path, []byte("corrupt"), 0600))
	assert.ErrorIs(t, b.ReportMetadata(context.Background(), "owner", false, emit), reporting.ErrInvalid)
	require.NoError(t, os.WriteFile(path, []byte(strings.Repeat("x", (2<<20)+1)), 0600))
	assert.ErrorIs(t, b.ReportMetadata(context.Background(), "owner", false, emit), reporting.ErrLimit)
}
