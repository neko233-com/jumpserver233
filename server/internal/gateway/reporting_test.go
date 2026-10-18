package gateway

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

func TestReportSessionLifecycleOwnershipCorruptionAndBound(t *testing.T) {
	b := NewBroker(t.TempDir(), make([]byte, 32), nil)
	require.NoError(t, os.MkdirAll(filepath.Dir(b.auditPath), 0700))
	id := strings.Repeat("a", 32)
	other := strings.Repeat("b", 32)
	raw := `{"session_id":"` + id + `","operator_id":"owner","event":"started","at":"2026-01-02T01:00:00Z","command":"synthetic-private"}` + "\n" + `{"session_id":"` + id + `","event":"ended","at":"2026-01-02T02:00:00Z"}` + "\n" + `{"session_id":"` + other + `","operator_id":"other","event":"started","at":"2026-01-02T03:00:00Z"}` + "\n"
	require.NoError(t, os.WriteFile(b.auditPath, []byte(raw), 0600))
	var rows []reporting.Entry
	emit := func(v reporting.Entry) error {
		unlocked := b.auditMu.TryLock()
		assert.True(t, unlocked, "report callbacks must not hold the audit lock")
		if unlocked {
			b.auditMu.Unlock()
		}
		rows = append(rows, v)
		return nil
	}
	require.NoError(t, b.ReportMetadata(context.Background(), "owner", false, emit))
	require.Len(t, rows, 1)
	assert.Equal(t, "ended", rows[0].State)
	rows = nil
	require.NoError(t, b.ReportMetadata(context.Background(), "", true, emit))
	require.Len(t, rows, 2)
	require.NoError(t, os.WriteFile(b.auditPath, []byte("corrupt"), 0600))
	assert.ErrorIs(t, b.ReportMetadata(context.Background(), "owner", false, emit), reporting.ErrInvalid)
	f, e := os.Create(b.auditPath)
	require.NoError(t, e)
	require.NoError(t, f.Truncate((64<<20)+1))
	require.NoError(t, f.Close())
	assert.ErrorIs(t, b.ReportMetadata(context.Background(), "owner", false, emit), reporting.ErrLimit)
}
