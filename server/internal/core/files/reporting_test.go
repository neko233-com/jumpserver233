package files

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/reporting"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
	"time"
)

func TestReportFileOperationsUseNativeActorScope(t *testing.T) {
	a, e := OpenAuditStore(filepath.Join(t.TempDir(), "audit.jsonl"))
	require.NoError(t, e)
	for _, actor := range []string{"owner", "other"} {
		require.NoError(t, a.Append(Transfer{Actor: actor, At: time.Now(), Path: "/synthetic-private", Success: actor == "owner"}))
	}
	s := NewService(nil, a)
	var rows []reporting.Entry
	emit := func(v reporting.Entry) error { rows = append(rows, v); return nil }
	require.NoError(t, s.ReportMetadata(context.Background(), "owner", false, emit))
	require.Len(t, rows, 1)
	assert.Equal(t, "succeeded", rows[0].State)
	rows = nil
	require.NoError(t, s.ReportMetadata(context.Background(), "", true, emit))
	require.Len(t, rows, 2)
}
