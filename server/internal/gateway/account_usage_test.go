package gateway

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAccountUsageUsesRetainedSessionMetadataAndFailsClosedOnCorruption(t *testing.T) {
	b := NewBroker(t.TempDir(), make([]byte, 32), nil)
	require.NoError(t, os.MkdirAll(filepath.Dir(b.auditPath), 0700))
	wanted := map[string]bool{"account": true}
	out, e := b.AccountUsage(context.Background(), wanted)
	require.NoError(t, e)
	assert.Empty(t, out)
	raw := "{\"asset_id\":\"account\",\"event\":\"started\",\"at\":\"2026-10-01T00:00:00Z\"}\n{\"asset_id\":\"account\",\"event\":\"ended\",\"at\":\"2026-10-02T00:00:00Z\"}\n{\"asset_id\":\"other\",\"event\":\"ended\",\"at\":\"2026-10-03T00:00:00Z\"}\n"
	raw += "{\"session_id\":\"session\",\"event\":\"monitor_started\",\"viewer_id\":\"operator\",\"at\":\"2026-10-04T00:00:00Z\"}\n"
	raw += "{\"session_id\":\"session\",\"event\":\"share_joined\",\"at\":\"2026-10-04T00:00:00Z\"}\n"
	require.NoError(t, os.WriteFile(b.auditPath, []byte(raw), 0600))
	out, e = b.AccountUsage(context.Background(), wanted)
	require.NoError(t, e)
	assert.Equal(t, time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC), out["account"])
	assert.Len(t, out, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = b.AccountUsage(ctx, wanted)
	assert.ErrorIs(t, e, context.Canceled)
	for _, bad := range []string{"broken\n", raw[:len(raw)-1], "{\"asset_id\":\"account\"}\n", "{\"event\":\"started\",\"at\":\"2026-10-01T00:00:00Z\"}\n"} {
		require.NoError(t, os.WriteFile(b.auditPath, []byte(bad), 0600))
		_, e = b.AccountUsage(context.Background(), wanted)
		assert.Error(t, e)
	}
}
