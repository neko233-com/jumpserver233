package accountrisks

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestScanNotificationMetadataRetainedAndNoFindingPayload(t *testing.T) {
	s, snapshot, _ := riskService(t)
	first := scanRisk(t, s, "notification-risk")
	batch, e := s.NotificationFeed(context.Background(), "", time.Time{}, 100)
	require.NoError(t, e)
	require.Len(t, batch.Events, 1)
	assert.Equal(t, first.ID, batch.Events[0].ResourceID)
	assert.Equal(t, "risk_scan_findings", batch.Events[0].State)
	raw, _ := json.Marshal(batch)
	for _, private := range []string{snapshot.Accounts[0].Binding, snapshot.Accounts[0].Identity, "weak_password", "short", "synthetic-risk-operator"} {
		assert.NotContains(t, string(raw), private)
	}
	snapshot.Accounts = nil
	clear := scanRisk(t, s, "notification-clear")
	next, e := s.NotificationFeed(context.Background(), batch.Cursor, time.Time{}, 100)
	require.NoError(t, e)
	require.Len(t, next.Events, 1)
	assert.Equal(t, clear.ID, next.Events[0].ResourceID)
	assert.Equal(t, "risk_scan_clear", next.Events[0].State)
}
