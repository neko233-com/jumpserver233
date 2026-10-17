package agentevents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNotificationIndexCommitsWithCursorAndOmitsPrivateReceipts(t *testing.T) {
	s := open(t)
	p := eventPage(fmt.Sprintf("%032x", 1), 1, 2, hostagent.SHA(nil), hostagent.EventCursor{})
	p.Events[1].Kind = "repair_failed"
	p.Events[1].ErrorCode = "kernel_unavailable"
	p.Events[1].Hash = hostagent.EventHash(p.Events[1])
	s.saveHook = func(key string, _ []byte) error {
		if key == "index" {
			return errors.New("synthetic index fault")
		}
		return nil
	}
	_, e := s.Import(src, col, p.Requested, p)
	require.Error(t, e)
	batch, e := s.NotificationFeed(context.Background(), "", time.Time{}, 64)
	require.NoError(t, e)
	assert.Empty(t, batch.Events)
	s.saveHook = nil
	_, e = s.Import(src, col, p.Requested, p)
	require.NoError(t, e)
	batch, e = s.NotificationFeed(context.Background(), "", time.Time{}, 1)
	require.NoError(t, e)
	require.Len(t, batch.Events, 1)
	assert.Equal(t, "agent_repair_completed", batch.Events[0].State)
	next, e := s.NotificationFeed(context.Background(), batch.Cursor, time.Time{}, 64)
	require.NoError(t, e)
	require.Len(t, next.Events, 1)
	assert.Equal(t, "agent_repair_failed", next.Events[0].State)
	public, _ := json.Marshal(next)
	for _, private := range []string{"configuration", "ConfigSHA", "kernel_unavailable", "PreviousHash"} {
		assert.NotContains(t, string(public), private)
	}
	reference, e := s.NotificationSource(next.Events[0].ResourceID)
	require.NoError(t, e)
	assert.Equal(t, src, reference.Source)
	assert.Equal(t, col.ID, reference.CollectorID)
	raw, e := os.ReadFile(filepath.Join(s.dir, "index.json"))
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "QA host")
	// A metadata read must not need a bulky raw collection segment.
	segment := filepath.Join(s.dir, "segment-000000000000.json")
	require.NoError(t, os.WriteFile(segment, []byte("synthetic unreadable segment"), 0600))
	recent, e := s.NotificationFeed(context.Background(), "", time.Time{}, 64)
	require.NoError(t, e)
	assert.Len(t, recent.Events, 2)
	_, e = s.NotificationSource(next.Events[0].ResourceID)
	require.NoError(t, e)
}
func TestLegacyAlertIndexMigrationStartsAtUpgradeAndKeepsAuditHistory(t *testing.T) {
	s := open(t)
	p := eventPage(fmt.Sprintf("%032x", 1), 1, 2, hostagent.SHA(nil), hostagent.EventCursor{})
	_, e := s.Import(src, col, p.Requested, p)
	require.NoError(t, e)
	s.data.Notifications = nil
	require.NoError(t, s.save("index", s.data))
	s.Close()
	current, e := Open(s.dir, make([]byte, 32), nil)
	require.NoError(t, e)
	defer current.Close()
	batch, e := current.NotificationFeed(context.Background(), "", time.Time{}, 64)
	require.NoError(t, e)
	assert.Empty(t, batch.Events)
	history, e := current.List(0, 50, func(Source) bool { return true })
	require.NoError(t, e)
	assert.Len(t, history.Results, 2)
	cursor, e := current.Cursor(src)
	require.NoError(t, e)
	page := eventPage(p.Stream, 3, 1, cursor.Hash, cursor)
	_, e = current.Import(src, col, cursor, page)
	require.NoError(t, e)
	batch, e = current.NotificationFeed(context.Background(), "", time.Time{}, 64)
	require.NoError(t, e)
	require.Len(t, batch.Events, 1)
	assert.Equal(t, "agent-event-3", batch.Events[0].ResourceID)
	current.Close()
	again, e := Open(s.dir, make([]byte, 32), nil)
	require.NoError(t, e)
	defer again.Close()
	batch, e = again.NotificationFeed(context.Background(), "", time.Time{}, 64)
	require.NoError(t, e)
	assert.Len(t, batch.Events, 1)
}
func TestAlertRetentionGapIsExplicitAndMetadataCopyIsIndependent(t *testing.T) {
	s := open(t)
	p := eventPage(fmt.Sprintf("%032x", 1), 1, 2, hostagent.SHA(nil), hostagent.EventCursor{})
	_, e := s.Import(src, col, p.Requested, p)
	require.NoError(t, e)
	first, e := s.NotificationFeed(context.Background(), "", time.Time{}, 1)
	require.NoError(t, e)
	next := copyIndex(s.data)
	next.Notifications.Alerts[0].At = time.Now().Add(-31 * 24 * time.Hour)
	next.Notifications.Alerts[0].ID = alertID(next.Notifications.Alerts[0])
	pruneNotificationAlerts(&next, time.Now())
	assert.Len(t, s.data.Notifications.Alerts, 2)
	assert.Len(t, next.Notifications.Alerts, 1)
	require.NoError(t, s.save("index", next))
	s.data = next
	gap, e := s.NotificationFeed(context.Background(), first.Cursor, time.Time{}, 64)
	require.NoError(t, e)
	assert.True(t, gap.Gap)
	assert.Len(t, gap.Events, 1)
}
func TestAlertIndexEncodedBudgetPrunesMetadataAndRemainsReadable(t *testing.T) {
	s := open(t)
	next := copyIndex(s.data)
	next.Total = maxNotificationAlerts
	now := time.Now().UTC()
	for i := 1; i <= maxNotificationAlerts; i++ {
		a := notificationAlert{Index: uint64(i), Source: Source{AssetID: strings.Repeat("a", 128), AssetName: strings.Repeat("\x00", 256), Account: strings.Repeat("u", 128)}, CollectorID: strings.Repeat("c", 128), State: "agent_repair_completed", At: now}
		a.ID = alertID(a)
		next.Notifications.Alerts = append(next.Notifications.Alerts, a)
	}
	require.NoError(t, s.saveIndex(&next))
	require.NotEmpty(t, next.Notifications.Alerts)
	assert.Less(t, len(next.Notifications.Alerts), maxNotificationAlerts)
	assert.Empty(t, s.data.Notifications.Alerts)
	var decoded index
	require.NoError(t, s.load("index", &decoded))
	assert.Equal(t, next.Notifications.Boundary, decoded.Notifications.Boundary)
	assert.Equal(t, next.Total, decoded.Total)
	assert.Equal(t, next.Notifications.Alerts, decoded.Notifications.Alerts)
	raw, e := os.ReadFile(filepath.Join(s.dir, "index.json"))
	require.NoError(t, e)
	assert.LessOrEqual(t, len(raw), maxEncryptedDocumentBytes)
	require.ErrorIs(t, s.save("oversized", strings.Repeat("x", maxEncryptedDocumentBytes)), ErrInvalid)
	_, e = os.Stat(filepath.Join(s.dir, "oversized.json"))
	assert.ErrorIs(t, e, os.ErrNotExist)
}
