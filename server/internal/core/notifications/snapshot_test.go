package notifications

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"slices"
	"testing"
	"time"
)

func TestSnapshotFeedLateAuthorityAndNoRepeatedSendOrIdleWrite(t *testing.T) {
	s, f, path := setup(t)
	subscribe(t, s)
	r := f.runner()
	r.Feeds[0].Read = func(_ context.Context, after string, since time.Time, limit int) (eventfeed.Batch, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		rows := slices.Clone(f.events)
		slices.SortFunc(rows, func(a, b eventfeed.Event) int {
			if a.ID < b.ID {
				return -1
			}
			if a.ID > b.ID {
				return 1
			}
			return 0
		})
		return eventfeed.Snapshot(rows, after, since, limit), nil
	}
	s.SetRunner(r)
	f.add("late-role")
	f.mu.Lock()
	f.visible = false
	f.mu.Unlock()
	drain(t, s)
	f.mu.Lock()
	assert.Empty(t, f.sent)
	f.visible = true
	f.mu.Unlock()
	drain(t, s)
	f.mu.Lock()
	require.Len(t, f.sent, 1)
	f.mu.Unlock()
	before, e := os.ReadFile(path)
	require.NoError(t, e)
	for range 3 {
		drain(t, s)
	}
	after, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.Equal(t, before, after)
	f.mu.Lock()
	require.Len(t, f.sent, 1)
	f.mu.Unlock()
	f.add("late-insert")
	drain(t, s)
	f.mu.Lock()
	assert.Len(t, f.sent, 2)
	f.mu.Unlock()
}
