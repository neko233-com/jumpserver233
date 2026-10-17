package notifications

import (
	"context"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPostgresTakeoverKeepsCursorAndUnknownReceiptIsolatesOrganizations(t *testing.T) {
	dsn := os.Getenv("JMS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires PostgreSQL state fixture")
	}
	docs, e := storage.OpenPostgres(context.Background(), dsn, fmt.Sprintf("notifications-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	a, e := docs.Scoped("notification-a")
	require.NoError(t, e)
	b, e := docs.Scoped("notification-b")
	require.NoError(t, e)
	defer docs.Close()
	defer a.Delete("notifications")
	defer b.Delete("notifications")
	_, f, _ := setup(t)
	s, e := Open(filepath.Join(t.TempDir(), "a.json"), make([]byte, 32), a)
	require.NoError(t, e)
	s.SetRunner(f.runner())
	subscribe(t, s)
	f.add("pg-job")
	drain(t, s)
	require.NoError(t, s.mutate(func(d *state) error {
		for id, v := range d.Deliveries {
			v.State = "sending"
			d.Deliveries[id] = v
		}
		return nil
	}))
	s.Close()
	raw, e := a.Load("notifications")
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "capture.invalid")
	next, e := Open(filepath.Join(t.TempDir(), "peer.json"), make([]byte, 32), a)
	require.NoError(t, e)
	defer next.Close()
	next.SetRunner(f.runner())
	drain(t, next)
	page, e := next.Deliveries(context.Background(), "operator", "uncertain", 0, 20)
	require.NoError(t, e)
	assert.Len(t, page.Results, 1)
	f.mu.Lock()
	assert.Len(t, f.sent, 1)
	f.mu.Unlock()
	isolated, e := Open(filepath.Join(t.TempDir(), "b.json"), bytesKey(2), b)
	require.NoError(t, e)
	defer isolated.Close()
	isolated.SetRunner(f.runner())
	page2, _, e := isolated.Inbox(context.Background(), "operator", false, 0, 20)
	require.NoError(t, e)
	assert.Empty(t, page2.Results)
}
