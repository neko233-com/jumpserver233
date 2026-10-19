package sessionclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMonitorHistoryClientScopesAndValidatesRequests(t *testing.T) {
	calls := 0
	from := time.Now().UTC().Add(-time.Hour)
	to := from.Add(time.Hour)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "/api/v1/assets/host1/monitor-history", r.URL.Path)
		assert.Equal(t, "Bearer synthetic-history-client", r.Header.Get("Authorization"))
		assert.Equal(t, "00000000-0000-0000-0000-000000000002", r.Header.Get("X-JMS-ORG"))
		assert.Equal(t, from.Format(time.RFC3339Nano), r.URL.Query().Get("from"))
		assert.Equal(t, "60", r.URL.Query().Get("step"))
		_, _ = w.Write([]byte(`{"asset_id":"host1","results":[],"password":"synthetic-extra-private-value"}`))
	}))
	defer srv.Close()
	c, e := New(srv.URL, "synthetic-history-client")
	require.NoError(t, e)
	c, e = c.WithOrganization("00000000-0000-0000-0000-000000000002")
	require.NoError(t, e)
	for _, id := range []string{"", "../escape", "a/b"} {
		_, e := c.MonitorHistory(context.Background(), id, from, to, 60)
		assert.Error(t, e)
	}
	_, e = c.MonitorHistory(context.Background(), "host1", from, to, 61)
	assert.Error(t, e)
	assert.Zero(t, calls)
	p, e := c.MonitorHistory(context.Background(), "host1", from, to, 60)
	require.NoError(t, e)
	assert.Equal(t, "host1", p.AssetID)
	assert.Equal(t, 1, calls)
}
