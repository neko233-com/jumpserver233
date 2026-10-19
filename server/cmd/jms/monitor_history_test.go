package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMonitorHistoryCLIReadsNativeHistoryAndRejectsInvalidRanges(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "/api/v1/assets/host1/monitor-history", r.URL.Path)
		assert.Equal(t, "300", r.URL.Query().Get("step"))
		_, _ = w.Write([]byte(`{"asset_id":"host1","results":[],"password":"synthetic-extra-private-value"}`))
	}))
	defer srv.Close()
	c, e := sessionclient.New(srv.URL, "synthetic-history-client")
	require.NoError(t, e)
	var output bytes.Buffer
	for _, args := range [][]string{{"history"}, {"history", "../escape"}, {"history", "host1", "--from", "bad"}, {"history", "host1", "--step", "1"}, {"history", "host1", "--to", "bad"}} {
		assert.Error(t, executeMonitor(context.Background(), c, args, strings.NewReader(""), &output))
	}
	assert.Zero(t, calls)
	end := time.Now().UTC()
	require.NoError(t, executeMonitor(context.Background(), c, []string{"history", "host1", "--from", end.Add(-time.Hour).Format(time.RFC3339Nano), "--to", end.Format(time.RFC3339Nano), "--step", "300"}, strings.NewReader(""), &output))
	assert.Equal(t, 1, calls)
	assert.Contains(t, output.String(), "host1")
	assert.NotContains(t, output.String(), "synthetic-extra-private-value")
}
