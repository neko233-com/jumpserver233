package main

import (
	"bytes"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOrganizationOverviewCLIRejectsUnrelatedFlagsAndReadsTotals(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "/api/v1/organizations/overview", r.URL.Path)
		assert.Equal(t, "true", r.URL.Query().Get("include_archived"))
		_, _ = w.Write([]byte(`{"results":[],"totals":{"assets":3},"partial":false}`))
	}))
	defer srv.Close()
	c, err := sessionclient.New(srv.URL, "synthetic-token")
	require.NoError(t, err)
	var out bytes.Buffer
	for _, args := range [][]string{{"organizations", "--sources", "ssh_jobs"}, {"organizations", "--all"}, {"organizations", "--from", "2026-10-20T00:00:00Z"}, {"overview", "--include-archived"}} {
		require.Error(t, executeReports(t.Context(), c, args, &out))
	}
	assert.Zero(t, calls)
	require.NoError(t, executeReports(t.Context(), c, []string{"organizations", "--include-archived"}, &out))
	assert.Contains(t, out.String(), `"assets":3`)
	assert.NotContains(t, out.String(), "synthetic-token")
}
