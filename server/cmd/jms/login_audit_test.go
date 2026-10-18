package main

import (
	"bytes"
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoginAuditCLIValidationAndCSV(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path == "/api/v1/audits/logins/export.csv" {
			assert.Equal(t, "all", r.URL.Query().Get("scope"))
			w.Header().Set("Content-Type", "text/csv")
			_, _ = w.Write([]byte("id,outcome\na,succeeded\n"))
			return
		}
		_, _ = w.Write([]byte(`{"results":[],"total":0}`))
	}))
	defer srv.Close()
	c, e := sessionclient.New(srv.URL, "synthetic-token")
	require.NoError(t, e)
	var out bytes.Buffer
	for _, args := range [][]string{{}, {"unknown"}, {"event", "../bad"}, {"list", "--limit", "201"}, {"list", "--from", "bad"}, {"list", "--offset", "-1"}} {
		require.Error(t, executeLoginAudit(context.Background(), c, args, &out))
	}
	assert.Zero(t, calls)
	require.NoError(t, executeLoginAudit(context.Background(), c, []string{"export", "--all"}, &out))
	assert.Contains(t, out.String(), "a,succeeded")
	require.NoError(t, executeLoginAudit(context.Background(), c, []string{"summary"}, &out))
	assert.Equal(t, 2, calls)
}
