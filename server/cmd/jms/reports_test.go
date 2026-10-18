package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReportCLIValidationCSVAndHistory(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path == "/api/v1/reports/export.csv" {
			data := "source,count\nssh_jobs,1\n"
			sum := sha256.Sum256([]byte(data))
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("X-JMS-Report-ID", "report-export-00112233445566778899aabbccddeeff")
			w.Header().Set("X-JMS-Report-SHA256", hex.EncodeToString(sum[:]))
			assert.Equal(t, "ssh_jobs", r.URL.Query().Get("sources"))
			fmt.Fprint(w, data)
			return
		}
		fmt.Fprint(w, `{"results":[],"total":0}`)
	}))
	defer srv.Close()
	c, e := sessionclient.New(srv.URL, "synthetic-token")
	require.NoError(t, e)
	var out bytes.Buffer
	for _, args := range [][]string{{}, {"unknown"}, {"overview", "--from", "bad"}, {"exports", "--limit", "101"}, {"exports", "--offset", "-1"}, {"overview", "extra"}} {
		require.Error(t, executeReports(context.Background(), c, args, &out))
	}
	assert.Zero(t, calls)
	require.NoError(t, executeReports(context.Background(), c, []string{"export", "--sources", "ssh_jobs"}, &out))
	assert.Equal(t, "source,count\nssh_jobs,1\n", out.String())
	require.NoError(t, executeReports(context.Background(), c, []string{"exports", "--all"}, &out))
	assert.Equal(t, 2, calls)
}
