package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestAccountRisksCLIRequiresVersionsAndExportsOnlyToNewFile(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.URL.Path {
		case "/api/v1/accounts/risks/policy":
			if r.Method == "PUT" {
				var p sessionclient.AccountRiskPolicy
				require.NoError(t, json.NewDecoder(r.Body).Decode(&p))
				assert.Equal(t, 9, p.Revision)
				assert.Equal(t, 30, p.MinPasswordLength)
				assert.Equal(t, 24, p.IntervalHours)
				_ = json.NewEncoder(w).Encode(p)
			} else {
				_ = json.NewEncoder(w).Encode(sessionclient.AccountRiskPolicy{Revision: 9, IntervalHours: 24})
			}
		case "/api/v1/accounts/risks/export":
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			_, _ = w.Write([]byte("id,kind\nrisk-test,weak_password\n"))
		default:
			t.Errorf("unexpected CLI request %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	c, e := sessionclient.New(server.URL, "synthetic-risk-token")
	require.NoError(t, e)
	var out bytes.Buffer
	for _, args := range [][]string{{"scan"}, {"review", "id", "--action", "ignore"}, {"policy-update"}, {"scans", "--limit", "101"}, {"audit", "--kind", "weak_password"}} {
		require.Error(t, executeAccountRisks(context.Background(), c, args, &out))
	}
	assert.Zero(t, calls)
	require.NoError(t, executeAccountRisks(context.Background(), c, []string{"policy-update", "--revision", "9", "--min-length", "30"}, &out))
	path := filepath.Join(t.TempDir(), "risks.csv")
	require.NoError(t, executeAccountRisks(context.Background(), c, []string{"export", "--out", path}, &out))
	require.Error(t, executeAccountRisks(context.Background(), c, []string{"export", "--out", path}, &out))
	data, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.Contains(t, string(data), "risk-test")
	assert.NotContains(t, out.String(), "synthetic-risk-token")
}
