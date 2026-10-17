package sessionclient

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRotationSDKAcceptsAsyncReceiptsAndPreservesScopeWithMetadataOnly(t *testing.T) {
	for _, mode := range []string{"bearer", "access-key"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				assert.Equal(t, "00000000-0000-0000-0000-000000000002", r.Header.Get("X-JMS-ORG"))
				assert.NotEmpty(t, r.Header.Get("Authorization"))
				switch r.URL.Path {
				case "/api/v1/accounts/rotation-targets":
					assert.Equal(t, "host & key", r.URL.Query().Get("q"))
					assert.Equal(t, "account-root", r.URL.Query().Get("collector_for"))
					_, _ = w.Write([]byte(`{"results":[{"account_id":"safe-account","password":"must-never-decode-secret"}],"total":1}`))
				case "/api/v1/accounts/rotation-plans/plan-safe/runs":
					w.WriteHeader(202)
					_, _ = w.Write([]byte(`{"id":"run-safe","state":"queued","items":[{"account_id":"safe-account","private_key":"must-never-decode-secret"}]}`))
				case "/api/v1/accounts/rotation-runs/run-safe/export":
					w.Header().Set("Content-Type", "text/csv; charset=utf-8")
					_, _ = w.Write([]byte("run_id,state\nrun-safe,succeeded\n"))
				default:
					w.WriteHeader(409)
					_, _ = w.Write([]byte(`{"error_code":"conflict","error":"must-never-print-secret"}`))
				}
			}))
			defer server.Close()
			c, e := New(server.URL, "synthetic-token")
			if mode == "access-key" {
				c, e = NewWithAccessKey(server.URL, "ak-"+strings.Repeat("a", 32), "synthetic-rotation-key")
			}
			require.NoError(t, e)
			c, e = c.WithOrganization("00000000-0000-0000-0000-000000000002")
			require.NoError(t, e)
			ctx := context.Background()
			targets, e := c.RotationTargets(ctx, "host & key", "account-root", 0, 25)
			require.NoError(t, e)
			assert.Equal(t, 1, targets.Total)
			run, e := c.RunRotationPlan(ctx, "plan-safe", "request-safe")
			require.NoError(t, e)
			assert.Equal(t, "run-safe", run.ID)
			raw, e := json.Marshal([]any{targets, run})
			require.NoError(t, e)
			assert.NotContains(t, string(raw), "must-never-decode")
			csv, e := c.ExportRotationRun(ctx, "run-safe")
			require.NoError(t, e)
			assert.Contains(t, string(csv), "succeeded")
			e = c.RecoverRotationRun(ctx, "run-safe")
			require.Error(t, e)
			assert.Contains(t, e.Error(), "conflict")
			assert.NotContains(t, e.Error(), "must-never-print")
			assert.Equal(t, 4, calls)
		})
	}
}
