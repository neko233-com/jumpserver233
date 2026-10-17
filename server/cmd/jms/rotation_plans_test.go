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

func TestRotationCLIParsesMetadataRejectsSecretsAndWaitsForPartialResult(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.URL.Path {
		case "/api/v1/accounts/rotation-plans":
			var in sessionclient.RotationPlanInput
			require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
			assert.Equal(t, "synthetic metadata", in.Name)
			assert.Equal(t, "account-test", in.Targets[0].AccountID)
			_ = json.NewEncoder(w).Encode(sessionclient.RotationPlan{ID: "plan-test", RotationPlanInput: in})
		case "/api/v1/accounts/rotation-plans/plan-test/runs":
			w.WriteHeader(202)
			_ = json.NewEncoder(w).Encode(sessionclient.RotationRun{ID: "run-test", State: "partial"})
		case "/api/v1/accounts/rotation-runs/run-test/export":
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			_, _ = w.Write([]byte("run_id,state\nrun-test,partial\n"))
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	c, e := sessionclient.New(server.URL, "synthetic-token")
	require.NoError(t, e)
	var output bytes.Buffer
	for _, args := range [][]string{{}, {"delete", "p"}, {"targets", "--limit", "101"}, {"plans", "--collector-for", "p"}, {"run", "p", "--timeout-seconds", "3601"}, {"create"}} {
		assert.Error(t, executeRotationPlans(context.Background(), c, args, &output))
	}
	assert.Zero(t, calls)
	path := filepath.Join(t.TempDir(), "plan.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"name":"synthetic metadata","kind":"manual","targets":[{"account_id":"account-test"}],"password":"must-not-be-accepted"}`), 0600))
	assert.Error(t, executeRotationPlans(context.Background(), c, []string{"create", "--file", path}, &output))
	assert.Zero(t, calls)
	require.NoError(t, os.WriteFile(path, []byte(`{"name":"synthetic metadata","kind":"manual","targets":[{"account_id":"account-test"}]}`), 0600))
	require.NoError(t, executeRotationPlans(context.Background(), c, []string{"create", "--file", path}, &output))
	assert.Equal(t, 1, calls)
	output.Reset()
	e = executeRotationPlans(context.Background(), c, []string{"run", "plan-test", "--request-id", "safe-request", "--wait"}, &output)
	require.Error(t, e)
	assert.Contains(t, output.String(), "run-test")
	assert.Contains(t, e.Error(), "attention")
	csv := filepath.Join(t.TempDir(), "run.csv")
	require.NoError(t, executeRotationPlans(context.Background(), c, []string{"export", "run-test", "--out", csv}, &output))
	assert.Error(t, executeRotationPlans(context.Background(), c, []string{"export", "run-test", "--out", csv}, &output))
	assert.NotContains(t, output.String(), "synthetic-token")
}
