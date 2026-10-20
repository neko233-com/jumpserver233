package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRotationPlanRetryCLIValidatesSelectionRevisionAndUsesPlatformIdentity(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "/api/v1/accounts/rotation-runs/source-run/retry", r.URL.Path)
		var in sessionclient.RotationRetryInput
		require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
		assert.Equal(t, 3, in.PlanRevision)
		assert.NotEmpty(t, in.RequestID)
		assert.Equal(t, []string{"item-a", "item-b"}, in.ItemIDs)
		w.WriteHeader(202)
		_ = json.NewEncoder(w).Encode(sessionclient.RotationRun{ID: "child-run", ParentRunID: "source-run", State: "succeeded"})
	}))
	defer server.Close()
	c, e := sessionclient.New(server.URL, "synthetic-token")
	require.NoError(t, e)
	var out bytes.Buffer
	for _, args := range [][]string{{"retry", "source-run"}, {"retry", "source-run", "--plan-revision", "0"}, {"retry", "source-run", "--plan-revision", "1", "--items", "item-a,item-a"}, {"retry", "source-run", "--plan-revision", "1", "--items", "bad/id"}, {"retry", "source-run", "--plan-revision", "1", "--fixed-password", "rejected"}} {
		assert.Error(t, executeRotationPlans(context.Background(), c, args, &out))
	}
	assert.Zero(t, calls)
	require.NoError(t, executeRotationPlans(context.Background(), c, []string{"retry", "source-run", "--plan-revision", "3", "--items", "item-a,item-b", "--request-id", "retry-cli", "--wait"}, &out))
	assert.Equal(t, 1, calls)
	assert.Contains(t, out.String(), "child-run")
	assert.NotContains(t, out.String(), "synthetic-token")
}
