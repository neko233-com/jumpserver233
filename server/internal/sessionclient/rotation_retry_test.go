package sessionclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRotationPlanRetrySDKUsesBoundMetadataOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/accounts/rotation-runs/parent-run/retry", r.URL.Path)
		assert.Equal(t, "Bearer synthetic-platform-token", r.Header.Get("Authorization"))
		var input RotationRetryInput
		require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
		assert.Equal(t, 7, input.PlanRevision)
		assert.Equal(t, []string{"source-item"}, input.ItemIDs)
		w.WriteHeader(202)
		_, _ = w.Write([]byte(`{"id":"child-run","parent_run_id":"parent-run","retry_item_ids":["source-item"],"items":[{"id":"child-item","source_item_id":"source-item","fixed_password":"foreign-ignored"}],"fixed_secret_id":"foreign-ignored"}`))
	}))
	defer server.Close()
	c, e := New(server.URL, "synthetic-platform-token")
	require.NoError(t, e)
	out, e := c.RetryRotationRun(context.Background(), "parent-run", RotationRetryInput{RequestID: "retry-sdk", PlanRevision: 7, ItemIDs: []string{"source-item"}})
	require.NoError(t, e)
	assert.Equal(t, "parent-run", out.ParentRunID)
	assert.Equal(t, "source-item", out.Items[0].SourceItemID)
	raw, e := json.Marshal(out)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "foreign-ignored")
}
