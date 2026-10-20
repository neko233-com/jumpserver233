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

func TestAccountCheckSDKUsesCheckEndpointAndMetadataOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/accounts/rotation-plans/check-plan/checks", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		var in map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
		assert.Equal(t, map[string]string{"request_id": "check-sdk-id"}, in)
		w.WriteHeader(202)
		_, _ = w.Write([]byte(`{"id":"check-run","operation":"check","items":[{"check_duration_ms":5,"before_revision":2}],"password":"foreign-ignored"}`))
	}))
	defer server.Close()
	c, e := New(server.URL, "synthetic-platform-token")
	require.NoError(t, e)
	r, e := c.CheckRotationPlan(context.Background(), "check-plan", "check-sdk-id")
	require.NoError(t, e)
	assert.Equal(t, "check", r.Operation)
	assert.EqualValues(t, 5, r.Items[0].CheckDurationMS)
	raw, _ := json.Marshal(r)
	assert.NotContains(t, string(raw), "foreign-ignored")
}
