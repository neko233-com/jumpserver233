package sessionclient

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAgentEventClientPreservesQueryAndAuthenticatedCollection(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		require.Equal(t, "Bearer synthetic-token", r.Header.Get("Authorization"))
		if r.Method == "GET" {
			require.Equal(t, "/api/v1/assets/asset-a/agent-events", r.URL.Path)
			require.Equal(t, "42", r.URL.Query().Get("before"))
			require.Equal(t, "50", r.URL.Query().Get("limit"))
			_, _ = w.Write([]byte(`{"results":[],"next_before":0}`))
			return
		}
		require.Equal(t, "/api/v1/assets/asset-a/agent-events/collection", r.URL.Path)
		var in map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
		require.Equal(t, true, in["enabled"])
		require.Equal(t, float64(300), in["interval_seconds"])
		w.WriteHeader(201)
	}))
	defer s.Close()
	c, e := New(s.URL, "synthetic-token")
	require.NoError(t, e)
	_, e = c.AgentEvents(context.Background(), "asset-a", 42)
	require.NoError(t, e)
	require.NoError(t, c.SetAgentCollection(context.Background(), "asset-a", true, 300, "qa-request"))
	require.Equal(t, 2, calls)
}
