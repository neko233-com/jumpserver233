package sessionclient

import (
	"context"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/connector/kubeclient"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestTelnetRouteUsesOnlyPlatformIdentityAndDimensions(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		assert.Equal(t, "/api/v1/assets/asset-telnet/telnet/sessions", r.URL.Path)
		assert.Equal(t, "Bearer synthetic-platform-token", r.Header.Get("Authorization"))
		var body map[string]any
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, map[string]any{"cols": float64(80), "rows": float64(24)}, body)
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(gateway.CreatedSession{SessionID: "session-test", Ticket: "ticket-test", WebSocketURL: "/ws/terminal"})
	}))
	defer s.Close()
	c, e := New(s.URL, "synthetic-platform-token")
	require.NoError(t, e)
	request := gateway.CreateRequest{AssetID: "asset-telnet", Protocol: "telnet", Cols: 80, Rows: 24}
	created, e := c.CreateSession(context.Background(), request)
	require.NoError(t, e)
	assert.Equal(t, "session-test", created.SessionID)
	request.Kubernetes = &kubeclient.Selection{}
	_, e = c.CreateSession(context.Background(), request)
	require.Error(t, e)
	assert.Equal(t, int32(1), calls.Load())
}
