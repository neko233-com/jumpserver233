package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReplayStorageCLICompleteSurfaceStrictInputAndSecretRedaction(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "Bearer synthetic-token", r.Header.Get("Authorization"))
		if r.Method == "PUT" {
			var body map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			_ = json.NewEncoder(w).Encode(body)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": []any{}, "total": 0, "config": map[string]any{"provider": "local"}})
	}))
	defer server.Close()
	c, e := sessionclient.New(server.URL, "synthetic-token")
	require.NoError(t, e)
	for _, args := range [][]string{{}, {"unknown"}, {"get", "terminal", "../escape"}, {"get", "invalid", "terminal-session-001"}, {"records", "--limit", "101"}, {"verify", "terminal", "terminal-session-001"}, {"save", "--file", "-"}} {
		var out bytes.Buffer
		require.Error(t, executeReplayStorage(context.Background(), c, args, strings.NewReader(`{"unknown":true}`), &out))
		assert.Empty(t, out.String())
	}
	assert.Zero(t, calls)
	for _, args := range [][]string{{"settings"}, {"records"}, {"audit", "--limit", "10"}, {"get", "terminal", "terminal-session-001"}, {"archive", "terminal", "terminal-session-001", "--request-id", "cli-archive-001"}, {"retry", "terminal", "terminal-session-001", "--request-id", "cli-retry-001"}, {"verify", "terminal", "terminal-session-001", "--request-id", "cli-verify-001"}, {"evict", "desktop", "desktop-session-0001", "--request-id", "cli-evict-001"}, {"save", "--file", "-"}} {
		var out bytes.Buffer
		body := `{"provider":"s3","enabled":true,"revision":0,"request_id":"cli-config-001","cloud":{"provider":"s3","endpoint":"https://replay.example.com","region":"us-east-1","bucket":"replays","access_key_id":"synthetic-key","secret_access_key":"synthetic-secret","session_token":"synthetic-token-value"}}`
		require.NoError(t, executeReplayStorage(context.Background(), c, args, strings.NewReader(body), &out))
		assert.NotEmpty(t, out.String())
		assert.NotContains(t, out.String(), "synthetic-secret")
		assert.NotContains(t, out.String(), "synthetic-token-value")
	}
	assert.Equal(t, 9, calls)
}
