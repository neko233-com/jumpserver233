package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/desktop"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDesktopMonitorCLICapturesWithoutInputOrClosingPrimary(t *testing.T) {
	var posts, deletes atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/desktop-sessions/{id}/monitor", func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		assert.Equal(t, "Bearer platform-token", r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(desktop.Created{ID: "qa", URL: "/ws/desktop/qa/monitor", Ticket: "one-use-monitor-ticket"})
	})
	mux.HandleFunc("DELETE /api/v1/desktop-sessions/{id}", func(w http.ResponseWriter, r *http.Request) { deletes.Add(1); w.WriteHeader(204) })
	mux.HandleFunc("GET /ws/desktop/qa/monitor", func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.Header.Get("Sec-WebSocket-Protocol"), desktop.MonitorTicketPrefix+"one-use-monitor-ticket")
		c, e := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{desktop.MonitorSubprotocol}})
		if !assert.NoError(t, e) {
			return
		}
		defer c.CloseNow()
		_ = c.Write(r.Context(), websocket.MessageText, []byte(`{"type":"ready","read_only":true,"clipboard":false}`))
		_ = c.Write(r.Context(), websocket.MessageBinary, append(make([]byte, 8), []byte("synthetic monitor PNG")...))
		_, _, _ = c.Read(r.Context())
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client, e := sessionclient.New(server.URL, "platform-token")
	require.NoError(t, e)
	file := filepath.Join(t.TempDir(), "monitor.png")
	var out bytes.Buffer
	require.Error(t, executeDesktop(context.Background(), client, []string{"monitor", "qa", "--capture", file, "--input", "events.json"}, &out))
	assert.Zero(t, posts.Load())
	assert.NoFileExists(t, file)
	require.NoError(t, executeDesktop(context.Background(), client, []string{"monitor", "qa", "--capture", file, "--wait", "1"}, &out))
	assert.EqualValues(t, 1, posts.Load())
	assert.Zero(t, deletes.Load())
	assert.Contains(t, out.String(), `"monitor":true`)
	assert.NotContains(t, out.String(), "platform-token")
	assert.NotContains(t, out.String(), "one-use-monitor-ticket")
	raw, e := os.ReadFile(file)
	require.NoError(t, e)
	assert.Equal(t, "synthetic monitor PNG", string(raw))
}
