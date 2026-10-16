package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/desktop"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestDesktopCLICaptureUsesPlatformIdentityAndExclusiveFile(t *testing.T) {
	var closed atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/assets/desk/rdp/sessions", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer platform-token", r.Header.Get("Authorization"))
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(desktop.Created{ID: "session", URL: "/ws/desktop/session", Ticket: "ticket"})
	})
	mux.HandleFunc("DELETE /api/v1/desktop-sessions/session", func(w http.ResponseWriter, r *http.Request) { closed.Store(true); w.WriteHeader(204) })
	mux.HandleFunc("GET /ws/desktop/session", func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("Authorization"))
		conn, e := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{desktop.Subprotocol}})
		if e != nil {
			return
		}
		defer conn.CloseNow()
		data := make([]byte, 32)
		binary.BigEndian.PutUint64(data, 1)
		copy(data[8:], []byte("synthetic frame payload"))
		_ = conn.Write(r.Context(), websocket.MessageBinary, data)
		for {
			var raw []byte
			if _, raw, e = conn.Read(r.Context()); e != nil {
				return
			}
			var event struct {
				Type string `json:"type"`
			}
			_ = json.Unmarshal(raw, &event)
			if event.Type == "text" {
				_ = conn.Write(r.Context(), websocket.MessageText, []byte(`{"type":"text_error"}`))
			}
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client, e := sessionclient.New(server.URL, "platform-token")
	require.NoError(t, e)
	path := filepath.Join(t.TempDir(), "capture.png")
	var out bytes.Buffer
	require.NoError(t, executeDesktop(context.Background(), client, []string{"desk", "--capture", path, "--wait", "1"}, &out))
	assert.True(t, closed.Load())
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.Contains(t, string(raw), "synthetic frame")
	assert.NotContains(t, out.String(), "platform-token")
	assert.Error(t, executeDesktop(context.Background(), client, []string{"desk", "--capture", path}, &out))
	input := filepath.Join(t.TempDir(), "events.json")
	require.NoError(t, os.WriteFile(input, []byte(`[{"type":"text","text":"中文"}]`), 0600))
	rejected := filepath.Join(t.TempDir(), "rejected.png")
	var failed bytes.Buffer
	closed.Store(false)
	assert.ErrorContains(t, executeDesktop(context.Background(), client, []string{"desk", "--capture", rejected, "--input", input, "--wait", "1"}, &failed), "did not accept")
	assert.NoFileExists(t, rejected)
	assert.Empty(t, failed.String())
	assert.True(t, closed.Load())
	for _, args := range [][]string{{}, {"desk"}, {"desk", "--capture", path, "--wait", "0"}, {"desk", "--capture", path, "--unknown"}} {
		assert.Error(t, executeDesktop(context.Background(), client, args, &out))
	}
}
