package sessionclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrganizationClientHeadersCloneAndTerminalQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/ops/jobs" {
			assert.Equal(t, organizations.DefaultID, r.Header.Get("X-JMS-ORG"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"job-org"}`))
			return
		}
		assert.Equal(t, "/ws/api/v1/sessions/test/terminal", r.URL.Path)
		assert.Equal(t, organizations.DefaultID, r.URL.Query().Get("org"))
		socket, e := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{gateway.TerminalSubprotocol}})
		if e != nil {
			return
		}
		_ = socket.Close(websocket.StatusNormalClosure, "done")
	}))
	defer server.Close()
	base, e := New(server.URL, "synthetic-token")
	require.NoError(t, e)
	selected, e := base.WithOrganization(organizations.DefaultID)
	require.NoError(t, e)
	assert.Empty(t, base.organization)
	_, e = selected.SubmitJob(context.Background(), jobs.Input{AssetID: "asset", Command: "printf ok"})
	require.NoError(t, e)
	socket, e := selected.DialTerminal(context.Background(), gateway.CreatedSession{SessionID: "test", Ticket: "synthetic-ticket", WebSocketURL: "/ws/api/v1/sessions/test/terminal?org=" + organizations.DefaultID})
	require.NoError(t, e)
	_ = socket.CloseNow()
	_, e = base.WithOrganization("../escape")
	require.Error(t, e)
}
