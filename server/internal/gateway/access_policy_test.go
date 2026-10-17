package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTerminalPolicyRecheckedAtTicketAttachAndBeforeInput(t *testing.T) {
	for _, atAttach := range []bool{true, false} {
		t.Run(map[bool]string{true: "attach", false: "input"}[atAttach], func(t *testing.T) {
			var denied atomic.Bool
			terminal := newEchoTerminal()
			broker := NewBroker(t.TempDir(), make([]byte, 32), func(context.Context, string, int, int) (AssetInfo, Terminal, error) {
				return AssetInfo{ID: "host", Name: "host", Username: "ops"}, terminal, nil
			})
			defer broker.CloseAll()
			created, e := broker.Create(context.Background(), CreateRequest{AssetID: "host", OperatorID: "operator", Cols: 80, Rows: 24, AccessPolicy: func(context.Context) error {
				if denied.Load() {
					return errSessionPolicyDenied
				}
				return nil
			}})
			require.NoError(t, e)
			denied.Store(atAttach)
			mux := http.NewServeMux()
			mux.HandleFunc("GET /ws/api/v1/sessions/{sessionID}/terminal", broker.ServeTerminal)
			server := httptest.NewServer(mux)
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, response, e := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+created.WebSocketURL, &websocket.DialOptions{Subprotocols: []string{TerminalSubprotocol, TicketSubprotocol(created.Ticket)}})
			if atAttach {
				require.Error(t, e)
				require.NotNil(t, response)
				assert.Equal(t, 403, response.StatusCode)
				response.Body.Close()
			} else {
				require.NoError(t, e)
				defer conn.CloseNow()
				denied.Store(true)
				require.NoError(t, conn.Write(ctx, websocket.MessageBinary, []byte("blocked\r")))
				_, _, e = conn.Read(ctx)
				require.Error(t, e)
			}
			require.Eventually(t, func() bool {
				records, _, _, e := broker.ListSessions(0, 10)
				return e == nil && len(records) == 1 && records[0].EndReason == "access_policy_denied"
			}, time.Second, 5*time.Millisecond)
		})
	}
}
