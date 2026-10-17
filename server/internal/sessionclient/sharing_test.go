package sessionclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSharingClientKeepsPlatformAuthOrganizationAndSecretsOutOfURLs(t *testing.T) {
	const org = "00000000-0000-0000-0000-000000000002"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NotContains(t, r.URL.String(), "synthetic-code")
		assert.NotContains(t, r.URL.String(), "synthetic-token")
		if strings.HasPrefix(r.URL.Path, "/ws/") {
			assert.Equal(t, org, r.URL.Query().Get("org"))
			assert.Contains(t, r.Header.Get("Sec-WebSocket-Protocol"), gateway.ShareSubprotocol)
			conn, e := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{gateway.ShareSubprotocol}})
			if !assert.NoError(t, e) {
				return
			}
			defer conn.CloseNow()
			_ = conn.Write(r.Context(), websocket.MessageBinary, []byte(strings.Repeat("x", 64*1024)))
			return
		}
		assert.Equal(t, "Bearer synthetic-token", r.Header.Get("Authorization"))
		assert.Equal(t, org, r.Header.Get("X-JMS-ORG"))
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/join"):
			var body map[string]string
			assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			assert.Equal(t, "synthetic-code", body["code"])
			_ = json.NewEncoder(w).Encode(gateway.SharedSession{CreatedSession: gateway.CreatedSession{SessionID: "abcdefghijklmnop", WebSocketURL: "/ws/api/v1/sessions/abcdefghijklmnop/share?org=" + org, Ticket: "synthetic-ticket"}})
		case strings.HasSuffix(r.URL.Path, "/share-events"):
			assert.Equal(t, "20", r.URL.Query().Get("offset"))
			assert.Equal(t, "10", r.URL.Query().Get("limit"))
			_, _ = w.Write([]byte(`{"results":[],"total":0,"offset":20,"limit":10}`))
		case strings.HasSuffix(r.URL.Path, "/shares") && r.Method == http.MethodPost:
			_, _ = w.Write([]byte(`{"id":"abcdefghijklmnop","code":"synthetic-code"}`))
		case strings.HasSuffix(r.URL.Path, "/shares"):
			_, _ = w.Write([]byte(`{"shares":[],"members":[],"controller":""}`))
		default:
			w.WriteHeader(204)
		}
	}))
	defer server.Close()
	c, e := New(server.URL, "synthetic-token")
	require.NoError(t, e)
	c, e = c.WithOrganization(org)
	require.NoError(t, e)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	invite, e := c.CreateShare(ctx, "abcdefghijklmnop", ShareInput{Mode: "read_only", Minutes: 10, Users: []string{"guest"}})
	require.NoError(t, e)
	assert.Equal(t, "synthetic-code", invite.Code)
	_, e = c.ShareState(ctx, "abcdefghijklmnop")
	require.NoError(t, e)
	joined, e := c.JoinShare(ctx, invite.ID, invite.Code)
	require.NoError(t, e)
	conn, e := c.DialSharedTerminal(ctx, joined)
	require.NoError(t, e)
	defer conn.CloseNow()
	_, data, e := conn.Read(ctx)
	require.NoError(t, e)
	assert.Len(t, data, 64*1024)
	require.NoError(t, c.ReclaimShare(ctx, "abcdefghijklmnop"))
	require.NoError(t, c.KickShareMember(ctx, "abcdefghijklmnop"))
	require.NoError(t, c.RevokeShare(ctx, "abcdefghijklmnop"))
	_, e = c.ShareEvents(ctx, "abcdefghijklmnop", 20, 10)
	require.NoError(t, e)
	joined.WebSocketURL = "wss://other.synthetic.invalid/ws/session"
	_, e = c.DialSharedTerminal(ctx, joined)
	require.Error(t, e)
}
