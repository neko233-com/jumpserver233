package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/sessionpolicy"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionShareAPIUsesPlatformIdentityWithoutGrantingAssetAccess(t *testing.T) {
	dir := t.TempDir()
	auth, e := coreauth.OpenService(filepath.Join(dir, "users.json"))
	require.NoError(t, e)
	_, e = auth.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, e)
	_, e = auth.CreateUser("share-guest", "synthetic-share-guest-233", coreauth.RoleOperator)
	require.NoError(t, e)
	admin, e := auth.Authenticate("admin", bootstrapPassword)
	require.NoError(t, e)
	guest, e := auth.Authenticate("share-guest", "synthetic-share-guest-233")
	require.NoError(t, e)
	inventory := testAssetService(t)
	a, e := inventory.Create(assets.Input{Name: "Shared QA", Host: "127.0.0.1", Port: 22, Username: "ops", Password: "synthetic-share-target-233", HostKeyFingerprint: validTestFingerprint()})
	require.NoError(t, e)
	rd, wr := io.Pipe()
	terminal := &liveTestTerminal{reader: rd, writer: wr}
	b := gateway.NewBroker(dir, make([]byte, 32), func(context.Context, string, int, int) (gateway.AssetInfo, gateway.Terminal, error) {
		return gateway.AssetInfo{ID: a.ID, Name: a.Name, Username: a.Username}, terminal, nil
	})
	defer b.CloseAll()
	b.SetSessionPolicy(func() sessionpolicy.Settings { return sessionpolicy.Settings{Sharing: true} })
	router := NewRouter("test", Dependencies{Auth: auth, Assets: inventory, Sessions: b})
	server := httptest.NewServer(router)
	defer server.Close()
	body := `{"asset_id":"` + a.ID + `","cols":80,"rows":24}`
	resp := doJSONRequest(t, router, "POST", "/api/v1/sessions", body, admin.AccessToken, "127.0.0.1:1234")
	require.Equal(t, 201, resp.Code)
	var session gateway.CreatedSession
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &session))
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	owner, _, e := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+session.WebSocketURL, &websocket.DialOptions{Subprotocols: []string{gateway.TerminalSubprotocol, gateway.TicketSubprotocol(session.Ticket)}})
	require.NoError(t, e)
	defer owner.CloseNow()
	path := "/api/v1/sessions/" + session.SessionID + "/shares"
	resp = doJSONRequest(t, router, "POST", path, `{"mode":"read_only","minutes":10,"users":["share-guest"]}`, guest.AccessToken, "127.0.0.1:1234")
	assert.Equal(t, 403, resp.Code)
	require.Eventually(t, func() bool {
		resp = doJSONRequest(t, router, "POST", path, `{"mode":"read_only","minutes":10,"users":["share-guest"]}`, admin.AccessToken, "127.0.0.1:1234")
		return resp.Code == 201
	}, time.Second, time.Millisecond)
	var created struct{ ID, Code string }
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &created))
	resp = doJSONRequest(t, router, "GET", path, "", admin.AccessToken, "127.0.0.1:1234")
	assert.Equal(t, 200, resp.Code)
	assert.NotContains(t, resp.Body.String(), created.Code)
	assert.Contains(t, resp.Body.String(), "share-guest")
	resp = doJSONRequest(t, router, "POST", "/api/v1/sessions", body, guest.AccessToken, "127.0.0.1:1234")
	assert.Equal(t, 403, resp.Code)
	joinPath := "/api/v1/session-shares/" + created.ID + "/join"
	resp = doJSONRequest(t, router, "POST", joinPath, `{"code":"wrong"}`, guest.AccessToken, "127.0.0.1:1234")
	assert.Equal(t, 404, resp.Code)
	resp = doJSONRequest(t, router, "POST", joinPath, `{"code":"`+created.Code+`"}`, guest.AccessToken, "127.0.0.1:1234")
	require.Equal(t, 201, resp.Code)
	assert.NotContains(t, resp.Body.String(), "synthetic-share-target-233")
	var joined gateway.SharedSession
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &joined))
	peer, _, e := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+joined.WebSocketURL, &websocket.DialOptions{Subprotocols: []string{gateway.ShareSubprotocol, gateway.TicketSubprotocol(joined.Ticket)}})
	require.NoError(t, e)
	defer peer.CloseNow()
	_, _, e = peer.Read(ctx)
	require.NoError(t, e)
	before := terminal.writes.Load()
	require.NoError(t, peer.Write(ctx, websocket.MessageBinary, []byte("injected")))
	_, _, e = peer.Read(ctx)
	require.Error(t, e)
	assert.Equal(t, before, terminal.writes.Load())
	resp = doJSONRequest(t, router, "DELETE", "/api/v1/session-shares/"+created.ID, "", guest.AccessToken, "127.0.0.1:1234")
	assert.Equal(t, 404, resp.Code)
	resp = doJSONRequest(t, router, "GET", "/api/v1/sessions/"+session.SessionID+"/share-events", "", guest.AccessToken, "127.0.0.1:1234")
	assert.Equal(t, 404, resp.Code)
	resp = doJSONRequest(t, router, "GET", "/api/v1/sessions/"+session.SessionID+"/share-events", "", admin.AccessToken, "127.0.0.1:1234")
	require.Equal(t, 200, resp.Code)
	assert.Contains(t, resp.Body.String(), "share_joined")
	assert.NotContains(t, resp.Body.String(), created.Code)
	resp = doJSONRequest(t, router, "POST", joinPath, `{"code":"`+created.Code+`"}`, guest.AccessToken, "198.51.100.4:1234")
	require.Equal(t, 201, resp.Code)
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &joined))
	_, denied, e := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+joined.WebSocketURL, &websocket.DialOptions{Subprotocols: []string{gateway.ShareSubprotocol, gateway.TicketSubprotocol(joined.Ticket)}})
	require.Error(t, e)
	require.NotNil(t, denied)
	assert.Equal(t, 403, denied.StatusCode)
	resp = doJSONRequest(t, router, "DELETE", "/api/v1/session-shares/"+created.ID, "", admin.AccessToken, "127.0.0.1:1234")
	assert.Equal(t, 204, resp.Code)
}
