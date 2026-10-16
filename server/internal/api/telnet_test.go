package api

import (
	"context"
	"encoding/json"
	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/neko233-com/jumpserver233/server/testsupport/telnetfixture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeTelnetAPIReviewOwnershipCommandDenyAndRevocation(t *testing.T) {
	target := telnetfixture.Load(t, false)
	root := t.TempDir()
	auth, e := coreauth.OpenService(filepath.Join(root, "users.json"))
	require.NoError(t, e)
	_, e = auth.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, e)
	owner, e := auth.CreateUser("telnet-owner", "synthetic-telnet-owner-1234", coreauth.RoleOperator)
	require.NoError(t, e)
	other, e := auth.CreateUser("telnet-other", "synthetic-telnet-other-1234", coreauth.RoleOperator)
	require.NoError(t, e)
	login, e := auth.Authenticate(owner.Username, "synthetic-telnet-owner-1234")
	require.NoError(t, e)
	foreign, e := auth.Authenticate(other.Username, "synthetic-telnet-other-1234")
	require.NoError(t, e)
	inventory := testAssetService(t)
	required := true
	a, e := inventory.Create(assets.Input{Name: "Telnet QA", Protocol: assets.ProtocolTelnet, Host: target.Host, Port: target.Port, Username: telnetfixture.Username, Password: telnetfixture.Password, Telnet: &target.Settings, LoginReviewRequired: &required})
	require.NoError(t, e)
	g, e := grants.OpenStore(filepath.Join(root, "grants.json"))
	require.NoError(t, e)
	reviews, e := accessreviews.OpenStore(filepath.Join(root, "reviews.json"))
	require.NoError(t, e)
	filters, e := commandfilters.OpenStore(filepath.Join(root, "filters.json"))
	require.NoError(t, e)
	_, e = filters.Create(commandfilters.Input{Name: "deny Telnet command", UserID: owner.ID, AssetID: a.ID, Account: a.Username, Match: "exact", Pattern: "forbidden-telnet-command", Action: "deny"}, "admin")
	require.NoError(t, e)
	broker := gateway.NewBroker(root, make([]byte, 32), nil)
	defer broker.CloseAll()
	server := httptest.NewServer(NewRouter("test", Dependencies{Assets: inventory, Auth: auth, Grants: g, AccessReviews: reviews, CommandFilters: filters, Sessions: broker}))
	defer server.Close()
	client, e := sessionclient.New(server.URL, login.AccessToken)
	require.NoError(t, e)
	ctx, stop := context.WithTimeout(context.Background(), 25*time.Second)
	defer stop()
	request := gateway.CreateRequest{AssetID: a.ID, Protocol: assets.ProtocolTelnet, Cols: 90, Rows: 30}
	view, e := g.Create(grants.Input{UserID: owner.ID, AssetID: a.ID, Account: a.Username, Actions: []string{"view"}}, "admin")
	require.NoError(t, e)
	_, e = client.CreateSession(ctx, request)
	require.Error(t, e)
	require.NoError(t, g.Delete(view.ID))
	grant, e := g.Create(grants.Input{UserID: owner.ID, AssetID: a.ID, Account: a.Username, Actions: []string{"connect"}}, "admin")
	require.NoError(t, e)
	sshReview, e := reviews.RequestAction(owner.ID, owner.Username, a.ID, a.Name, a.Username, accessreviews.ActionSSH)
	require.NoError(t, e)
	require.NoError(t, reviews.Resolve(sshReview.ID, "admin", true))
	_, e = client.CreateSession(ctx, request)
	var pending *sessionclient.AccessReviewPendingError
	require.ErrorAs(t, e, &pending)
	require.NoError(t, reviews.Resolve(pending.ReviewID, "admin", true))
	session, e := client.CreateSession(ctx, request)
	require.NoError(t, e)
	approved, e := reviews.ConsumeApprovedAction(owner.ID, a.ID, a.Username, accessreviews.ActionSSH)
	require.NoError(t, e)
	assert.True(t, approved)
	conn, e := client.DialTerminal(ctx, session)
	require.NoError(t, e)
	defer conn.CloseNow()
	var output strings.Builder
	for !strings.Contains(output.String(), "$ ") {
		_, data, e := conn.Read(ctx)
		require.NoError(t, e)
		output.Write(data)
	}
	require.NoError(t, conn.Write(ctx, websocket.MessageBinary, []byte("forbidden-telnet-command\r")))
	for {
		typ, data, e := conn.Read(ctx)
		require.NoError(t, e)
		if typ == websocket.MessageText && strings.Contains(string(data), "command_blocked") {
			break
		}
	}
	commands, total, e := broker.ListCommands(session.SessionID, 0, 20)
	require.NoError(t, e)
	require.Equal(t, 1, total)
	assert.Equal(t, "blocked", commands[0].Outcome)
	foreignClient, e := sessionclient.New(server.URL, foreign.AccessToken)
	require.NoError(t, e)
	_, e = foreignClient.CreateSession(ctx, request)
	require.Error(t, e)
	records, _, _, e := broker.ListSessionsForOperator(other.ID, 0, 20)
	require.NoError(t, e)
	assert.Empty(t, records)
	require.NoError(t, g.Delete(grant.ID))
	_ = conn.Write(ctx, websocket.MessageBinary, []byte("echo revoked\r"))
	for {
		_, _, e = conn.Read(ctx)
		if e != nil {
			break
		}
	}
	require.Eventually(t, func() bool {
		r, _, _, e := broker.ListSessions(0, 20)
		return e == nil && len(r) == 1 && r[0].Status == "ended"
	}, time.Second, 5*time.Millisecond)
	records, _, _, e = broker.ListSessions(0, 20)
	require.NoError(t, e)
	assert.Equal(t, assets.ProtocolTelnet, records[0].Protocol)
	raw, e := json.Marshal(records)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), telnetfixture.Password)
}
