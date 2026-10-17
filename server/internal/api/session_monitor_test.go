package api

import (
	"context"
	"io"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/neko233-com/jumpserver233/server/internal/core/groups"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type liveTestTerminal struct {
	reader *io.PipeReader
	writer *io.PipeWriter
	writes atomic.Int32
}

func (p *liveTestTerminal) Read(b []byte) (int, error)  { return p.reader.Read(b) }
func (p *liveTestTerminal) Write(b []byte) (int, error) { p.writes.Add(1); return p.writer.Write(b) }
func (p *liveTestTerminal) Close() error                { _ = p.writer.Close(); return p.reader.Close() }
func (p *liveTestTerminal) Resize(int, int) error       { return nil }

func TestSSHLiveAuthorizationRechecksCurrentState(t *testing.T) {
	for _, mode := range []string{"grant", "group", "role", "credential", "organization", "ticket_attach"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			auth, e := coreauth.OpenService(filepath.Join(dir, "users.json"))
			require.NoError(t, e)
			_, e = auth.Bootstrap("admin", bootstrapPassword)
			require.NoError(t, e)
			u, e := auth.CreateUser("live-operator", "synthetic-live-operator-233", coreauth.RoleOperator)
			require.NoError(t, e)
			login, e := auth.Authenticate(u.Username, "synthetic-live-operator-233")
			require.NoError(t, e)
			inventory := testAssetService(t)
			input := assets.Input{Name: "Live QA", Host: "127.0.0.1", Port: 22, Username: "ops", Password: "synthetic-live-target-233", HostKeyFingerprint: validTestFingerprint()}
			a, e := inventory.Create(input)
			require.NoError(t, e)
			grantStore, e := grants.OpenStore(filepath.Join(dir, "grants.json"))
			require.NoError(t, e)
			groupStore, e := groups.OpenStore(filepath.Join(dir, "groups.json"))
			require.NoError(t, e)
			roles, e := rbac.Open(filepath.Join(dir, "rbac.json"), nil)
			require.NoError(t, e)
			grantInput := grants.Input{UserID: u.ID, AssetID: a.ID, Account: a.Username, Actions: []string{"connect"}}
			var groupID string
			if mode == "group" {
				g, e := groupStore.Create("live-group", "live QA")
				require.NoError(t, e)
				groupID = g.ID
				_, e = groupStore.AddMember(g.ID, u.ID)
				require.NoError(t, e)
				grantInput.UserID, grantInput.GroupID = "", g.ID
			}
			grant, e := grantStore.Create(grantInput, "admin")
			require.NoError(t, e)
			var binding rbac.Binding
			if mode == "role" {
				require.NoError(t, grantStore.Delete(grant.ID))
				role, e := roles.SaveRole("", rbac.RoleInput{Name: "live-connect", Permissions: []string{"assets.connect_all"}}, "admin", "admin")
				require.NoError(t, e)
				binding, e = roles.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: u.ID, RoleIDs: []string{role.ID}}, "admin", "admin")
				require.NoError(t, e)
			}
			reader, writer := io.Pipe()
			terminal := &liveTestTerminal{reader: reader, writer: writer}
			broker := gateway.NewBroker(dir, make([]byte, 32), func(context.Context, string, int, int) (gateway.AssetInfo, gateway.Terminal, error) {
				return gateway.AssetInfo{ID: a.ID, Name: a.Name, Username: a.Username}, terminal, nil
			})
			defer broker.CloseAll()
			var denied atomic.Bool
			server := httptest.NewServer(NewRouter("test", Dependencies{Auth: auth, Assets: inventory, Grants: grantStore, Groups: groupStore, RBAC: roles, Sessions: broker, OrganizationAllowed: func(coreauth.User) bool { return !denied.Load() }}))
			defer server.Close()
			client, e := sessionclient.New(server.URL, login.AccessToken)
			require.NoError(t, e)
			ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			s, e := client.CreateSession(ctx, gateway.CreateRequest{AssetID: a.ID, Cols: 80, Rows: 24})
			require.NoError(t, e)
			var conn *websocket.Conn
			if mode != "ticket_attach" {
				conn, e = client.DialTerminal(ctx, s)
				require.NoError(t, e)
				defer conn.CloseNow()
			}
			switch mode {
			case "grant", "ticket_attach":
				require.NoError(t, grantStore.Delete(grant.ID))
			case "group":
				_, e = groupStore.RemoveMember(groupID, u.ID)
				require.NoError(t, e)
			case "role":
				_, e = roles.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: u.ID, Revision: binding.Revision}, "admin", "admin")
				require.NoError(t, e)
			case "credential":
				input.Password = "synthetic-live-replaced-233"
				_, e = inventory.Update(a.ID, input)
				require.NoError(t, e)
			case "organization":
				denied.Store(true)
			}
			if mode == "ticket_attach" {
				_, e = client.DialTerminal(ctx, s)
				require.Error(t, e)
			} else {
				require.NoError(t, conn.Write(ctx, websocket.MessageBinary, []byte("must not execute\r")))
				_, _, e = conn.Read(ctx)
				require.Error(t, e)
			}
			assert.Zero(t, terminal.writes.Load())
			require.Eventually(t, func() bool {
				rows, _, _, e := broker.ListSessions(0, 10)
				return e == nil && len(rows) == 1 && rows[0].EndReason == "access_policy_denied"
			}, time.Second, time.Millisecond)
		})
	}
}

func TestMonitorAPIRequiresSeparatePermissionAndRevokesLiveViewer(t *testing.T) {
	dir := t.TempDir()
	auth, e := coreauth.OpenService(filepath.Join(dir, "users.json"))
	require.NoError(t, e)
	owner, e := auth.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, e)
	viewer, e := auth.CreateUser("monitor-reviewer", "synthetic-monitor-reviewer-233", coreauth.RoleOperator)
	require.NoError(t, e)
	login, e := auth.Authenticate(viewer.Username, "synthetic-monitor-reviewer-233")
	require.NoError(t, e)
	roles, e := rbac.Open(filepath.Join(dir, "rbac.json"), nil)
	require.NoError(t, e)
	reader, writer := io.Pipe()
	terminal := &liveTestTerminal{reader: reader, writer: writer}
	broker := gateway.NewBroker(dir, make([]byte, 32), func(context.Context, string, int, int) (gateway.AssetInfo, gateway.Terminal, error) {
		return gateway.AssetInfo{ID: "qa", Name: "qa", Username: "ops"}, terminal, nil
	})
	defer broker.CloseAll()
	s, e := broker.Create(context.Background(), gateway.CreateRequest{AssetID: "qa", OperatorID: owner.ID, Cols: 80, Rows: 24})
	require.NoError(t, e)
	server := httptest.NewServer(NewRouter("test", Dependencies{Auth: auth, Sessions: broker, RBAC: roles}))
	defer server.Close()
	ctx, stop := context.WithTimeout(context.Background(), 6*time.Second)
	defer stop()
	base := "ws" + strings.TrimPrefix(server.URL, "http")
	primary, _, e := websocket.Dial(ctx, base+s.WebSocketURL, &websocket.DialOptions{Subprotocols: []string{gateway.TerminalSubprotocol, gateway.TicketSubprotocol(s.Ticket)}})
	require.NoError(t, e)
	defer primary.CloseNow()
	client, e := sessionclient.New(server.URL, login.AccessToken)
	require.NoError(t, e)
	path := "/api/v1/sessions/" + s.SessionID + "/monitor"
	var ticket gateway.CreatedSession
	_, e = roles.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: viewer.ID, RoleIDs: []string{"auditor"}}, "admin", "admin")
	require.NoError(t, e)
	assert.Error(t, client.DatabaseRequest(ctx, "POST", path, "", nil, &ticket))
	role, e := roles.SaveRole("", rbac.RoleInput{Name: "live-reviewer", Permissions: []string{"audit.sessions.monitor_all"}}, "admin", "admin")
	require.NoError(t, e)
	binding, e := roles.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: viewer.ID, RoleIDs: []string{role.ID}, Revision: 1}, "admin", "admin")
	require.NoError(t, e)
	require.NoError(t, client.DatabaseRequest(ctx, "POST", path, "", nil, &ticket))
	monitor, _, e := websocket.Dial(ctx, base+ticket.WebSocketURL, &websocket.DialOptions{Subprotocols: []string{gateway.MonitorSubprotocol, gateway.TicketSubprotocol(ticket.Ticket)}})
	require.NoError(t, e)
	defer monitor.CloseNow()
	_, _, e = monitor.Read(ctx)
	require.NoError(t, e)
	_, e = roles.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: viewer.ID, Revision: binding.Revision}, "admin", "admin")
	require.NoError(t, e)
	_, _, e = monitor.Read(ctx)
	require.Error(t, e)
	require.NoError(t, primary.Write(ctx, websocket.MessageBinary, []byte("unaffected")))
	_, data, e := primary.Read(ctx)
	require.NoError(t, e)
	assert.Equal(t, "unaffected", string(data))
}
