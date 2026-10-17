package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/connector/rdpclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/desktop"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type monitorTestDisplay struct {
	done   chan struct{}
	once   sync.Once
	inputs atomic.Int32
}

func (d *monitorTestDisplay) Close() error          { d.once.Do(func() { close(d.done) }); return nil }
func (d *monitorTestDisplay) Done() <-chan struct{} { return d.done }
func (d *monitorTestDisplay) Snapshot() (rdpclient.Frame, error) {
	return rdpclient.Frame{Sequence: 1, PNG: []byte("synthetic monitor PNG"), Width: 320, Height: 200}, nil
}
func (d *monitorTestDisplay) Input(rdpclient.Input) error          { d.inputs.Add(1); return nil }
func (d *monitorTestDisplay) SetClipboardGuard(func(string) error) {}
func (d *monitorTestDisplay) ClipboardSnapshot() rdpclient.ClipboardState {
	return rdpclient.ClipboardState{Revision: 1, Text: "owner clipboard must not reach the viewer"}
}

func TestDesktopMonitorAPIRequiresExplicitDesktopPermissionAndRechecksIdentity(t *testing.T) {
	dir := t.TempDir()
	auth, e := coreauth.OpenService(filepath.Join(dir, "users.json"))
	require.NoError(t, e)
	owner, e := auth.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, e)
	viewer, e := auth.CreateUser("desktop-reviewer", "synthetic-desktop-reviewer-233", coreauth.RoleOperator)
	require.NoError(t, e)
	login, e := auth.Authenticate(viewer.Username, "synthetic-desktop-reviewer-233")
	require.NoError(t, e)
	roles, e := rbac.Open(filepath.Join(dir, "rbac.json"), nil)
	require.NoError(t, e)
	inventory := testAssetService(t)
	a, e := inventory.Create(assets.Input{Name: "Desktop QA", Protocol: assets.ProtocolRDP, Host: "127.0.0.1", Port: 3389, Username: "ops", Password: "synthetic-desktop-target-233", RDP: &rdpclient.Settings{Security: "tls"}})
	require.NoError(t, e)
	b, e := desktop.New(dir, make([]byte, 32))
	require.NoError(t, e)
	defer b.CloseAll()
	display := &monitorTestDisplay{done: make(chan struct{})}
	s, e := b.Create(context.Background(), desktop.Request{Record: desktop.Record{AssetID: a.ID, AssetName: a.Name, OperatorID: owner.ID, Operator: owner.Username}, Open: func(context.Context) (desktop.Display, error) { return display, nil }, Guard: func(context.Context, string) error { return nil }})
	require.NoError(t, e)
	var membershipDenied atomic.Bool
	router := NewRouter("test", Dependencies{Auth: auth, Assets: inventory, Desktops: b, RBAC: roles, OrganizationAllowed: func(u coreauth.User) bool { return u.ID != viewer.ID || !membershipDenied.Load() }})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if source := r.Header.Get("X-QA-Remote-Addr"); source != "" {
			r.RemoteAddr = source
		}
		router.ServeHTTP(w, r)
	}))
	defer server.Close()
	ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	base := "ws" + strings.TrimPrefix(server.URL, "http")
	primary, _, e := websocket.Dial(ctx, base+s.URL, &websocket.DialOptions{Subprotocols: []string{desktop.Subprotocol, desktop.TicketPrefix + s.Ticket}})
	require.NoError(t, e)
	defer primary.CloseNow()
	_, _, e = primary.Read(ctx)
	require.NoError(t, e)
	client, e := sessionclient.New(server.URL, login.AccessToken)
	require.NoError(t, e)
	_, e = client.CreateDesktopMonitor(ctx, s.ID)
	require.Error(t, e)
	role, e := roles.SaveRole("", rbac.RoleInput{Name: "terminal-review-only", Permissions: []string{"audit.sessions.monitor_all", "audit.sessions.view_all", "audit.replays.view_all"}}, "admin", "admin")
	require.NoError(t, e)
	binding, e := roles.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: viewer.ID, RoleIDs: []string{role.ID}}, "admin", "admin")
	require.NoError(t, e)
	_, e = client.CreateDesktopMonitor(ctx, s.ID)
	require.Error(t, e, "terminal and metadata permissions cannot expose desktop pixels")
	e = client.DatabaseRequest(ctx, "GET", "/api/v1/desktop-sessions/"+s.ID+"/frames/0", "", nil, nil)
	require.Error(t, e, "historical replay permission cannot bypass live monitor permission")
	role, e = roles.SaveRole("", rbac.RoleInput{Name: "desktop-review", Permissions: []string{"audit.desktops.monitor_all"}}, "admin", "admin")
	require.NoError(t, e)
	binding, e = roles.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: viewer.ID, RoleIDs: []string{role.ID}, Revision: binding.Revision}, "admin", "admin")
	require.NoError(t, e)
	wrongSource, e := client.CreateDesktopMonitor(ctx, s.ID)
	require.NoError(t, e)
	_, response, e := websocket.Dial(ctx, base+wrongSource.URL, &websocket.DialOptions{HTTPHeader: http.Header{"X-QA-Remote-Addr": {"192.0.2.15:12345"}}, Subprotocols: []string{desktop.MonitorSubprotocol, desktop.MonitorTicketPrefix + wrongSource.Ticket}})
	require.Error(t, e)
	assert.Equal(t, 403, response.StatusCode)
	badRequest, e := http.NewRequestWithContext(ctx, "POST", server.URL+"/api/v1/desktop-sessions/"+s.ID+"/monitor", nil)
	require.NoError(t, e)
	badRequest.Header.Set("Authorization", "Bearer "+login.AccessToken)
	badRequest.Header.Set("X-QA-Remote-Addr", "unknown")
	badResponse, e := http.DefaultClient.Do(badRequest)
	require.NoError(t, e)
	badResponse.Body.Close()
	assert.Equal(t, 404, badResponse.StatusCode)
	created, e := client.CreateDesktopMonitor(ctx, s.ID)
	require.NoError(t, e)
	raw, e := json.Marshal(created)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "synthetic-desktop-target-233")
	assert.NotContains(t, created.URL, created.Ticket)
	monitor, e := client.DialDesktopMonitor(ctx, created)
	require.NoError(t, e)
	defer monitor.CloseNow()
	_, ready, e := monitor.Read(ctx)
	require.NoError(t, e)
	assert.Contains(t, string(ready), `"clipboard":false`)
	kind, frame, e := monitor.Read(ctx)
	require.NoError(t, e)
	assert.Equal(t, websocket.MessageBinary, kind)
	assert.Contains(t, string(frame), "synthetic monitor PNG")
	assert.NotContains(t, string(frame), "owner clipboard")
	_, e = client.CreateDesktop(ctx, a.ID)
	require.Error(t, e, "monitoring must not grant independent connections")
	membershipDenied.Store(true)
	for i := 0; i < 10; i++ {
		_, _, e = monitor.Read(ctx)
		if e != nil {
			break
		}
	}
	require.Error(t, e, "organization membership revocation must close an attached viewer")
	_, e = client.CreateDesktopMonitor(ctx, s.ID)
	require.Error(t, e)
	membershipDenied.Store(false)
	created, e = client.CreateDesktopMonitor(ctx, s.ID)
	require.NoError(t, e)
	monitor, e = client.DialDesktopMonitor(ctx, created)
	require.NoError(t, e)
	defer monitor.CloseNow()
	_, _, e = monitor.Read(ctx)
	require.NoError(t, e)
	_, e = roles.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: viewer.ID, Revision: binding.Revision}, "admin", "admin")
	require.NoError(t, e)
	for i := 0; i < 10; i++ {
		_, _, e = monitor.Read(ctx)
		if e != nil {
			break
		}
	}
	require.Error(t, e)
	require.NoError(t, primary.Write(ctx, websocket.MessageText, []byte(`{"type":"key","code":30,"down":true}`)))
	require.Eventually(t, func() bool { return display.inputs.Load() == 1 }, time.Second, time.Millisecond)
	rows, e := b.List(owner.ID, false)
	require.NoError(t, e)
	require.Len(t, rows, 1)
	assert.Equal(t, "active", rows[0].Status)
}
