package desktop

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/core/sessionpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func desktopMonitorFixture(t *testing.T) (*Broker, Created, *fakeDisplay, *websocket.Conn, string, context.Context) {
	t.Helper()
	b, e := New(t.TempDir(), make([]byte, 32))
	require.NoError(t, e)
	t.Cleanup(b.CloseAll)
	d := &fakeDisplay{done: make(chan struct{})}
	s, e := b.Create(context.Background(), Request{Record: Record{AssetID: "qa", OperatorID: "owner", Operator: "operator"}, Open: func(context.Context) (Display, error) { return d, nil }, Guard: func(context.Context, string) error { return nil }})
	require.NoError(t, e)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ws/desktop/{sessionID}", b.ServeWS)
	mux.HandleFunc("GET /ws/desktop/{sessionID}/monitor", b.ServeMonitor)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	ctx, stop := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(stop)
	base := "ws" + strings.TrimPrefix(server.URL, "http")
	owner, _, e := websocket.Dial(ctx, base+s.URL, &websocket.DialOptions{Subprotocols: []string{Subprotocol, TicketPrefix + s.Ticket}})
	require.NoError(t, e)
	t.Cleanup(func() { owner.CloseNow() })
	_, _, e = owner.Read(ctx)
	require.NoError(t, e)
	return b, s, d, owner, base, ctx
}
func desktopMonitorRequest(id string) MonitorRequest {
	return MonitorRequest{SessionID: id, ViewerID: "reviewer", Viewer: "Reviewer", AllowAll: true, Guard: func(context.Context, Record) error { return nil }}
}
func dialMonitor(t *testing.T, ctx context.Context, base string, s Created) *websocket.Conn {
	t.Helper()
	c, _, e := websocket.Dial(ctx, base+s.URL, &websocket.DialOptions{Subprotocols: []string{MonitorSubprotocol, MonitorTicketPrefix + s.Ticket}})
	require.NoError(t, e)
	t.Cleanup(func() { c.CloseNow() })
	return c
}
func monitorMustClose(t *testing.T, ctx context.Context, c *websocket.Conn) {
	t.Helper()
	for i := 0; i < 10; i++ {
		if _, _, e := c.Read(ctx); e != nil {
			return
		}
	}
	t.Fatal("desktop viewer remained connected")
}

func TestDesktopMonitorReadOnlyTicketSeparationAndDurableAudit(t *testing.T) {
	b, s, d, owner, base, ctx := desktopMonitorFixture(t)
	in := desktopMonitorRequest(s.ID)
	in.AllowAll = false
	_, e := b.CreateMonitor(ctx, in)
	assert.ErrorIs(t, e, ErrNotFound)
	in.AllowAll = true
	m, e := b.CreateMonitor(ctx, in)
	require.NoError(t, e)
	viewer := dialMonitor(t, ctx, base, m)
	kind, meta, e := viewer.Read(ctx)
	require.NoError(t, e)
	assert.Equal(t, websocket.MessageText, kind)
	assert.Contains(t, string(meta), `"read_only":true`)
	assert.Contains(t, string(meta), `"clipboard":false`)
	kind, frame, e := viewer.Read(ctx)
	require.NoError(t, e)
	assert.Equal(t, websocket.MessageBinary, kind)
	kind, original, e := owner.Read(ctx)
	require.NoError(t, e)
	assert.Equal(t, websocket.MessageBinary, kind)
	assert.Equal(t, original, frame)
	_, e = b.Frame(s.ID, "history-reader", true, 0)
	assert.ErrorIs(t, e, ErrNotFound)
	_, response, e := websocket.Dial(ctx, base+m.URL, &websocket.DialOptions{Subprotocols: []string{MonitorSubprotocol, MonitorTicketPrefix + m.Ticket}})
	require.Error(t, e)
	assert.Equal(t, 401, response.StatusCode)
	_, response, e = websocket.Dial(ctx, base+s.URL, &websocket.DialOptions{Subprotocols: []string{Subprotocol, TicketPrefix + m.Ticket}})
	require.Error(t, e)
	assert.Equal(t, 401, response.StatusCode)
	_, response, e = websocket.Dial(ctx, base+m.URL, &websocket.DialOptions{Subprotocols: []string{MonitorSubprotocol, MonitorTicketPrefix + s.Ticket}})
	require.Error(t, e)
	assert.Equal(t, 401, response.StatusCode)
	require.NoError(t, viewer.Write(ctx, websocket.MessageText, []byte(`{"type":"clipboard_read"}`)))
	monitorMustClose(t, ctx, viewer)
	assert.Zero(t, d.inputs.Load())
	require.NoError(t, owner.Write(ctx, websocket.MessageText, []byte(`{"type":"key","code":30,"down":true}`)))
	require.Eventually(t, func() bool { return d.inputs.Load() == 1 }, time.Second, time.Millisecond)
	require.Eventually(t, func() bool {
		rows, total, e := b.ListMonitorEvents(s.ID, "owner", false, 0, 10)
		return e == nil && total == 2 && rows[0].Event == "monitor_ended"
	}, time.Second, time.Millisecond)
	rows, total, e := b.ListMonitorEvents(s.ID, "owner", false, 1, 1)
	require.NoError(t, e)
	assert.Equal(t, 2, total)
	require.Len(t, rows, 1)
	assert.Equal(t, "monitor_started", rows[0].Event)
	raw, e := json.Marshal(rows)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), m.Ticket)
	assert.NotContains(t, string(raw), "synthetic graphical frame")
	_, _, e = b.ListMonitorEvents(s.ID, "reviewer", false, 0, 10)
	assert.ErrorIs(t, e, ErrNotFound)
	reopened, e := New(filepath.Dir(b.root), make([]byte, 32))
	require.NoError(t, e)
	defer reopened.CloseAll()
	_, total, e = reopened.ListMonitorEvents(s.ID, "owner", false, 0, 10)
	require.NoError(t, e)
	assert.Equal(t, 2, total)
}
func TestDesktopMonitorRevocationAndIdleNeverTouchPrimaryInput(t *testing.T) {
	b, s, d, owner, base, ctx := desktopMonitorFixture(t)
	var denied atomic.Bool
	in := desktopMonitorRequest(s.ID)
	in.Guard = func(context.Context, Record) error {
		if denied.Load() {
			return ErrNotFound
		}
		return nil
	}
	m, e := b.CreateMonitor(ctx, in)
	require.NoError(t, e)
	viewer := dialMonitor(t, ctx, base, m)
	_, _, e = viewer.Read(ctx)
	require.NoError(t, e)
	_, _, e = viewer.Read(ctx)
	require.NoError(t, e)
	b.mu.Lock()
	a := b.live[s.ID]
	b.mu.Unlock()
	a.mu.Lock()
	before := a.lastInput
	a.mu.Unlock()
	denied.Store(true)
	monitorMustClose(t, ctx, viewer)
	a.mu.Lock()
	assert.Equal(t, before, a.lastInput)
	a.mu.Unlock()
	assert.Zero(t, d.inputs.Load())
	require.NoError(t, owner.Write(ctx, websocket.MessageText, []byte(`{"type":"key","code":30,"down":true}`)))
	require.Eventually(t, func() bool { return d.inputs.Load() == 1 }, time.Second, time.Millisecond)
	a.mu.Lock()
	a.lastInput = time.Now().Add(-2 * time.Minute)
	a.mu.Unlock()
	b.SetSessionPolicy(func() sessionpolicy.Settings { return sessionpolicy.Settings{IdleMinutes: 1} })
	_, e = b.CreateMonitor(ctx, desktopMonitorRequest(s.ID))
	assert.ErrorIs(t, e, ErrNotFound)
}
func TestDesktopMonitorCapacityExpiryAuditFailureAndParentClose(t *testing.T) {
	b, s, d, owner, base, ctx := desktopMonitorFixture(t)
	var tickets []Created
	for i := 0; i < maxSessionMonitors; i++ {
		m, e := b.CreateMonitor(ctx, desktopMonitorRequest(s.ID))
		require.NoError(t, e)
		tickets = append(tickets, m)
	}
	_, e := b.CreateMonitor(ctx, desktopMonitorRequest(s.ID))
	assert.ErrorIs(t, e, ErrMonitorCapacity)
	b.mu.Lock()
	expired := b.monitors[sha256.Sum256([]byte(tickets[0].Ticket))]
	expired.expires = time.Now().Add(-time.Second)
	b.mu.Unlock()
	_, response, e := websocket.Dial(ctx, base+tickets[0].URL, &websocket.DialOptions{Subprotocols: []string{MonitorSubprotocol, MonitorTicketPrefix + tickets[0].Ticket}})
	require.Error(t, e)
	assert.Equal(t, 401, response.StatusCode)
	b.mu.Lock()
	for _, m := range b.monitors {
		b.stopMonitorLocked(m)
	}
	b.mu.Unlock()
	require.NoError(t, os.Mkdir(filepath.Join(b.root, s.ID, "monitors.jsonl"), 0700))
	m, e := b.CreateMonitor(ctx, desktopMonitorRequest(s.ID))
	require.NoError(t, e)
	viewer := dialMonitor(t, ctx, base, m)
	monitorMustClose(t, ctx, viewer)
	assert.Zero(t, d.inputs.Load())
	require.NoError(t, owner.Write(ctx, websocket.MessageText, []byte(`{"type":"key","code":30,"down":true}`)))
	require.Eventually(t, func() bool { return d.inputs.Load() == 1 }, time.Second, time.Millisecond)
	require.NoError(t, os.Remove(filepath.Join(b.root, s.ID, "monitors.jsonl")))
	m, e = b.CreateMonitor(ctx, desktopMonitorRequest(s.ID))
	require.NoError(t, e)
	viewer = dialMonitor(t, ctx, base, m)
	_, _, e = viewer.Read(ctx)
	require.NoError(t, e)
	require.NoError(t, b.Stop(s.ID, "owner", false))
	monitorMustClose(t, ctx, viewer)
	_, e = b.Frame(s.ID, "history-reader", true, 0)
	require.NoError(t, e, "ended-session replay remains available with historical authority")
	b.mu.Lock()
	assert.Empty(t, b.monitors)
	b.mu.Unlock()
}

func TestDesktopMonitorAuditRejectsPartialTailAndNewStartsAtLimit(t *testing.T) {
	b, s, _, owner, _, ctx := desktopMonitorFixture(t)
	_ = owner
	created, e := b.CreateMonitor(ctx, desktopMonitorRequest(s.ID))
	require.NoError(t, e)
	b.mu.Lock()
	m := b.monitors[sha256.Sum256([]byte(created.Ticket))]
	b.mu.Unlock()
	path := filepath.Join(b.root, s.ID, "monitors.jsonl")
	require.NoError(t, os.WriteFile(path, []byte(`{"event":"incomplete"`), 0600))
	assert.ErrorIs(t, b.appendMonitorEvent(m, "monitor_started"), ErrMonitorAudit)
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.Equal(t, `{"event":"incomplete"`, string(raw))
	f, e := os.OpenFile(path, os.O_RDWR|os.O_TRUNC, 0600)
	require.NoError(t, e)
	require.NoError(t, f.Truncate(maxMonitorAuditBytes))
	_, e = f.WriteAt([]byte{'\n'}, maxMonitorAuditBytes-1)
	require.NoError(t, e)
	require.NoError(t, f.Close())
	assert.ErrorIs(t, b.appendMonitorEvent(m, "monitor_started"), ErrMonitorAudit)
	require.NoError(t, b.appendMonitorEvent(m, "monitor_ended"), "capacity must reserve durable exits")
	_, _, e = owner.Read(ctx)
	require.NoError(t, e, "audit refusal does not interrupt the primary desktop")
}

func TestDesktopWireFramesReuseTheSamePacket(t *testing.T) {
	d := &pngDisplay{png: []byte("same immutable PNG")}
	a := &active{display: d}
	sequence, first, e := a.wireFrame()
	require.NoError(t, e)
	assert.EqualValues(t, 1, sequence)
	_, second, e := a.wireFrame()
	require.NoError(t, e)
	assert.True(t, &first[0] == &second[0])
	assert.Zero(t, testing.AllocsPerRun(25, func() { _, _, _ = a.wireFrame() }))
	assert.Equal(t, "same immutable PNG", string(second[8:]))
}
