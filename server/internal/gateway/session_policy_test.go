package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/core/sessionpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdatedPolicyExpiresActiveTerminalAndMonitorWithoutInput(t *testing.T) {
	b, created, owner, base, ctx := monitorFixture(t)
	store, err := sessionpolicy.Open(filepath.Join(t.TempDir(), "policy.json"), nil)
	require.NoError(t, err)
	b.SetSessionPolicy(store.Snapshot)
	m, err := b.CreateMonitor(ctx, MonitorRequest{SessionID: created.SessionID, ViewerID: "owner", AccessPolicy: func(context.Context) error { return nil }})
	require.NoError(t, err)
	viewer, _, err := websocket.Dial(ctx, base+m.WebSocketURL, &websocket.DialOptions{Subprotocols: []string{MonitorSubprotocol, TicketSubprotocol(m.Ticket)}})
	require.NoError(t, err)
	defer viewer.CloseNow()
	_, _, err = viewer.Read(ctx) // initial dimensions
	require.NoError(t, err)
	b.mu.Lock()
	b.sessions[created.SessionID].lastInput = time.Now().Add(-2 * time.Minute)
	b.mu.Unlock()
	updated := store.Snapshot()
	updated.IdleMinutes = 1
	_, err = store.Save(updated, "admin", "admin")
	require.NoError(t, err)
	readCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, _, err = owner.Read(readCtx)
	require.Error(t, err)
	_, _, err = viewer.Read(readCtx)
	require.Error(t, err)
	require.Eventually(t, func() bool {
		rows, _, _, err := b.ListSessions(0, 10)
		return err == nil && len(rows) == 1 && rows[0].EndReason == "idle_timeout"
	}, time.Second, time.Millisecond)
}

func TestTerminalPolicyIdleDurationAndResizeDoesNotKeepAlive(t *testing.T) {
	for _, max := range []bool{false, true} {
		t.Run(map[bool]string{false: "idle", true: "duration"}[max], func(t *testing.T) {
			b, s, conn, _, ctx := monitorFixture(t)
			policy := sessionpolicy.Settings{IdleMinutes: 1}
			if max {
				policy = sessionpolicy.Settings{MaxHours: 1}
			}
			b.SetSessionPolicy(func() sessionpolicy.Settings { return policy })
			b.mu.Lock()
			live := b.sessions[s.SessionID]
			live.lastInput = time.Now().Add(-2 * time.Minute)
			if max {
				live.startedAt = time.Now().Add(-2 * time.Hour)
			}
			b.mu.Unlock()
			// Resize cannot reset user activity or rescue an expired connection.
			require.NoError(t, conn.Write(ctx, websocket.MessageText, []byte(`{"type":"resize","cols":80,"rows":24}`)))
			_, _, e := conn.Read(ctx)
			require.Error(t, e)
			want := "idle_timeout"
			if max {
				want = "duration_limit"
			}
			require.Eventually(t, func() bool {
				rows, _, _, e := b.ListSessions(0, 10)
				return e == nil && len(rows) == 1 && rows[0].EndReason == want
			}, time.Second, time.Millisecond)
		})
	}
}

func TestTerminalPolicyWatermarkPersistsInCompatibleReplay(t *testing.T) {
	b := NewBroker(t.TempDir(), make([]byte, 32), func(context.Context, string, int, int) (AssetInfo, Terminal, error) {
		return AssetInfo{ID: "qa", Name: "qa"}, newEchoTerminal(), nil
	})
	defer b.CloseAll()
	b.SetSessionPolicy(sessionpolicy.Defaults)
	s, e := b.Create(context.Background(), CreateRequest{AssetID: "qa", OperatorID: "user-123", Cols: 80, Rows: 24})
	require.NoError(t, e)
	assert.Contains(t, s.Watermark, "user-123")
	b.SetSessionPolicy(func() sessionpolicy.Settings { return sessionpolicy.Settings{} })
	require.NoError(t, b.Close(s.SessionID))
	replay, e := b.OpenReplay(s.SessionID)
	require.NoError(t, e)
	defer replay.Close()
	line, e := bufio.NewReader(replay).ReadBytes('\n')
	require.NoError(t, e)
	var header struct {
		Version int               `json:"version"`
		Env     map[string]string `json:"env"`
	}
	require.NoError(t, json.Unmarshal(line, &header))
	assert.Equal(t, 2, header.Version)
	assert.Equal(t, s.Watermark, header.Env["JMS_WATERMARK"])
	rows, _, _, e := b.ListSessions(0, 10)
	require.NoError(t, e)
	assert.Equal(t, s.Watermark, rows[0].Watermark)
}

type stalledTerminal struct {
	entered, closed chan struct{}
	once            sync.Once
	closeOnce       sync.Once
}

func (p *stalledTerminal) Read([]byte) (int, error) { <-p.closed; return 0, io.EOF }
func (p *stalledTerminal) Write([]byte) (int, error) {
	p.once.Do(func() { close(p.entered) })
	<-p.closed
	return 0, io.ErrClosedPipe
}
func (p *stalledTerminal) Resize(int, int) error { return nil }
func (p *stalledTerminal) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}
func TestTerminationUnblocksRemoteThatStopsReading(t *testing.T) {
	p := &stalledTerminal{entered: make(chan struct{}), closed: make(chan struct{})}
	b := NewBroker(t.TempDir(), make([]byte, 32), func(context.Context, string, int, int) (AssetInfo, Terminal, error) {
		return AssetInfo{ID: "qa"}, p, nil
	})
	defer b.CloseAll()
	s, e := b.Create(context.Background(), CreateRequest{AssetID: "qa", Cols: 80, Rows: 24})
	require.NoError(t, e)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ws/api/v1/sessions/{sessionID}/terminal", b.ServeTerminal)
	server := httptest.NewServer(mux)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, _, e := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+s.WebSocketURL, &websocket.DialOptions{Subprotocols: []string{TerminalSubprotocol, TicketSubprotocol(s.Ticket)}})
	require.NoError(t, e)
	defer conn.CloseNow()
	require.NoError(t, conn.Write(ctx, websocket.MessageBinary, []byte("blocked input")))
	select {
	case <-p.entered:
	case <-ctx.Done():
		t.Fatal("write never entered")
	}
	done := make(chan error, 1)
	go func() { done <- b.Close(s.SessionID) }()
	select {
	case e := <-done:
		require.NoError(t, e)
	case <-ctx.Done():
		t.Fatal("termination blocked behind remote input")
	}
}
