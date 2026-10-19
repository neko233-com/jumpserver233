package gateway

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func monitorFixture(t *testing.T, options ...CreateRequest) (*Broker, CreatedSession, *websocket.Conn, string, context.Context) {
	return monitorFixtureWithCapabilities(t, true, options...)
}
func monitorFixtureWithCapabilities(t *testing.T, shareControl bool, options ...CreateRequest) (*Broker, CreatedSession, *websocket.Conn, string, context.Context) {
	return monitorFixtureTerminal(t, shareControl, newEchoTerminal(), options...)
}
func monitorFixtureTerminal(t *testing.T, shareControl bool, terminal Terminal, options ...CreateRequest) (*Broker, CreatedSession, *websocket.Conn, string, context.Context) {
	t.Helper()
	b := NewBroker(t.TempDir(), make([]byte, 32), func(context.Context, string, int, int) (AssetInfo, Terminal, error) {
		return AssetInfo{ID: "qa", Name: "qa", Username: "ops"}, terminal, nil
	})
	t.Cleanup(b.CloseAll)
	request := CreateRequest{AssetID: "qa", OperatorID: "owner", Cols: 90, Rows: 30}
	if len(options) > 0 {
		request.AccessPolicy, request.CommandPolicy = options[0].AccessPolicy, options[0].CommandPolicy
	}
	s, e := b.Create(context.Background(), request)
	require.NoError(t, e)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ws/api/v1/sessions/{sessionID}/terminal", b.ServeTerminal)
	mux.HandleFunc("GET /ws/api/v1/sessions/{sessionID}/monitor", b.ServeMonitor)
	mux.HandleFunc("GET /ws/api/v1/sessions/{sessionID}/share", b.ServeShare)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(stop)
	base := "ws" + strings.TrimPrefix(server.URL, "http")
	protocols := []string{TerminalSubprotocol, TicketSubprotocol(s.Ticket)}
	if shareControl {
		protocols = append(protocols, ShareControlCapability)
	}
	conn, _, e := websocket.Dial(ctx, base+s.WebSocketURL, &websocket.DialOptions{Subprotocols: protocols})
	require.NoError(t, e)
	t.Cleanup(func() { conn.CloseNow() })
	require.Eventually(t, func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.sessions[s.SessionID].terminalSocket != nil
	}, time.Second, time.Millisecond)
	return b, s, conn, base, ctx
}

func TestPendingCommandReviewRevalidatesAccessAndCommandRules(t *testing.T) {
	for _, access := range []bool{true, false} {
		t.Run(map[bool]string{true: "access_revoked", false: "rule_changed"}[access], func(t *testing.T) {
			var changed atomic.Bool
			b, s, primary, _, ctx := monitorFixture(t, CreateRequest{
				AccessPolicy: func(context.Context) error {
					if access && changed.Load() {
						return ErrSessionAccessDenied
					}
					return nil
				},
				CommandPolicy: func(string, bool, time.Time) CommandPolicyDecision {
					if !access && changed.Load() {
						return CommandPolicyDecision{RuleName: "new deny"}
					}
					return CommandPolicyDecision{RequireReview: true, RuleName: "review"}
				},
			})
			b.mu.Lock()
			live := b.sessions[s.SessionID]
			b.mu.Unlock()
			live.commands.ObserveOutput([]byte("ops@qa:~$ "))
			require.NoError(t, primary.Write(ctx, websocket.MessageBinary, []byte("echo needs-review\r")))
			_, data, e := primary.Read(ctx)
			require.NoError(t, e)
			assert.Contains(t, string(data), "command_review_pending")
			_, data, e = primary.Read(ctx)
			require.NoError(t, e)
			assert.Equal(t, "echo needs-review", string(data))
			reviews := b.ListPendingCommandReviews()
			require.Len(t, reviews, 1)
			changed.Store(true)
			result := make(chan error, 1)
			go func() { result <- b.ResolveCommandReview(reviews[0].ID, "reviewer", true) }()
			_, data, e = primary.Read(ctx)
			if access {
				require.Error(t, e)
				assert.ErrorIs(t, <-result, ErrSessionAccessDenied)
			} else {
				require.NoError(t, e)
				assert.Contains(t, string(data), "command_review_denied")
				_, data, e = primary.Read(ctx)
				require.NoError(t, e)
				assert.Equal(t, []byte{0x03}, data)
				require.NoError(t, <-result)
			}
		})
	}
}

func TestCommandDirectoryPolicyRevisionInvalidatesPendingTerminalApproval(t *testing.T) {
	for _, nowAllowed := range []bool{false, true} {
		t.Run(map[bool]string{false: "same_name_new_revision", true: "changed_to_allow"}[nowAllowed], func(t *testing.T) {
			var changed atomic.Bool
			b, s, primary, _, ctx := monitorFixture(t, CreateRequest{CommandPolicy: func(string, bool, time.Time) CommandPolicyDecision {
				if changed.Load() {
					return CommandPolicyDecision{Allowed: nowAllowed, RequireReview: !nowAllowed, RuleName: "review", PolicyKey: "new policy"}
				}
				return CommandPolicyDecision{RequireReview: true, RuleName: "review", PolicyKey: "old policy"}
			}})
			b.mu.Lock()
			live := b.sessions[s.SessionID]
			b.mu.Unlock()
			live.commands.ObserveOutput([]byte("ops@qa:~$ "))
			require.NoError(t, primary.Write(ctx, websocket.MessageBinary, []byte("echo held\r")))
			_, data, err := primary.Read(ctx)
			require.NoError(t, err)
			assert.Contains(t, string(data), "command_review_pending")
			_, _, err = primary.Read(ctx)
			require.NoError(t, err)
			reviews := b.ListPendingCommandReviews()
			require.Len(t, reviews, 1)
			changed.Store(true)
			result := make(chan error, 1)
			go func() { result <- b.ResolveCommandReview(reviews[0].ID, "reviewer", true) }()
			_, data, err = primary.Read(ctx)
			require.NoError(t, err)
			assert.Contains(t, string(data), "command_review_denied")
			_, data, err = primary.Read(ctx)
			require.NoError(t, err)
			assert.Equal(t, []byte{0x03}, data)
			require.NoError(t, <-result)
		})
	}
}

func TestLiveMonitorOutputIsolationTicketAndAudit(t *testing.T) {
	b, s, owner, base, ctx := monitorFixture(t)
	request := MonitorRequest{SessionID: s.SessionID, ViewerID: "stranger", Viewer: "reviewer", AccessPolicy: func(context.Context) error { return nil }}
	_, e := b.CreateMonitor(ctx, request)
	assert.ErrorIs(t, e, ErrSessionNotFound)
	request.AllowAll = true
	m, e := b.CreateMonitor(ctx, request)
	require.NoError(t, e)
	monitor, _, e := websocket.Dial(ctx, base+m.WebSocketURL, &websocket.DialOptions{Subprotocols: []string{MonitorSubprotocol, TicketSubprotocol(m.Ticket)}})
	require.NoError(t, e)
	defer monitor.CloseNow()
	kind, meta, e := monitor.Read(ctx)
	require.NoError(t, e)
	assert.Equal(t, websocket.MessageText, kind)
	assert.JSONEq(t, `{"type":"resize","cols":90,"rows":30}`, string(meta))
	_, response, e := websocket.Dial(ctx, base+m.WebSocketURL, &websocket.DialOptions{Subprotocols: []string{MonitorSubprotocol, TicketSubprotocol(m.Ticket)}})
	require.Error(t, e)
	require.NotNil(t, response)
	assert.Equal(t, 401, response.StatusCode)
	response.Body.Close()
	require.NoError(t, owner.Write(ctx, websocket.MessageBinary, []byte("visible output\r")))
	_, output, e := owner.Read(ctx)
	require.NoError(t, e)
	_, observed, e := monitor.Read(ctx)
	require.NoError(t, e)
	assert.Equal(t, output, observed)
	// Even a client that bypasses the read-only UI cannot inject input.
	require.NoError(t, monitor.Write(ctx, websocket.MessageBinary, []byte("injected\r")))
	_, _, e = monitor.Read(ctx)
	require.Error(t, e)
	require.NoError(t, owner.Write(ctx, websocket.MessageBinary, []byte("owner continues\r")))
	_, output, e = owner.Read(ctx)
	require.NoError(t, e)
	assert.Equal(t, "owner continues\r", string(output))
	require.Eventually(t, func() bool {
		data, e := os.ReadFile(b.auditPath)
		return e == nil && strings.Contains(string(data), "monitor_ended")
	}, time.Second, time.Millisecond)
	data, e := os.ReadFile(b.auditPath)
	require.NoError(t, e)
	assert.Contains(t, string(data), `"viewer_id":"stranger"`)
	assert.NotContains(t, string(data), "visible output")
}

func TestLiveMonitorRevocationAndSessionClose(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(map[bool]string{true: "viewer_revoked", false: "primary_ended"}[revoke], func(t *testing.T) {
			b, s, owner, base, ctx := monitorFixture(t)
			var denied atomic.Bool
			m, e := b.CreateMonitor(ctx, MonitorRequest{SessionID: s.SessionID, ViewerID: "owner", AccessPolicy: func(context.Context) error {
				if denied.Load() {
					return errSessionPolicyDenied
				}
				return nil
			}})
			require.NoError(t, e)
			monitor, _, e := websocket.Dial(ctx, base+m.WebSocketURL, &websocket.DialOptions{Subprotocols: []string{MonitorSubprotocol, TicketSubprotocol(m.Ticket)}})
			require.NoError(t, e)
			defer monitor.CloseNow()
			_, _, e = monitor.Read(ctx)
			require.NoError(t, e)
			if revoke {
				denied.Store(true)
			} else {
				require.NoError(t, b.Close(s.SessionID))
			}
			_, _, e = monitor.Read(ctx)
			require.Error(t, e)
			if revoke {
				require.NoError(t, owner.Write(ctx, websocket.MessageBinary, []byte("still connected")))
				_, output, e := owner.Read(ctx)
				require.NoError(t, e)
				assert.Equal(t, "still connected", string(output))
			}
		})
	}
}

func TestLiveMonitorCapacityExpirationSlowViewerAndAuditFailure(t *testing.T) {
	b, s, _, base, ctx := monitorFixture(t)
	request := MonitorRequest{SessionID: s.SessionID, ViewerID: "owner", AccessPolicy: func(context.Context) error { return nil }}
	for i := 0; i < maxSessionMonitors; i++ {
		_, e := b.CreateMonitor(ctx, request)
		require.NoError(t, e)
	}
	_, e := b.CreateMonitor(ctx, request)
	assert.ErrorIs(t, e, ErrMonitorCapacity)
	b.mu.Lock()
	for monitor := range b.sessions[s.SessionID].monitors {
		b.stopMonitorLocked(monitor)
	}
	b.mu.Unlock()
	expiring, e := b.CreateMonitor(ctx, request)
	require.NoError(t, e)
	b.mu.Lock()
	expired := b.monitors[sha256.Sum256([]byte(expiring.Ticket))]
	expired.expires = time.Now().Add(-time.Second)
	b.mu.Unlock()
	_, response, e := websocket.Dial(ctx, base+expiring.WebSocketURL, &websocket.DialOptions{Subprotocols: []string{MonitorSubprotocol, TicketSubprotocol(expiring.Ticket)}})
	require.Error(t, e)
	require.NotNil(t, response)
	assert.Equal(t, 401, response.StatusCode)
	response.Body.Close()
	b.mu.Lock()
	b.stopMonitorLocked(expired)
	b.mu.Unlock()
	m, e := b.CreateMonitor(ctx, request)
	require.NoError(t, e)
	b.mu.Lock()
	internal := b.monitors[sha256.Sum256([]byte(m.Ticket))]
	internal.used = true
	b.mu.Unlock()
	for i := 0; i < 33; i++ {
		b.publishMonitorOutput(internal.session, []byte("output"))
	}
	select {
	case <-internal.done:
	default:
		t.Fatal("slow viewer not disconnected")
	}
	b.mu.Lock()
	assert.Empty(t, b.monitors)
	b.mu.Unlock()
	// A late monitor can attach after a prior viewer was dropped.
	_, e = b.CreateMonitor(ctx, request)
	require.NoError(t, e)
	// Expiry and unknown sessions do not grant another terminal a ticket.
	request.SessionID = "other-session"
	_, e = b.CreateMonitor(ctx, request)
	assert.ErrorIs(t, e, ErrSessionNotFound)
	assert.NoError(t, os.Mkdir(filepath.Join(b.dataDir, "directory"), 0700))
	b.auditPath = filepath.Join(b.dataDir, "directory")
	assert.Error(t, b.appendMonitorAudit(internal, "monitor_started"))
}
