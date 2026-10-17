package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/coder/websocket"
)

const MonitorSubprotocol = "jms233-monitor-v1"

// Monitoring has no input path to the PTY. A slow or revoked viewer only loses
// its own stream. Pending tickets and attached viewers share the same bounds.
const maxSessionMonitors, maxBrokerMonitors = 8, 64

var ErrMonitorCapacity = errors.New("session monitor capacity reached")

type MonitorRequest struct {
	SessionID, ViewerID, Viewer string
	AllowAll                    bool
	AccessPolicy                func(context.Context) error
}

type sessionMonitor struct {
	session *activeSession
	request MonitorRequest
	hash    [32]byte
	expires time.Time
	timer   *time.Timer
	used    bool
	output  chan []byte
	done    chan struct{}
}

func (b *Broker) CreateMonitor(ctx context.Context, request MonitorRequest) (CreatedSession, error) {
	if request.ViewerID == "" || request.AccessPolicy == nil || request.AccessPolicy(ctx) != nil {
		return CreatedSession{}, ErrSessionNotFound
	}
	ticket, err := randomToken(32)
	if err != nil {
		return CreatedSession{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	session := b.sessions[request.SessionID]
	if session == nil || session.closing || session.terminalSocket == nil || (!request.AllowAll && session.operatorID != request.ViewerID) {
		return CreatedSession{}, ErrSessionNotFound
	}
	if len(session.monitors) >= maxSessionMonitors || len(b.monitors) >= maxBrokerMonitors {
		return CreatedSession{}, ErrMonitorCapacity
	}
	m := &sessionMonitor{session: session, request: request, hash: sha256.Sum256([]byte(ticket)), expires: time.Now().Add(terminalTicketLifetime), output: make(chan []byte, 32), done: make(chan struct{})}
	b.monitors[m.hash] = m
	session.monitors[m] = struct{}{}
	m.timer = time.AfterFunc(terminalTicketLifetime, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if !m.used {
			b.stopMonitorLocked(m)
		}
	})
	return CreatedSession{SessionID: session.id, AssetName: session.asset.Name, Ticket: ticket, ExpiresAt: m.expires, WebSocketURL: "/ws/api/v1/sessions/" + session.id + "/monitor"}, nil
}

// Caller holds b.mu. Never close the output channel: a detached viewer can
// finish without racing a publisher or holding the primary terminal stream.
func (b *Broker) stopMonitorLocked(m *sessionMonitor) {
	if b.monitors[m.hash] != m {
		return
	}
	delete(b.monitors, m.hash)
	delete(m.session.monitors, m)
	if m.timer != nil {
		m.timer.Stop()
	}
	close(m.done)
}

func (b *Broker) publishMonitorOutput(s *activeSession, data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for m := range s.monitors {
		if !m.used {
			continue
		}
		select {
		case m.output <- data: // immutable copy made by writeTerminal
		default:
			b.stopMonitorLocked(m)
		}
	}
}

func (b *Broker) ServeMonitor(w http.ResponseWriter, r *http.Request) {
	ticket := ticketFromProtocols(r.Header.Values("Sec-WebSocket-Protocol"))
	hash := sha256.Sum256([]byte(ticket))
	b.mu.Lock()
	m := b.monitors[hash]
	valid := m != nil && !m.used && time.Now().Before(m.expires) && m.session.id == r.PathValue("sessionID") && !m.session.closing
	if valid {
		m.used = true
		m.timer.Stop()
	}
	b.mu.Unlock()
	if !valid {
		http.Error(w, "monitor ticket is invalid or expired", http.StatusUnauthorized)
		return
	}
	defer func() { b.mu.Lock(); b.stopMonitorLocked(m); b.mu.Unlock() }()
	if m.request.AccessPolicy(r.Context()) != nil {
		http.Error(w, "monitor access denied", http.StatusForbidden)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{MonitorSubprotocol}})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(1024)
	// Incoming application frames always end monitoring; none are forwarded.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	go func() { _, _, _ = conn.Read(ctx); cancel() }()
	if b.appendMonitorAudit(m, "monitor_started") != nil {
		return
	}
	defer func() { _ = b.appendMonitorAudit(m, "monitor_ended") }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	cols, rows := 0, 0
	write := func(kind websocket.MessageType, data []byte) error {
		if m.request.AccessPolicy(ctx) != nil {
			return errSessionPolicyDenied
		}
		select {
		case <-m.done:
			return ErrSessionNotFound
		default:
		}
		deadline, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		return conn.Write(deadline, kind, data)
	}
	resize := func() error {
		b.mu.Lock()
		c, r := m.session.cols, m.session.rows
		b.mu.Unlock()
		if c == cols && r == rows {
			return nil
		}
		cols, rows = c, r
		data, _ := json.Marshal(map[string]any{"type": "resize", "cols": c, "rows": r})
		return write(websocket.MessageText, data)
	}
	if resize() != nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.done:
			return
		case <-ticker.C:
			if m.request.AccessPolicy(ctx) != nil || resize() != nil {
				return
			}
		case data := <-m.output:
			if resize() != nil || write(websocket.MessageBinary, data) != nil {
				return
			}
		}
	}
}

func (b *Broker) appendMonitorAudit(m *sessionMonitor, event string) error {
	// Reuse the durable index writer, keeping viewer identity distinct from the
	// operator whose terminal is being observed. No terminal bytes are logged.
	return b.appendSessionAudit(map[string]any{"session_id": m.session.id, "event": event, "viewer_id": m.request.ViewerID, "viewer": m.request.Viewer, "at": time.Now().UTC()})
}
