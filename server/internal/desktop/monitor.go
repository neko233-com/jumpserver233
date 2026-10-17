package desktop

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/coder/websocket"
)

const MonitorSubprotocol = "jms233-desktop-monitor-v1"
const MonitorTicketPrefix = "jms233-desktop-monitor-ticket."
const maxSessionMonitors, maxBrokerMonitors = 4, 16
const maxMonitorAuditBytes = 16 << 20

var ErrMonitorCapacity = errors.New("desktop monitor capacity reached")
var ErrMonitorAudit = errors.New("desktop monitor audit unavailable")

type MonitorRequest struct {
	SessionID, ViewerID, Viewer string
	AllowAll                    bool
	Guard                       func(context.Context, Record) error
}

type MonitorEvent struct {
	SessionID string    `json:"session_id"`
	MonitorID string    `json:"monitor_id"`
	Event     string    `json:"event"`
	ViewerID  string    `json:"viewer_id"`
	Viewer    string    `json:"viewer"`
	At        time.Time `json:"at"`
}

type monitor struct {
	session *active
	request MonitorRequest
	id      string
	hash    [32]byte
	expires time.Time
	timer   *time.Timer
	used    bool
	done    chan struct{}
}

func (b *Broker) CreateMonitor(ctx context.Context, in MonitorRequest) (Created, error) {
	if in.ViewerID == "" || in.Viewer == "" || in.Guard == nil || ctx.Err() != nil {
		return Created{}, ErrNotFound
	}
	b.mu.Lock()
	a := b.live[in.SessionID]
	b.mu.Unlock()
	if a == nil {
		return Created{}, ErrNotFound
	}
	a.mu.Lock()
	closed, connected := a.closed, a.consumed && a.socket != nil
	record := a.record
	last := a.lastInput
	record.Frames = nil
	a.mu.Unlock()
	if closed || !connected || !in.AllowAll && record.OperatorID != in.ViewerID || b.securitySettings().EndReason(record.StartedAt, last, time.Now()) != "" || in.Guard(ctx, record) != nil || a.guard(a.ctx, "rdp") != nil {
		return Created{}, ErrNotFound
	}
	id, e := token()
	if e != nil {
		return Created{}, e
	}
	ticket, e := token()
	if e != nil {
		return Created{}, e
	}
	m := &monitor{session: a, request: in, id: id, hash: sha256.Sum256([]byte(ticket)), expires: time.Now().Add(30 * time.Second), done: make(chan struct{})}
	b.mu.Lock()
	defer b.mu.Unlock()
	a.mu.Lock()
	closed = a.closed
	a.mu.Unlock()
	if b.closed || b.live[in.SessionID] != a || closed {
		return Created{}, ErrNotFound
	}
	count := 0
	for _, peer := range b.monitors {
		if peer.session == a {
			count++
		}
	}
	if len(b.monitors) >= maxBrokerMonitors || count >= maxSessionMonitors {
		return Created{}, ErrMonitorCapacity
	}
	b.monitors[m.hash] = m
	m.timer = time.AfterFunc(30*time.Second, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if !m.used {
			b.stopMonitorLocked(m)
		}
	})
	return Created{ID: in.SessionID, URL: "/ws/desktop/" + in.SessionID + "/monitor", Ticket: ticket, Expires: m.expires}, nil
}

func (b *Broker) stopMonitorLocked(m *monitor) {
	if b.monitors[m.hash] != m {
		return
	}
	delete(b.monitors, m.hash)
	if m.timer != nil {
		m.timer.Stop()
	}
	close(m.done)
}

func (b *Broker) monitorAccess(ctx context.Context, m *monitor) error {
	if ctx.Err() != nil {
		return ErrNotFound
	}
	select {
	case <-m.done:
		return ErrNotFound
	default:
	}
	a := m.session
	a.mu.Lock()
	closed := a.closed
	record, last := a.record, a.lastInput
	record.Frames = nil
	a.mu.Unlock()
	if closed || !m.request.AllowAll && record.OperatorID != m.request.ViewerID || b.securitySettings().EndReason(record.StartedAt, last, time.Now()) != "" || a.guard(a.ctx, "rdp") != nil {
		return ErrNotFound
	}
	return m.request.Guard(ctx, record)
}

func (b *Broker) appendMonitorEvent(m *monitor, kind string) error {
	event := MonitorEvent{SessionID: m.session.record.ID, MonitorID: m.id, Event: kind, ViewerID: m.request.ViewerID, Viewer: m.request.Viewer, At: time.Now().UTC()}
	data, e := json.Marshal(event)
	if e != nil {
		return ErrMonitorAudit
	}
	b.monitorMu.Lock()
	defer b.monitorMu.Unlock()
	f, e := os.OpenFile(filepath.Join(b.root, event.SessionID, "monitors.jsonl"), os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if e != nil {
		return ErrMonitorAudit
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || kind == "monitor_started" && info.Size()+int64(len(data))+1 > maxMonitorAuditBytes {
		return ErrMonitorAudit
	}
	if info.Size() > 0 {
		var tail [1]byte
		if _, e = f.ReadAt(tail[:], info.Size()-1); e != nil || tail[0] != '\n' {
			return ErrMonitorAudit
		}
	}
	if _, e = f.Write(append(data, '\n')); e != nil {
		_ = f.Truncate(info.Size())
		_ = f.Sync()
		return ErrMonitorAudit
	}
	if f.Sync() != nil {
		return ErrMonitorAudit
	}
	if f.Close() != nil {
		return ErrMonitorAudit
	}
	return nil
}

func (b *Broker) ListMonitorEvents(id, viewer string, all bool, offset, limit int) ([]MonitorEvent, int, error) {
	if offset < 0 || offset > 1000000 || limit < 1 || limit > 100 {
		return nil, 0, ErrNotFound
	}
	if _, e := b.Get(id, viewer, all); e != nil {
		return nil, 0, e
	}
	// Keep both bounded scans on the same append-only snapshot.
	b.monitorMu.Lock()
	defer b.monitorMu.Unlock()
	f, e := os.Open(filepath.Join(b.root, id, "monitors.jsonl"))
	if errors.Is(e, os.ErrNotExist) {
		return []MonitorEvent{}, 0, nil
	}
	if e != nil {
		return nil, 0, ErrMonitorAudit
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 4096), 64<<10)
	total := 0
	for scan.Scan() {
		var row MonitorEvent
		if json.Unmarshal(scan.Bytes(), &row) == nil && row.SessionID == id && (row.Event == "monitor_started" || row.Event == "monitor_ended") {
			total++
		}
	}
	if scan.Err() != nil {
		return nil, 0, ErrMonitorAudit
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return nil, 0, ErrMonitorAudit
	}
	scan = bufio.NewScanner(f)
	scan.Buffer(make([]byte, 4096), 64<<10)
	rows := []MonitorEvent{}
	index := 0
	for scan.Scan() {
		var row MonitorEvent
		if json.Unmarshal(scan.Bytes(), &row) != nil || row.SessionID != id || row.Event != "monitor_started" && row.Event != "monitor_ended" {
			continue
		}
		position := total - 1 - index
		index++
		if position >= offset && position < offset+limit {
			rows = append(rows, row)
		}
	}
	if scan.Err() != nil {
		return nil, 0, ErrMonitorAudit
	}
	slices.Reverse(rows)
	return rows, total, nil
}

// Viewers have no path to Display.Input or ClipboardSnapshot. Every application
// message closes only the viewer, including text, pointer, resize and clipboard.
func (b *Broker) ServeMonitor(w http.ResponseWriter, r *http.Request) {
	ticket := ""
	protocol := false
	for _, value := range strings.Split(r.Header.Get("Sec-WebSocket-Protocol"), ",") {
		if strings.TrimSpace(value) == MonitorSubprotocol {
			protocol = true
		}
		if strings.HasPrefix(strings.TrimSpace(value), MonitorTicketPrefix) {
			ticket = strings.TrimPrefix(strings.TrimSpace(value), MonitorTicketPrefix)
		}
	}
	hash := sha256.Sum256([]byte(ticket))
	b.mu.Lock()
	m := b.monitors[hash]
	valid := protocol && m != nil && !m.used && time.Now().Before(m.expires) && m.session.record.ID == r.PathValue("sessionID")
	if valid {
		m.used = true
		m.timer.Stop()
	}
	b.mu.Unlock()
	if !valid {
		http.Error(w, "desktop monitor ticket is invalid", 401)
		return
	}
	defer func() { b.mu.Lock(); b.stopMonitorLocked(m); b.mu.Unlock() }()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	if b.monitorAccess(ctx, m) != nil {
		http.Error(w, "desktop monitor access denied", 403)
		return
	}
	conn, e := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{MonitorSubprotocol}})
	if e != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(1024)
	if b.appendMonitorEvent(m, "monitor_started") != nil {
		return
	}
	defer func() {
		// Revoke transport and capacity before a best-effort storage write.
		conn.CloseNow()
		b.mu.Lock()
		b.stopMonitorLocked(m)
		b.mu.Unlock()
		_ = b.appendMonitorEvent(m, "monitor_ended")
	}()
	go func() { _, _, _ = conn.Read(ctx); cancel() }()
	write := func(kind websocket.MessageType, data []byte) error {
		if b.monitorAccess(ctx, m) != nil {
			return ErrNotFound
		}
		deadline, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		return conn.Write(deadline, kind, data)
	}
	ready, _ := json.Marshal(map[string]any{"type": "ready", "read_only": true, "clipboard": false, "viewer_id": m.request.ViewerID, "session_id": m.session.record.ID})
	if write(websocket.MessageText, ready) != nil {
		return
	}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	var sequence uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.done:
			return
		case <-m.session.display.Done():
			return
		case <-ticker.C:
			if b.monitorAccess(ctx, m) != nil {
				return
			}
			next, packet, e := m.session.wireFrame()
			if e != nil {
				return
			}
			if next != sequence {
				if write(websocket.MessageBinary, packet) != nil {
					return
				}
				sequence = next
			}
		}
	}
}
