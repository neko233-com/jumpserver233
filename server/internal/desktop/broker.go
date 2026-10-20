// Package desktop owns graphical sessions independently of the terminal frame
// and asciinema protocols. Credentials remain inside the asset connector.
package desktop

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/connector/rdpclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/replayarchive"
	"github.com/neko233-com/jumpserver233/server/internal/core/sessionpolicy"
	"github.com/neko233-com/jumpserver233/server/internal/recorder"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const Subprotocol = "jms233-desktop-v1"
const TicketPrefix = "jms233-desktop-ticket."

var ErrNotFound = errors.New("desktop session not found")
var ErrUnavailable = errors.New("desktop service unavailable")
var idPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type Display interface {
	Close() error
	Done() <-chan struct{}
	Snapshot() (rdpclient.Frame, error)
	Input(rdpclient.Input) error
	SetClipboardGuard(func(string) error)
	ClipboardSnapshot() rdpclient.ClipboardState
}
type Record struct {
	Watermark  string                  `json:"watermark,omitempty"`
	ID         string                  `json:"session_id"`
	AssetID    string                  `json:"asset_id"`
	AssetName  string                  `json:"asset_name"`
	OperatorID string                  `json:"operator_id"`
	Operator   string                  `json:"operator"`
	Username   string                  `json:"username"`
	GatewayIDs []string                `json:"gateway_ids,omitempty"`
	StartedAt  time.Time               `json:"started_at"`
	EndedAt    *time.Time              `json:"ended_at,omitempty"`
	Status     string                  `json:"status"`
	EndReason  string                  `json:"end_reason,omitempty"`
	ReadOnly   bool                    `json:"read_only"`
	Clipboard  bool                    `json:"clipboard"`
	Inputs     int                     `json:"inputs"`
	Frames     []recorder.DesktopFrame `json:"frames"`
}
type Request struct {
	Record Record
	Open   func(context.Context) (Display, error)
	Guard  func(context.Context, string) error
	// ResolvedGateways returns the route used by Open, after the post-open guard.
	ResolvedGateways func() []string
}
type Created struct {
	ID      string    `json:"session_id"`
	URL     string    `json:"websocket_url"`
	Ticket  string    `json:"ticket"`
	Expires time.Time `json:"expires_at"`
}
type active struct {
	lastInput    time.Time
	frameMu      sync.Mutex
	cached       rdpclient.Frame
	wireSequence uint64
	wirePacket   []byte
	mu           sync.Mutex
	record       Record
	display      Display
	recording    *recorder.Desktop
	guard        func(context.Context, string) error
	ctx          context.Context
	token        [32]byte
	expiry       time.Time
	consumed     bool
	closed       bool
	finished     chan struct{}
	socket       *websocket.Conn
}
type Broker struct {
	archive   atomic.Pointer[replayarchive.Store]
	monitorMu sync.Mutex
	monitors  map[[32]byte]*monitor
	policy    func() sessionpolicy.Settings
	mu        sync.Mutex
	indexMu   sync.Mutex // Windows readers must close before atomic index replacement.
	root      string
	key       []byte
	live      map[string]*active
	closed    bool
	pending   int
}

func New(root string, key []byte) (*Broker, error) {
	if len(key) != 32 {
		return nil, ErrUnavailable
	}
	root = filepath.Join(root, "desktop-sessions")
	if e := os.MkdirAll(root, 0700); e != nil {
		return nil, e
	}
	return &Broker{root: root, key: append([]byte(nil), key...), live: map[string]*active{}, monitors: map[[32]byte]*monitor{}}, nil
}
func token() (string, error) {
	v := make([]byte, 16)
	_, e := rand.Read(v)
	return hex.EncodeToString(v), e
}
func (b *Broker) persist(a *active) error {
	b.indexMu.Lock()
	defer b.indexMu.Unlock()
	data, e := json.Marshal(a.record)
	if e != nil {
		return e
	}
	directory := filepath.Join(b.root, a.record.ID)
	f, e := os.CreateTemp(directory, "index-*.tmp")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(name, filepath.Join(directory, "index.json"))
}
func (b *Broker) Create(ctx context.Context, req Request) (Created, error) {
	if req.Open == nil || req.Guard == nil || req.Record.OperatorID == "" || req.Record.AssetID == "" {
		return Created{}, ErrUnavailable
	}
	b.mu.Lock()
	if b.closed || len(b.live)+b.pending >= 16 {
		b.mu.Unlock()
		return Created{}, ErrUnavailable
	}
	b.pending++
	b.mu.Unlock()
	defer func() { b.mu.Lock(); b.pending--; b.mu.Unlock() }()
	if e := req.Guard(ctx, "rdp"); e != nil {
		return Created{}, e
	}
	setup, cancel := context.WithTimeout(ctx, 25*time.Second)
	display, e := req.Open(setup)
	cancel()
	if e != nil {
		return Created{}, e
	}
	ok := false
	defer func() {
		if !ok {
			display.Close()
		}
	}()
	if e = req.Guard(ctx, "rdp"); e != nil {
		return Created{}, e
	}
	if req.ResolvedGateways != nil {
		req.Record.GatewayIDs = append([]string(nil), req.ResolvedGateways()...)
	}
	id, e := token()
	if e != nil {
		return Created{}, e
	}
	ticket, e := token()
	if e != nil {
		return Created{}, e
	}
	rec, e := recorder.NewDesktop(filepath.Join(b.root, id), id, b.key)
	if e != nil {
		return Created{}, e
	}
	req.Record.ID = id
	req.Record.StartedAt = time.Now().UTC()
	if b.securitySettings().Watermark {
		req.Record.Watermark = sessionpolicy.Label(req.Record.OperatorID, id, req.Record.StartedAt)
	}
	req.Record.Status = "active"
	req.Record.Frames = []recorder.DesktopFrame{}
	a := &active{lastInput: req.Record.StartedAt, record: req.Record, display: display, recording: rec, guard: req.Guard, ctx: context.WithoutCancel(ctx), token: sha256.Sum256([]byte(ticket)), expiry: time.Now().Add(30 * time.Second)}
	display.SetClipboardGuard(func(method string) error { return req.Guard(a.ctx, method) })
	a.mu.Lock()
	e = b.capture(a)
	a.mu.Unlock()
	if e != nil {
		return Created{}, e
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return Created{}, ErrUnavailable
	}
	b.live[id] = a
	b.mu.Unlock()
	ok = true
	go b.watch(a)
	return Created{ID: id, URL: "/ws/desktop/" + id, Ticket: ticket, Expires: a.expiry}, nil
}
func (b *Broker) capture(a *active) error {
	f, e := a.snapshot()
	if e != nil {
		return e
	}
	n := len(a.record.Frames)
	if n > 0 && a.record.Frames[n-1].Sequence == f.Sequence {
		return nil
	}
	frame := recorder.DesktopFrame{Index: n, AtMS: time.Since(a.record.StartedAt).Milliseconds(), Sequence: f.Sequence, Width: f.Width, Height: f.Height}
	if e = a.recording.Record(frame, f.PNG); e != nil {
		return e
	}
	a.record.Frames = append(a.record.Frames, frame)
	return b.persist(a)
}
func (b *Broker) watch(a *active) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-a.display.Done():
			b.end(a, "remote_closed")
			return
		case <-ticker.C:
			settings := b.securitySettings()
			a.mu.Lock()
			closed := a.closed
			expired := !a.consumed && time.Now().After(a.expiry)
			limitReason := settings.EndReason(a.record.StartedAt, a.lastInput, time.Now())
			a.mu.Unlock()
			if closed {
				return
			}
			if expired {
				b.end(a, "ticket_expired")
				return
			}
			if limitReason != "" {
				b.end(a, limitReason)
				return
			}
			if a.guard(a.ctx, "rdp") != nil {
				b.end(a, "access_revoked")
				return
			}
			a.mu.Lock()
			if a.closed {
				a.mu.Unlock()
				return
			}
			e := b.capture(a)
			a.mu.Unlock()
			if e != nil {
				b.end(a, "recording_failed")
				return
			}
		}
	}
}
func (b *Broker) end(a *active, reason string) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closed = true
	if a.finished == nil {
		a.finished = make(chan struct{})
	}
	defer close(a.finished)
	a.token = [32]byte{}
	at := time.Now().UTC()
	a.record.Status = "ended"
	a.record.EndedAt = &at
	a.record.EndReason = reason
	if e := b.capture(a); e != nil {
		a.record.EndReason = "recording_failed"
	}
	persistError := b.persist(a)
	socket := a.socket
	id := a.record.ID
	a.mu.Unlock()
	if persistError == nil {
		if archive := b.replayArchive(); archive != nil {
			_ = archive.Enqueue(replayarchive.Ref{Kind: "desktop", SessionID: id})
		}
	}
	a.display.Close()
	if socket != nil {
		socket.CloseNow()
	}
	b.mu.Lock()
	for _, viewer := range b.monitors {
		if viewer.session == a {
			b.stopMonitorLocked(viewer)
		}
	}
	delete(b.live, id)
	b.mu.Unlock()
}
func (b *Broker) CloseAll() {
	b.mu.Lock()
	b.closed = true
	list := make([]*active, 0, len(b.live))
	for _, a := range b.live {
		list = append(list, a)
	}
	b.mu.Unlock()
	for _, a := range list {
		b.end(a, "server_shutdown")
		a.mu.Lock()
		finished := a.finished
		a.mu.Unlock()
		if finished != nil {
			<-finished
		}
	}
}
func (b *Broker) readIndex(id string) (Record, error) {
	b.indexMu.Lock()
	defer b.indexMu.Unlock()
	file, e := os.Open(filepath.Join(b.root, id, "index.json"))
	if e != nil {
		return Record{}, ErrNotFound
	}
	defer file.Close()
	raw, e := io.ReadAll(io.LimitReader(file, (2<<20)+1))
	if e != nil || len(raw) > 2<<20 {
		return Record{}, ErrNotFound
	}
	var r Record
	if json.Unmarshal(raw, &r) != nil || r.ID != id {
		return Record{}, ErrNotFound
	}
	return r, nil
}
func (b *Broker) Get(id, owner string, all bool) (Record, error) {
	if !idPattern.MatchString(id) {
		return Record{}, ErrNotFound
	}
	r, e := b.readIndex(id)
	if e != nil || (!all && (owner == "" || r.OperatorID != owner)) {
		return Record{}, ErrNotFound
	}
	if r.Status == "active" {
		b.mu.Lock()
		a := b.live[id]
		b.mu.Unlock()
		if a == nil {
			r.Status = "interrupted"
			r.EndReason = "server_interrupted"
		}
	}
	return r, nil
}
func (b *Broker) List(owner string, all bool) ([]Record, error) {
	entries, e := os.ReadDir(b.root)
	if e != nil {
		return nil, e
	}
	list := []Record{}
	for _, entry := range entries {
		if !entry.IsDir() || !idPattern.MatchString(entry.Name()) {
			continue
		}
		r, e := b.Get(entry.Name(), owner, all)
		if e == nil {
			r.Frames = nil
			list = append(list, r)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].StartedAt.After(list[j].StartedAt) })
	if len(list) > 1000 {
		list = list[:1000]
	}
	return list, nil
}
func (b *Broker) Stop(id, owner string, all bool) error {
	if _, e := b.Get(id, owner, all); e != nil {
		return e
	}
	b.mu.Lock()
	a := b.live[id]
	b.mu.Unlock()
	if a == nil {
		return ErrNotFound
	}
	b.end(a, "operator_stopped")
	return nil
}
func (b *Broker) Frame(id, owner string, all bool, index int) ([]byte, error) {
	return b.FrameContext(context.Background(), id, owner, all, index)
}
func (b *Broker) FrameContext(ctx context.Context, id, owner string, all bool, index int) ([]byte, error) {
	r, e := b.Get(id, owner, all)
	// Historic replay authority must not become an unaudited live screen feed.
	if e != nil || r.Status == "active" && r.OperatorID != owner || index < 0 || index >= len(r.Frames) {
		return nil, ErrNotFound
	}
	d, e := recorder.NewDesktop(filepath.Join(b.root, id), id, b.key)
	if e != nil {
		return nil, e
	}
	data, e := d.Read(r.Frames[index])
	if errors.Is(e, os.ErrNotExist) && r.Status == "ended" {
		if archive := b.replayArchive(); archive != nil {
			return archive.DesktopFrame(ctx, id, r.Frames[index], b.key)
		}
	}
	return data, e
}
func (b *Broker) ServeWS(w http.ResponseWriter, r *http.Request) {
	set := func(code int) { http.Error(w, "desktop session unavailable", code) }
	id := r.PathValue("sessionID")
	b.mu.Lock()
	a := b.live[id]
	b.mu.Unlock()
	if a == nil {
		set(404)
		return
	}
	ticket := ""
	for _, v := range strings.Split(r.Header.Get("Sec-WebSocket-Protocol"), ",") {
		if strings.HasPrefix(strings.TrimSpace(v), TicketPrefix) {
			ticket = strings.TrimPrefix(strings.TrimSpace(v), TicketPrefix)
		}
	}
	a.mu.Lock()
	hash := sha256.Sum256([]byte(ticket))
	valid := !a.closed && !a.consumed && time.Now().Before(a.expiry) && ticket != "" && subtle.ConstantTimeCompare(hash[:], a.token[:]) == 1
	if valid {
		a.consumed = true
		a.token = [32]byte{}
	}
	a.mu.Unlock()
	if !valid {
		set(401)
		return
	}
	ctx := accesspolicies.WithSourceIP(context.WithoutCancel(r.Context()), accesspolicies.SourceIP(r.Context()))
	if a.guard(ctx, "rdp") != nil {
		b.end(a, "access_revoked")
		set(403)
		return
	}
	socket, e := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{Subprotocol}})
	if e != nil {
		b.end(a, "handshake_failed")
		return
	}
	defer b.end(a, "disconnected")
	socket.SetReadLimit(128 << 10)
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		socket.CloseNow()
		return
	}
	a.socket = socket
	a.mu.Unlock()
	wsctx, cancel := context.WithCancel(ctx)
	defer cancel()
	failed := make(chan struct{}, 1)
	clipboardUnavailable := make(chan struct{}, 1)
	write := func(kind websocket.MessageType, data []byte) error {
		wc, c := context.WithTimeout(wsctx, 5*time.Second)
		defer c()
		return socket.Write(wc, kind, data)
	}
	go func() {
		defer func() { failed <- struct{}{} }()
		window := time.Now()
		count := 0
		for {
			kind, data, e := socket.Read(wsctx)
			if e != nil {
				return
			}
			if kind != websocket.MessageText {
				return
			}
			if time.Since(window) > time.Second {
				window = time.Now()
				count = 0
			}
			count++
			if count > 250 {
				return
			}
			var input rdpclient.Input
			if json.Unmarshal(data, &input) != nil {
				return
			}
			method := "rdp_input"
			if input.Type == "clipboard_read" {
				method = "rdp_clipboard_read"
			}
			if input.Type == "clipboard_write" {
				method = "rdp_clipboard_write"
			}
			if a.guard(ctx, "rdp") != nil || a.guard(ctx, method) != nil {
				return
			}
			settings := b.securitySettings()
			a.mu.Lock()
			reason := settings.EndReason(a.record.StartedAt, a.lastInput, time.Now())
			a.mu.Unlock()
			if reason != "" {
				b.end(a, reason)
				return
			}
			if e = a.display.Input(input); e != nil {
				if input.Type == "text" && errors.Is(e, rdpclient.ErrTextUnsupported) {
					if write(websocket.MessageText, []byte(`{"type":"text_error"}`)) != nil {
						return
					}
					continue
				}
				if (input.Type == "clipboard_read" || input.Type == "clipboard_write") && errors.Is(e, rdpclient.ErrClipboardNotReady) {
					select {
					case clipboardUnavailable <- struct{}{}:
					default:
					}
					continue
				}
				return
			}
			if input.Type == "text" {
				if write(websocket.MessageText, []byte(`{"type":"text_accepted"}`)) != nil {
					return
				}
			}
			a.mu.Lock()
			a.lastInput = time.Now()
			a.record.Inputs++
			a.mu.Unlock()
		}
	}()
	a.mu.Lock()
	ready, _ := json.Marshal(map[string]any{"type": "ready", "read_only": a.record.ReadOnly, "clipboard": a.record.Clipboard})
	a.mu.Unlock()
	if write(websocket.MessageText, ready) != nil {
		return
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var sequence uint64
	var clipboardRevision uint64
	for {
		select {
		case <-failed:
			return
		case <-a.display.Done():
			return
		case <-clipboardUnavailable:
			if write(websocket.MessageText, []byte(`{"type":"clipboard_error"}`)) != nil {
				return
			}
		case <-ticker.C:
			if a.guard(ctx, "rdp") != nil {
				return
			}
			next, packet, e := a.wireFrame()
			if e != nil {
				return
			}
			if next != sequence {
				if write(websocket.MessageBinary, packet) != nil {
					return
				}
				sequence = next
			}
			clipboard := a.display.ClipboardSnapshot()
			if clipboard.Revision > clipboardRevision {
				message, _ := json.Marshal(map[string]string{"type": "clipboard", "text": clipboard.Text})
				if clipboard.Failed {
					message = []byte(`{"type":"clipboard_error"}`)
				}
				if write(websocket.MessageText, message) != nil {
					return
				}
				clipboardRevision = clipboard.Revision
			}
		}
	}
}
