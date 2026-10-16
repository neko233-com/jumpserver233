package desktop

import (
	"context"
	"encoding/json"
	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/connector/rdpclient"
	"github.com/neko233-com/jumpserver233/server/internal/recorder"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeDisplay struct {
	once   sync.Once
	done   chan struct{}
	inputs atomic.Int32
}

func (f *fakeDisplay) Close() error          { f.once.Do(func() { close(f.done) }); return nil }
func (f *fakeDisplay) Done() <-chan struct{} { return f.done }
func (f *fakeDisplay) Snapshot() (rdpclient.Frame, error) {
	return rdpclient.Frame{Sequence: 1, Width: 320, Height: 200, PNG: []byte("synthetic graphical frame")}, nil
}
func (f *fakeDisplay) Input(rdpclient.Input) error                 { f.inputs.Add(1); return nil }
func (f *fakeDisplay) SetClipboardGuard(func(string) error)        {}
func (f *fakeDisplay) ClipboardSnapshot() rdpclient.ClipboardState { return rdpclient.ClipboardState{} }
func TestResolvedGatewayChainIsCopiedIntoPersistentAudit(t *testing.T) {
	root := t.TempDir()
	b, e := New(root, make([]byte, 32))
	require.NoError(t, e)
	defer b.CloseAll()
	var opened []string
	created, e := b.Create(context.Background(), Request{
		Record: Record{AssetID: "asset", OperatorID: "owner"},
		Open: func(context.Context) (Display, error) {
			opened = []string{"outer", "inner"}
			return &fakeDisplay{done: make(chan struct{})}, nil
		},
		Guard:            func(context.Context, string) error { return nil },
		ResolvedGateways: func() []string { return opened },
	})
	require.NoError(t, e)
	opened[0] = "must not alter audit"
	record, e := b.Get(created.ID, "owner", false)
	require.NoError(t, e)
	require.Equal(t, []string{"outer", "inner"}, record.GatewayIDs)
	require.NoError(t, b.Stop(created.ID, "owner", false))
	reopened, e := New(root, make([]byte, 32))
	require.NoError(t, e)
	defer reopened.CloseAll()
	record, e = reopened.Get(created.ID, "owner", false)
	require.NoError(t, e)
	require.Equal(t, []string{"outer", "inner"}, record.GatewayIDs)
}
func TestTicketsOwnershipReplayAndRevocation(t *testing.T) {
	root := t.TempDir()
	broker, e := New(root, make([]byte, 32))
	require.NoError(t, e)
	defer broker.CloseAll()
	display := &fakeDisplay{done: make(chan struct{})}
	var revoked atomic.Bool
	created, e := broker.Create(context.Background(), Request{Record: Record{AssetID: "asset", AssetName: "Desktop", OperatorID: "alice", Operator: "Alice"}, Open: func(context.Context) (Display, error) { return display, nil }, Guard: func(context.Context, string) error {
		if revoked.Load() {
			return ErrUnavailable
		}
		return nil
	}})
	require.NoError(t, e)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ws/desktop/{sessionID}", broker.ServeWS)
	server := httptest.NewServer(mux)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	uri := "ws" + strings.TrimPrefix(server.URL, "http") + created.URL
	_, _, e = websocket.Dial(ctx, uri, &websocket.DialOptions{Subprotocols: []string{Subprotocol, TicketPrefix + "wrong"}})
	assert.Error(t, e)
	conn, _, e := websocket.Dial(ctx, uri, &websocket.DialOptions{Subprotocols: []string{Subprotocol, TicketPrefix + created.Ticket}})
	require.NoError(t, e)
	defer conn.CloseNow()
	_, _, e = websocket.Dial(ctx, uri, &websocket.DialOptions{Subprotocols: []string{Subprotocol, TicketPrefix + created.Ticket}})
	assert.Error(t, e)
	kind, _, e := conn.Read(ctx)
	require.NoError(t, e)
	assert.Equal(t, websocket.MessageText, kind)
	kind, data, e := conn.Read(ctx)
	require.NoError(t, e)
	assert.Equal(t, websocket.MessageBinary, kind)
	assert.Contains(t, string(data[8:]), "graphical")
	input, _ := json.Marshal(rdpclient.Input{Type: "key", Code: 30, Down: true})
	require.NoError(t, conn.Write(ctx, websocket.MessageText, input))
	require.Eventually(t, func() bool { return display.inputs.Load() == 1 }, time.Second, time.Millisecond)
	_, e = broker.Get(created.ID, "bob", false)
	assert.ErrorIs(t, e, ErrNotFound)
	rows, e := broker.List("bob", false)
	require.NoError(t, e)
	assert.Empty(t, rows)
	assert.ErrorIs(t, broker.Stop(created.ID, "bob", false), ErrNotFound)
	frame, e := broker.Frame(created.ID, "alice", false, 0)
	require.NoError(t, e)
	assert.Equal(t, "synthetic graphical frame", string(frame))
	raw, e := os.ReadFile(filepath.Join(root, "desktop-sessions", created.ID, "000000.png.enc"))
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "graphical frame")
	revoked.Store(true)
	for {
		_, _, e = conn.Read(ctx)
		if e != nil {
			break
		}
	}
	require.Eventually(t, func() bool { r, e := broker.Get(created.ID, "alice", false); return e == nil && r.Status == "ended" }, time.Second, time.Millisecond)
	assert.ErrorIs(t, broker.Stop("../../outside", "alice", true), ErrNotFound)
}
func TestCreateGuardAndCapacityFailClosed(t *testing.T) {
	b, e := New(t.TempDir(), make([]byte, 32))
	require.NoError(t, e)
	defer b.CloseAll()
	called := false
	_, e = b.Create(context.Background(), Request{Record: Record{AssetID: "a", OperatorID: "u"}, Open: func(context.Context) (Display, error) { called = true; return nil, ErrUnavailable }, Guard: func(context.Context, string) error { return ErrUnavailable }})
	assert.Error(t, e)
	assert.False(t, called)
	b.CloseAll()
	_, e = b.Create(context.Background(), Request{})
	assert.Error(t, e)
}

type clipboardDisplay struct {
	*fakeDisplay
	mu          sync.Mutex
	state       rdpclient.ClipboardState
	unavailable bool
}

func TestIndexReadsDoNotRaceAtomicReplacement(t *testing.T) {
	b, e := New(t.TempDir(), make([]byte, 32))
	require.NoError(t, e)
	a := &active{record: Record{ID: strings.Repeat("a", 32), AssetID: "a", OperatorID: "alice", Status: "ended"}}
	for i := 0; i < 2000; i++ {
		a.record.Frames = append(a.record.Frames, recorder.DesktopFrame{Index: i, Width: 1280, Height: 720})
	}
	require.NoError(t, os.MkdirAll(filepath.Join(b.root, a.record.ID), 0700))
	require.NoError(t, b.persist(a))
	stop := make(chan struct{})
	done := make(chan struct{})
	readerErrors := make(chan error, 1)
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, e := b.Get(a.record.ID, "alice", false); e != nil {
				select {
				case readerErrors <- e:
				default:
				}
				return
			}
		}
	}()
	defer func() { close(stop); <-done }()
	for i := 0; i < 40; i++ {
		require.NoError(t, b.persist(a))
	}
	select {
	case e := <-readerErrors:
		require.NoError(t, e)
	default:
	}
}

func (d *clipboardDisplay) Input(input rdpclient.Input) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.unavailable {
		d.unavailable = false
		return rdpclient.ErrClipboardNotReady
	}
	d.state.Revision++
	d.state.Text = input.Text
	return nil
}
func (d *clipboardDisplay) ClipboardSnapshot() rdpclient.ClipboardState {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.state
}
func TestClipboardUnavailableAndRepeatedEmptyResultsKeepDesktop(t *testing.T) {
	b, e := New(t.TempDir(), make([]byte, 32))
	require.NoError(t, e)
	defer b.CloseAll()
	d := &clipboardDisplay{fakeDisplay: &fakeDisplay{done: make(chan struct{})}, unavailable: true}
	created, e := b.Create(context.Background(), Request{Record: Record{AssetID: "desktop", OperatorID: "alice", Clipboard: true}, Open: func(context.Context) (Display, error) { return d, nil }, Guard: func(context.Context, string) error { return nil }})
	require.NoError(t, e)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ws/desktop/{sessionID}", b.ServeWS)
	server := httptest.NewServer(mux)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, e := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+created.URL, &websocket.DialOptions{Subprotocols: []string{Subprotocol, TicketPrefix + created.Ticket}})
	require.NoError(t, e)
	defer conn.CloseNow()
	read := func(want string) map[string]string {
		for {
			kind, raw, e := conn.Read(ctx)
			require.NoError(t, e)
			if kind != websocket.MessageText {
				continue
			}
			var message map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(raw, &message))
			var typ string
			require.NoError(t, json.Unmarshal(message["type"], &typ))
			if typ != want {
				continue
			}
			var text string
			if message["text"] != nil {
				require.NoError(t, json.Unmarshal(message["text"], &text))
			}
			return map[string]string{"type": typ, "text": text}
		}
	}
	request := func(text string) {
		raw, _ := json.Marshal(rdpclient.Input{Type: "clipboard_read", Text: text})
		require.NoError(t, conn.Write(ctx, websocket.MessageText, raw))
	}
	request("")
	read("clipboard_error")
	for _, text := range []string{"same", "same", ""} {
		request(text)
		assert.Equal(t, text, read("clipboard")["text"])
	}
	r, e := b.Get(created.ID, "alice", false)
	require.NoError(t, e)
	assert.Equal(t, "active", r.Status)
}
