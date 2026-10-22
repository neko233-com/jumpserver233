package nativeaccess

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"unicode"

	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
	"golang.org/x/crypto/ssh"
)

type terminalState struct {
	mu             sync.Mutex
	cols, rows     int
	socket         *websocket.Conn
	redraw         chan struct{}
	english, plain bool
}

func (s *terminalState) resize(ctx context.Context, cols, rows int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cols, s.rows = cols, rows
	select {
	case s.redraw <- struct{}{}:
	default:
	}
	if s.socket != nil {
		raw, _ := json.Marshal(map[string]any{"type": "resize", "cols": cols, "rows": rows})
		_ = s.socket.Write(ctx, websocket.MessageText, raw)
	}
}
func safeLabel(value string) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\x1b' {
			return ' '
		}
		return r
	}, value)
	r := []rune(value)
	if len(r) > 100 {
		return string(r[:100]) + "…"
	}
	return value
}

// Relay preserves the exact binary/control frame protocol used by Web SSH and
// jms. All command capture, review, directory proof and recorder work stays in
// the existing gateway. Raw direct-tcpip forwarding is intentionally rejected.
func (s *terminalState) relay(ctx context.Context, c *apiClient, ch ssh.Channel, assetID string, input *channelInput) error {
	id, release, e := c.holdTarget(ctx)
	if e != nil {
		return e
	}
	defer release()
	if id != assetID {
		return errTargetBusy
	}
	s.mu.Lock()
	cols, rows := s.cols, s.rows
	s.mu.Unlock()
	created, e := c.createSession(ctx, assetID, cols, rows)
	if e != nil {
		return e
	}
	defer c.closeSession(created.SessionID)
	u, e := url.Parse(created.WebSocketURL)
	if e != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(u.Path, "/ws/") || created.Ticket == "" {
		return errors.New("invalid terminal capability")
	}
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ws, _, e := websocket.Dial(wctx, "ws://native.ssh.invalid"+created.WebSocketURL, &websocket.DialOptions{HTTPClient: c.transport.client, Subprotocols: []string{gateway.TerminalSubprotocol, gateway.TicketSubprotocol(created.Ticket)}})
	if e != nil {
		return e
	}
	defer ws.CloseNow()
	ws.SetReadLimit(64 * 1024)
	if ws.Subprotocol() != gateway.TerminalSubprotocol {
		return errors.New("invalid terminal protocol")
	}
	s.mu.Lock()
	s.socket = ws
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.socket = nil; s.mu.Unlock() }()
	if created.Watermark != "" {
		_, _ = fmt.Fprintf(ch, "\r\n%s\r\n", safeLabel(created.Watermark))
	}
	errorsOut := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	defer func() { cancel(); _ = ws.CloseNow(); workers.Wait() }()
	go func() {
		defer workers.Done()
		for {
			data, e := input.next(wctx)
			if e != nil {
				errorsOut <- e
				return
			}
			s.mu.Lock()
			e = ws.Write(wctx, websocket.MessageBinary, data)
			s.mu.Unlock()
			if e != nil {
				errorsOut <- e
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		for {
			kind, data, e := ws.Read(wctx)
			if e != nil {
				errorsOut <- e
				return
			}
			if kind == websocket.MessageBinary {
				if _, e = ch.Write(data); e != nil {
					errorsOut <- e
					return
				}
			} else {
				var notice struct {
					Type     string `json:"type"`
					Message  string `json:"message"`
					ReviewID string `json:"review_id"`
					RuleName string `json:"rule_name"`
				}
				if json.Unmarshal(data, &notice) == nil && notice.Type != "" {
					_, _ = fmt.Fprintf(ch, "\r\n[%s] %s %s %s\r\n", safeLabel(notice.Type), safeLabel(notice.Message), safeLabel(notice.RuleName), safeLabel(notice.ReviewID))
				}
			}
		}
	}()
	e = <-errorsOut
	cancel()
	if websocket.CloseStatus(e) == websocket.StatusNormalClosure || websocket.CloseStatus(e) == websocket.StatusGoingAway {
		return nil
	}
	return e
}

type inputBlock struct {
	data []byte
	err  error
}
type channelInput struct {
	data    chan inputBlock
	ctx     context.Context
	ch      ssh.Channel
	pending []byte
}

// Exactly one input pump lives for the entire SSH channel, including repeated
// menu/target transitions. A cancelled relay leaves the next input for the
// menu. Menu reads one byte at a time to avoid terminal line-editor prefetch.
func inputFor(ctx context.Context, ch ssh.Channel) *channelInput {
	in := &channelInput{data: make(chan inputBlock), ctx: ctx, ch: ch}
	go func() {
		defer close(in.data)
		for {
			buffer := make([]byte, 8192)
			n, e := ch.Read(buffer)
			if n > 0 {
				select {
				case in.data <- inputBlock{data: buffer[:n]}:
				case <-ctx.Done():
					return
				}
			}
			if e != nil {
				select {
				case in.data <- inputBlock{err: e}:
				case <-ctx.Done():
				}
				return
			}
		}
	}()
	return in
}
func (in *channelInput) next(ctx context.Context) ([]byte, error) {
	if len(in.pending) > 0 {
		v := in.pending
		in.pending = nil
		return v, nil
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case b, ok := <-in.data:
		if !ok {
			return nil, io.EOF
		}
		return b.data, b.err
	}
}
func (in *channelInput) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	b, e := in.next(in.ctx)
	if e != nil {
		return 0, e
	}
	p[0] = b[0]
	in.pending = b[1:]
	return 1, nil
}
func (in *channelInput) Write(p []byte) (int, error) { return in.ch.Write(p) }
