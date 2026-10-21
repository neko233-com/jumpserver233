package nativeaccess

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type terminalState struct {
	mu         sync.Mutex
	cols, rows int
	socket     *websocket.Conn
}

func (s *terminalState) resize(ctx context.Context, cols, rows int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cols, s.rows = cols, rows
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
func (s *terminalState) menu(ctx context.Context, c *apiClient, ch ssh.Channel, input *channelInput) error {
	t := term.NewTerminal(input, "搜索/Search (编号/number, /关键词, r, q)> ")
	_, _ = io.WriteString(t, "\r\nJumpServer233 · SSH / SFTP\r\n名称 title · 备注 desc · IP · 账号 account\r\n退出目标主机后返回列表 / Exit the target shell to return here.\r\nSFTP: sftp -P 2222 <platform-user>@<bastion>; ls /\r\n")
	query := ""
	page := 0
	for {
		rows, e := c.assets(ctx)
		if e != nil {
			return e
		}
		filtered := filterAssets(rows, query)
		if page*15 >= len(filtered) {
			page = 0
		}
		_, _ = fmt.Fprintf(t, "\r\n%d servers / 服务器; search=%s; page=%d\r\n", len(filtered), safeLabel(query), page+1)
		for i := page * 15; i < len(filtered) && i < (page+1)*15; i++ {
			a := filtered[i]
			_, _ = fmt.Fprintf(t, "%d) %s | %s | %s\r\n   %s\r\n   SFTP: /%s/\r\n", i+1, safeLabel(a.Title), safeLabel(a.IP), safeLabel(a.Account), safeLabel(a.Desc), a.ID)
		}
		_, _ = io.WriteString(t, "r 刷新/refresh · n 下一页/next · p 上一页/previous · q 退出/quit\r\n")
		line, e := t.ReadLine()
		if e != nil {
			return e
		}
		line = strings.TrimSpace(line)
		switch line {
		case "q", "quit", "exit":
			return nil
		case "r", "":
			continue
		case "n":
			page++
			continue
		case "p":
			if page > 0 {
				page--
			}
			continue
		}
		if !strings.HasPrefix(line, "/") {
			if n, e := strconv.Atoi(line); e == nil && n >= 1 && n <= len(filtered) {
				selected := filtered[n-1]
				if !selected.Connect {
					_, _ = io.WriteString(t, "SSH access not granted / 未授予 SSH 连接权限\r\n")
					continue
				}
				_, _ = fmt.Fprintf(t, "Connecting / 正在连接: %s (%s)\r\n", safeLabel(selected.Title), safeLabel(selected.Account))
				if e = s.relay(ctx, c, ch, selected.ID, input); e != nil {
					var denied *apiError
					if errors.As(e, &denied) && denied.ReviewID != "" {
						_, _ = fmt.Fprintf(t, "Login approval pending / 等待登录审批: %s; retry after approval / 批准后重试\r\n", safeLabel(denied.ReviewID))
					} else {
						_, _ = io.WriteString(t, "Connection closed or denied / 连接已关闭或拒绝\r\n")
					}
				}
				continue
			}
		}
		query = strings.TrimPrefix(line, "/")
		page = 0
	}
}

// Relay preserves the exact binary/control frame protocol used by Web SSH and
// jms. All command capture, review, directory proof and recorder work stays in
// the existing gateway. Raw direct-tcpip forwarding is intentionally rejected.
func (s *terminalState) relay(ctx context.Context, c *apiClient, ch ssh.Channel, assetID string, input *channelInput) error {
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
