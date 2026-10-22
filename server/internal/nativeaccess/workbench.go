package nativeaccess

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

// Workbench input and rendering are independent of SSH I/O. Searching never
// fetches inventory; connect and probe still use the existing authorization API.
type hostWorkbench struct {
	rows                             []assetChoice
	actor                            string
	query, number, notice, busy      string
	selected                         int
	searching, info, failed, pasting bool
}

func (m *hostWorkbench) matches() []assetChoice { return filterAssets(m.rows, m.query) }
func (m *hostWorkbench) selection() (assetChoice, bool) {
	rows := m.matches()
	if len(rows) == 0 {
		return assetChoice{}, false
	}
	m.selected = max(0, min(m.selected, len(rows)-1))
	return rows[m.selected], true
}
func (m *hostWorkbench) replace(rows []assetChoice) {
	old, ok := m.selection()
	m.rows = rows
	if ok {
		for i, a := range m.matches() {
			if a.ID == old.ID {
				m.selected = i
				return
			}
		}
	}
	m.selected = 0
}
func (m *hostWorkbench) edit(value string) {
	if len([]rune(m.query+value)) > 128 {
		return
	}
	m.query += value
	m.selected, m.info, m.failed, m.notice = 0, false, false, ""
}
func (m *hostWorkbench) key(key string, size int) string {
	if key == "paste-start" {
		m.pasting, m.searching = true, true
		m.query, m.number, m.selected = "", "", 0
		return "redraw"
	}
	if key == "paste-end" {
		m.pasting = false
		return "redraw"
	}
	if m.pasting {
		if key == "enter" {
			m.edit(" ")
		} else if len([]rune(key)) == 1 {
			m.edit(key)
		}
		return "redraw"
	}
	rows := m.matches()
	switch key {
	case "up", "down", "page-up", "page-down", "home", "end", "tab", "back-tab":
		step := 1
		if key == "up" || key == "back-tab" {
			step = -1
		}
		if key == "page-up" {
			step = -size
		}
		if key == "page-down" {
			step = size
		}
		m.selected = max(0, min(m.selected+step, len(rows)-1))
		if key == "home" {
			m.selected = 0
		}
		if key == "end" {
			m.selected = max(0, len(rows)-1)
		}
		m.number, m.info = "", false
		return "redraw"
	case "escape":
		if m.searching {
			m.searching = false
		} else {
			m.query, m.number, m.selected, m.info = "", "", 0, false
		}
		return "snapshot"
	case "interrupt", "eof":
		return "quit"
	case "refresh":
		return "refresh"
	case "search":
		m.searching = true
		m.number = ""
		return "redraw"
	case "backspace":
		if m.searching {
			r := []rune(m.query)
			if len(r) > 0 {
				m.query = string(r[:len(r)-1])
				m.selected = 0
			}
		} else if len(m.number) > 0 {
			m.number = m.number[:len(m.number)-1]
		}
		return "redraw"
	case "enter":
		if m.searching {
			m.searching = false
			return "connect"
		}
		if m.number != "" {
			n, e := strconv.Atoi(m.number)
			m.number = ""
			if e != nil || n < 1 || n > len(rows) {
				return "invalid-number"
			}
			m.selected = n - 1
		}
		return "connect"
	}
	if m.searching {
		if key != "" && utf8.ValidString(key) {
			m.edit(key)
		}
		return "redraw"
	}
	switch key {
	case "/", "search":
		m.searching = true
		m.query, m.number, m.selected, m.info = "", "", 0, false
		return "redraw"
	case "q":
		return "quit"
	case "r", "refresh":
		return "refresh"
	case "m", "monitor":
		return "monitor"
	case "l":
		return "language"
	case "i", "?":
		m.info = !m.info
		return "snapshot"
	case "n":
		m.selected = min(max(0, len(rows)-1), m.selected+size)
		return "redraw"
	case "p":
		m.selected = max(0, m.selected-size)
		return "redraw"
	}
	if len(key) == 1 && key[0] >= '0' && key[0] <= '9' {
		if len(m.number) < 6 {
			m.number += key
		}
		return "redraw"
	}
	if key != "" && utf8.ValidString(key) {
		m.searching = true
		m.query = ""
		m.edit(key)
		return "redraw"
	}
	return ""
}

type menuKeys struct {
	pending   []byte
	escapeAt  time.Time
	replay    byte
	hasReplay bool
}

func (d *menuKeys) feed(b byte) string {
	d.pending = append(d.pending, b)
	if d.pending[0] == 27 {
		if len(d.pending) == 1 {
			d.escapeAt = time.Now()
			return ""
		}
		if len(d.pending) == 2 && b != '[' && b != 'O' {
			d.pending = nil
			d.replay = b
			d.hasReplay = true
			return "escape"
		}
		seq := string(d.pending)
		keys := map[string]string{"\x1b[A": "up", "\x1b[B": "down", "\x1b[H": "home", "\x1b[F": "end", "\x1b[1~": "home", "\x1b[4~": "end", "\x1b[5~": "page-up", "\x1b[6~": "page-down", "\x1b[Z": "back-tab", "\x1bOA": "up", "\x1bOB": "down", "\x1bOH": "home", "\x1bOF": "end", "\x1b[15~": "refresh", "\x1b[200~": "paste-start", "\x1b[201~": "paste-end"}
		if key, ok := keys[seq]; ok {
			d.pending = nil
			return key
		}
		prefix := false
		for k := range keys {
			prefix = prefix || strings.HasPrefix(k, seq)
		}
		if prefix && len(d.pending) < 12 {
			return ""
		}
		d.pending = nil
		return ""
	}
	if len(d.pending) == 1 {
		keys := map[byte]string{3: "interrupt", 4: "eof", 6: "search", 9: "tab", 10: "enter", 13: "enter", 14: "down", 16: "up", 18: "refresh", 8: "backspace", 127: "backspace"}
		if key, ok := keys[b]; ok {
			d.pending = nil
			return key
		}
		if b < 32 {
			d.pending = nil
			return ""
		}
	}
	if !utf8.FullRune(d.pending) {
		return ""
	}
	r, n := utf8.DecodeRune(d.pending)
	d.pending = nil
	if r == utf8.RuneError && n == 1 {
		return ""
	}
	return string(r)
}
func (d *menuKeys) expire(now time.Time) string {
	if len(d.pending) > 0 && d.pending[0] == 27 && now.Sub(d.escapeAt) > 80*time.Millisecond {
		d.pending = nil
		return "escape"
	}
	return ""
}

type menuResult struct {
	rows []assetChoice
	err  error
}

func (s *terminalState) workbench(parent context.Context, c *apiClient, ch ssh.Channel, input *channelInput) error {
	ctx, cancel := context.WithCancel(parent)
	var fetches sync.WaitGroup
	defer func() { cancel(); fetches.Wait() }()
	redraw := make(chan struct{}, 1)
	s.mu.Lock()
	s.redraw = redraw
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.redraw = nil; s.mu.Unlock() }()
	m := &hostWorkbench{actor: c.actor, busy: "loading"}
	results := make(chan menuResult, 1)
	fetch := func(probe string) {
		fetches.Add(1)
		go func() {
			defer fetches.Done()
			var e error
			if probe != "" {
				e = c.json(ctx, "POST", "/api/v1/assets/"+url.PathEscape(probe)+"/probe", nil, nil)
			}
			var rows []assetChoice
			if e == nil {
				rows, e = c.assets(ctx)
			}
			select {
			case results <- menuResult{rows: rows, err: e}:
			case <-ctx.Done():
			}
		}()
	}
	fetch("")
	d := &menuKeys{}
	view := &menuScreen{writer: ch}
	defer view.leave()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	frame := 0
	paint := func(force bool) error {
		s.mu.Lock()
		w, h := s.cols, s.rows
		s.mu.Unlock()
		return view.draw(s, m, w, h, frame, force)
	}
	if e := paint(true); e != nil {
		return e
	}
	handle := func(key string) (bool, error) {
		s.mu.Lock()
		w, h := s.cols, s.rows
		s.mu.Unlock()
		action := m.key(key, workbenchSize(w, h))
		switch action {
		case "quit":
			return true, nil
		case "language":
			s.english = !s.english
			m.notice = ""
		case "invalid-number":
			m.notice = s.label("编号不在当前结果中。", "Number is outside the current results.")
			m.failed = true
		case "refresh", "monitor":
			if m.busy != "" {
				break
			}
			id := ""
			if action == "monitor" {
				a, ok := m.selection()
				if !ok {
					break
				}
				id = a.ID
			}
			m.busy = "refreshing"
			m.notice = ""
			m.failed = false
			fetch(id)
		case "connect":
			a, ok := m.selection()
			if !ok {
				break
			}
			if !a.Connect {
				m.notice = s.label("此账号只有文件权限，尚未授予 SSH 连接权限。", "This account has file access but no SSH connection grant.")
				m.failed = true
				break
			}
			m.notice = s.label("正在连接所选主机…", "Connecting to the selected host…")
			m.failed = false
			_ = paint(true)
			if e := c.selectTarget(ctx, a.ID); e != nil {
				m.notice = s.label("无法切换目标：当前文件或监控连接可能仍绑定其他主机。请另开固定账号连接。", "Cannot switch targets while file or monitoring channels bind another host. Open a pinned-account connection.")
				m.failed = true
				break
			}
			view.leave()
			_, _ = fmt.Fprintf(ch, "\r\n%s · %s@%s\r\n", safeLabel(a.Title), safeLabel(a.Account), safeLabel(a.IP))
			e := s.relay(ctx, c, ch, a.ID, input)
			m.notice = s.label("已返回主机列表。", "Returned to the host list.")
			m.failed = false
			if e != nil {
				m.notice = s.label("连接结束或需要审批，请在 Web 审批台查看。", "Connection ended or approval required. Check Web reviews.")
				m.failed = true
			}
			d.pending = nil
			return false, paint(true)
		}
		return false, paint(action == "snapshot")
	}
	for {
		if d.hasReplay {
			input.pending = append([]byte{d.replay}, input.pending...)
			d.hasReplay = false
		}
		if len(input.pending) > 0 {
			b := input.pending[0]
			input.pending = input.pending[1:]
			if key := d.feed(b); key != "" {
				done, e := handle(key)
				if done || e != nil {
					return e
				}
			}
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case b, ok := <-input.data:
			if !ok {
				return io.EOF
			}
			if b.err != nil {
				return b.err
			}
			input.pending = b.data
		case <-redraw:
			if e := paint(true); e != nil {
				return e
			}
		case r := <-results:
			m.busy = ""
			if r.err != nil {
				var a *apiError
				if errors.As(r.err, &a) && a.Status == 401 {
					return r.err
				}
				m.notice = s.label("刷新失败，按 r 重试；请检查授权和主机状态。", "Refresh failed. Press r to retry; check grants and host access.")
				m.failed = true
			} else {
				m.replace(r.rows)
				m.notice = s.label("主机列表已更新。", "Host list updated.")
				m.failed = false
			}
			if e := paint(true); e != nil {
				return e
			}
		case now := <-tick.C:
			if key := d.expire(now); key != "" {
				done, e := handle(key)
				if done || e != nil {
					return e
				}
			}
			if m.busy != "" {
				frame++
				if e := paint(false); e != nil {
					return e
				}
			}
		}
	}
}
