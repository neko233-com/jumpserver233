package nativeaccess

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func cellWidth(r rune) int {
	if unicode.Is(unicode.Mn, r) {
		return 0
	}
	if r >= 0x1100 && (r <= 0x115f || r >= 0x2e80 && r <= 0xa4cf || r >= 0xac00 && r <= 0xd7af || r >= 0xf900 && r <= 0xfaff || r >= 0xfe10 && r <= 0xfe6f || r >= 0xff01 && r <= 0xff60 || r >= 0x1f300) {
		return 2
	}
	return 1
}
func fit(value string, width int) string {
	value = safeLabel(value)
	if width <= 0 {
		return ""
	}
	total := 0
	for _, r := range value {
		total += cellWidth(r)
	}
	limit := width
	if total > width {
		limit--
	}
	var b strings.Builder
	n := 0
	for _, r := range value {
		w := cellWidth(r)
		if n+w > limit {
			break
		}
		b.WriteRune(r)
		n += w
	}
	result := b.String() + strings.Repeat(" ", max(0, limit-n))
	if total > width {
		result += "…"
	}
	return result
}
func (s *terminalState) label(zh, en string) string {
	if s.english {
		return en
	}
	return zh
}
func (s *terminalState) prompt() string {
	return s.label(" 搜索或编号 › ", " Search or number › ")
}
func rate(v float64) string {
	if v >= 1024*1024 {
		return fmt.Sprintf("%.0fM/s", v/(1024*1024))
	}
	if v >= 1024 {
		return fmt.Sprintf("%.0fK/s", v/1024)
	}
	return fmt.Sprintf("%.0fB/s", max(0, v))
}
func menuSize(width, height int) int {
	lines := 2
	if width < 88 {
		lines = 3
	}
	return max(1, min(12, (height-10)/lines))
}
func (s *terminalState) menuPage(rows []assetChoice, query string, page, width, height int, monitor bool) string {
	width = max(24, min(width, 140))
	size := menuSize(width, height)
	start := page * size
	end := min(start+size, len(rows))
	var b strings.Builder
	paint := func(code, text string) string {
		if s.plain {
			return text
		}
		return "\x1b[" + code + "m" + text + "\x1b[0m"
	}
	if !s.plain {
		b.WriteString("\x1b[2J\x1b[H")
	}
	if width < 56 {
		fmt.Fprintf(&b, "\r\n %s · SSH\r\n", paint("1;36", "JumpServer233"))
	} else {
		fmt.Fprintf(&b, "\r\n %s  %s\r\n", paint("1;36", "JumpServer233"), paint("90", s.label("安全运维 · SSH / SFTP", "Secure operations · SSH / SFTP")))
	}
	fmt.Fprintf(&b, " %s\r\n", paint("90", strings.Repeat("─", width-2)))
	fmt.Fprintf(&b, " %s %d   %s %d/%d", s.label("主机", "Hosts"), len(rows), s.label("页", "Page"), page+1, max(1, (len(rows)+size-1)/size))
	if query != "" {
		fmt.Fprintf(&b, "   %s: %s", s.label("筛选", "Filter"), fit(query, max(8, width-35)))
	}
	b.WriteString("\r\n\r\n")
	for i := start; i < end; i++ {
		a := rows[i]
		status := a.Monitor.State
		if status == "" {
			status = "unknown"
		}
		if width >= 88 {
			fmt.Fprintf(&b, " %s %s %s %s %s\r\n", paint("36", fit(strconv.Itoa(i+1), 3)), paint("1", fit(a.Title, width-54)), fit(a.IP, 20), fit(a.Account, 12), paint("90", fit(status, 8)))
		} else {
			fmt.Fprintf(&b, " %s %s\r\n", paint("36", fit(strconv.Itoa(i+1), 3)), paint("1", strings.TrimRight(fit(a.Title, width-7), " ")))
			fmt.Fprintf(&b, "     %s\r\n", strings.TrimSpace(fit(a.IP+" · "+a.Account+" · "+status, width-6)))
		}
		if monitor && a.Monitor.Metrics != nil {
			m := a.Monitor.Metrics
			fmt.Fprintf(&b, "     %s\r\n", paint("90", strings.TrimSpace(fit(fmt.Sprintf("CPU %.1f%% RAM %.1f%% DISK %.1f%% ↑%s ↓%s", m.CPUPercent, m.MemoryPercent, m.DiskPercent, rate(a.Monitor.NetworkSentBytesPerSecond), rate(a.Monitor.NetworkReceivedBytesPerSecond)), width-6))))
		} else if a.Desc != "" {
			fmt.Fprintf(&b, "     %s\r\n", paint("90", strings.TrimRight(fit(a.Desc, width-6), " ")))
		}
	}
	if len(rows) == 0 {
		fmt.Fprintf(&b, " %s\r\n", s.label("没有匹配主机，请修改关键词。", "No matching hosts. Change your search."))
	}
	fmt.Fprintf(&b, "\r\n %s\r\n", paint("90", s.label("编号连接 · /关键词搜索 · r 刷新", "Number to connect · /search · r refresh")))
	fmt.Fprintf(&b, " %s\r\n", paint("90", s.label("n/p 翻页 · m 监控 · i 文件信息", "n/p pages · m monitoring · i files")))
	fmt.Fprintf(&b, " %s\r\n\r\n", paint("90", s.label("en English · q 退出", "zh 中文 · q quit")))
	return b.String()
}
func (s *terminalState) menu(ctx context.Context, c *apiClient, ch ssh.Channel, input *channelInput) error {
	t := term.NewTerminal(input, s.prompt())
	query := ""
	page := 0
	monitor := true
	notice := ""
	for {
		rows, e := c.assets(ctx)
		if e != nil {
			return e
		}
		filtered := filterAssets(rows, query)
		s.mu.Lock()
		width, height := s.cols, s.rows
		s.mu.Unlock()
		size := menuSize(width, height)
		if page*size >= len(filtered) {
			page = 0
		}
		_ = t.SetSize(width, height)
		t.SetPrompt(s.prompt())
		_, _ = io.WriteString(t, s.menuPage(filtered, query, page, width, height, monitor))
		if notice != "" {
			_, _ = io.WriteString(t, " "+notice+"\r\n")
			notice = ""
		}
		line, e := t.ReadLine()
		if e != nil {
			return e
		}
		line = strings.TrimSpace(line)
		switch line {
		case "q", "quit", "exit":
			return nil
		case "en":
			s.english = true
			continue
		case "zh":
			s.english = false
			continue
		case "r", "":
			continue
		case "n":
			page++
			continue
		case "p":
			page = max(0, page-1)
			continue
		case "m", "monitor":
			id, release, e := c.holdTarget(ctx)
			if e != nil {
				notice = e.Error()
				continue
			}
			e = c.json(ctx, "POST", "/api/v1/assets/"+url.PathEscape(id)+"/probe", nil, nil)
			release()
			if e != nil {
				notice = s.label("监控刷新失败，请检查权限及主机连接。", "Monitoring refresh failed. Check permissions and host access.")
			}
			monitor = true
			continue
		case "i":
			id, release, e := c.holdTarget(ctx)
			if e != nil {
				notice = e.Error()
				continue
			}
			release()
			notice = s.label("XTerminal 用户名: ", "XTerminal username: ") + c.actor + "#" + id + "  |  SFTP: /" + id + "/"
			continue
		}
		if !strings.HasPrefix(line, "/") {
			if n, e := strconv.Atoi(line); e == nil && n >= 1 && n <= len(filtered) {
				a := filtered[n-1]
				if !a.Connect {
					notice = s.label("未授予 SSH 权限", "SSH permission required")
					continue
				}
				if e = c.selectTarget(ctx, a.ID); e != nil {
					notice = e.Error()
					continue
				}
				if !s.plain {
					_, _ = io.WriteString(ch, "\x1b[2J\x1b[H")
				}
				_, _ = fmt.Fprintf(ch, "%s · %s@%s\r\n", safeLabel(a.Title), safeLabel(a.Account), safeLabel(a.IP))
				if e = s.relay(ctx, c, ch, a.ID, input); e != nil {
					notice = s.label("连接结束或需要审批，请在 Web 审批台查看。", "Connection ended or approval required. Check Web reviews.")
				}
				continue
			}
		}
		query = strings.TrimPrefix(line, "/")
		page = 0
	}
}
