package nativeaccess

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	menuForeground = "\x1b[38;2;232;237;247m"
	menuBackground = "\x1b[48;2;15;17;28m"
	menuMuted      = "38;2;180;193;215"
	menuAccent     = "38;2;105;223;224"
	menuBorder     = "38;2;126;151;180"
	menuSelected   = "48;2;34;69;88;38;2;255;255;255;1"
)

func ansi(code, text string) string {
	return "\x1b[" + code + "m" + text + "\x1b[0m" + menuBackground + menuForeground
}
func (s *terminalState) busyLabel(task string) string {
	if task == "loading" {
		return s.label("正在加载主机…", "Loading hosts…")
	}
	return s.label("正在刷新主机…", "Refreshing hosts…")
}
func visibleWidth(text string) int {
	n := 0
	for _, r := range text {
		n += cellWidth(r)
	}
	return n
}
func legend(s *terminalState, width int) []string {
	groups := []string{s.label("↑↓ 选择", "↑↓ Select"), s.label("Enter 连接", "Enter Connect"), s.label("/ 即时搜索", "/ Search"), s.label("Esc 返回/清空", "Esc Back/Clear"), s.label("r 刷新", "r Refresh"), s.label("m 监控", "m Monitor"), s.label("i 详情", "i Details"), s.label("l 中/EN", "l 中/EN"), s.label("q 退出", "q Quit")}
	var lines []string
	line := ""
	for _, g := range groups {
		next := g
		if line != "" {
			next = line + "   " + g
		}
		// fit applies the shared 100-rune label bound. Wrap help before that
		// bound as well, so wide English panes never hide the final shortcut.
		if visibleWidth(next) > max(1, min(width-2, 98)) && line != "" {
			lines = append(lines, " "+line)
			line = g
		} else {
			line = next
		}
	}
	if line != "" {
		lines = append(lines, " "+line)
	}
	return lines
}

func legendLine(line string, width int) string {
	line = strings.TrimRight(fit(line, width), " ")
	parts := strings.SplitN(line, "Enter", 2)
	if len(parts) == 2 {
		return ansi(menuMuted, parts[0]) + ansi("1;"+menuAccent, "Enter") + ansi(menuMuted, parts[1])
	}
	return ansi(menuMuted, line)
}
func workbenchSize(width, height int) int {
	if width < 24 || height < 10 {
		return 1
	}
	if height < 20 {
		fixed := 9
		if height >= 14 {
			fixed = 11
		}
		return max(1, min(12, height-fixed))
	}
	details := 1
	if height >= 20 {
		details = 3
	}
	zh, en := &terminalState{}, &terminalState{english: true}
	help := max(len(legend(zh, width)), len(legend(en, width)))
	return max(1, min(12, height-(6+1+details+1+help)))
}

type menuColumn struct {
	key   string
	width int
}

func columns(width int) []menuColumn {
	// The first two cells reserve selection + number. Details below retain
	// hidden columns on small panes, so no row becomes a truncated blob.
	space := width - 7
	if width >= 112 {
		return []menuColumn{{"title", space - 23 - 11 - 9 - 7 - 7 - 10}, {"ip", 23}, {"account", 11}, {"state", 9}, {"cpu", 7}, {"memory", 7}}
	}
	if width >= 82 {
		return []menuColumn{{"title", space - 23 - 11 - 9 - 6}, {"ip", 23}, {"account", 11}, {"state", 9}}
	}
	if width >= 62 {
		return []menuColumn{{"title", space - 23 - 9 - 4}, {"ip", 23}, {"state", 9}}
	}
	return []menuColumn{{"title", space - 7 - 2}, {"state", 7}}
}
func (s *terminalState) stateLabel(a assetChoice) string {
	if !a.Connect {
		return s.label("仅文件", "Files")
	}
	switch a.Monitor.State {
	case "online":
		return s.label("在线", "Online")
	case "offline":
		return s.label("离线", "Offline")
	default:
		return s.label("待检测", "Unknown")
	}
}
func (s *terminalState) tableLine(a assetChoice, index int, selected, header bool, width int) string {
	cols := columns(width)
	var b strings.Builder
	if header {
		b.WriteString("   #  ")
	} else if selected {
		b.WriteString(" ❯ " + fit(strconv.Itoa(index+1), 3))
	} else {
		b.WriteString("   " + fit(strconv.Itoa(index+1), 3))
	}
	for i, col := range cols {
		if i > 0 {
			b.WriteString("  ")
		}
		v := ""
		if header {
			switch col.key {
			case "title":
				v = s.label("主机名称", "HOST")
			case "ip":
				v = s.label("地址", "ADDRESS")
			case "account":
				v = s.label("账号", "ACCOUNT")
			case "state":
				v = s.label("状态", "STATE")
			case "cpu":
				v = "CPU"
			case "memory":
				v = s.label("内存", "MEMORY")
			}
		} else {
			switch col.key {
			case "title":
				v = a.Title
			case "ip":
				v = a.IP
			case "account":
				v = a.Account
			case "state":
				v = s.stateLabel(a)
			case "cpu", "memory":
				v = "—"
				if a.Monitor.Metrics != nil {
					p := a.Monitor.Metrics.CPUPercent
					if col.key == "memory" {
						p = a.Monitor.Metrics.MemoryPercent
					}
					v = fmt.Sprintf("%.1f%%", p)
				}
			}
		}
		b.WriteString(fit(v, max(1, col.width)))
	}
	line := b.String()
	line += strings.Repeat(" ", max(0, width-visibleWidth(line)))
	if header {
		return ansi("1;"+menuAccent, line)
	}
	if selected {
		return ansi(menuSelected, line)
	}
	return menuForeground + line
}
func (s *terminalState) workbenchFrame(m *hostWorkbench, width, height, frame int) []string {
	width = max(1, min(width, 180))
	height = max(1, height)
	if width < 24 || height < 10 {
		lines := []string{ansi(menuAccent, fit("JumpServer233", width)), fit(s.label("请扩大终端窗口", "Enlarge the terminal"), width), fit("q / Ctrl-C", width)}
		return lines[:min(height, len(lines))]
	}
	if height < 20 {
		return s.compactWorkbenchFrame(m, width, height, frame)
	}
	rows := m.matches()
	size := workbenchSize(width, height)
	page := m.selected / size
	start := page * size
	end := min(start+size, len(rows))
	if start >= len(rows) {
		start = 0
		end = min(size, len(rows))
	}
	brand := " JumpServer233"
	subtitle := s.label(" / SSH 主机工作台", " / SSH host workbench")
	if visibleWidth(brand+subtitle) > width {
		subtitle = " / SSH"
	}
	if visibleWidth(brand+subtitle) > width {
		subtitle = ""
	}
	lines := []string{ansi("1;"+menuAccent, brand) + ansi("1", subtitle)}
	summary := fmt.Sprintf(" %s %d / %d   %s %d/%d", s.label("主机", "Hosts"), len(rows), len(m.rows), s.label("页", "Page"), page+1, max(1, (len(rows)+size-1)/size))
	lines = append(lines, ansi(menuMuted, strings.TrimRight(fit(summary, width), " ")))
	query := m.query
	if query == "" {
		query = s.label("名称 · 备注 · IP", "title · description · IP")
	}
	if m.searching {
		query = m.query + "▏"
	}
	if m.number != "" {
		query = "#" + m.number
	}
	search := " / " + s.label("搜索或编号", "Search or number") + "  " + query
	code := menuMuted
	if m.searching || m.number != "" {
		code = "1;" + menuAccent
	}
	lines = append(lines, ansi(code, strings.TrimRight(fit(search, width), " ")), "", s.tableLine(assetChoice{}, 0, false, true, width), ansi(menuBorder, strings.Repeat("─", width)))
	if len(rows) == 0 {
		message := s.label("没有匹配主机。按 Esc 清空筛选。", "No matching hosts. Press Esc to clear.")
		if m.busy != "" {
			message = s.label("正在获取已授权主机…", "Fetching authorized hosts…")
		}
		lines = append(lines, strings.TrimRight(fit(" "+message, width), " "))
	} else {
		for i := start; i < end; i++ {
			lines = append(lines, s.tableLine(rows[i], i, i == m.selected, false, width))
		}
	}
	lines = append(lines, ansi(menuBorder, strings.Repeat("─", width)))
	a, ok := m.selection()
	details := []string{s.label(" 暂无选中主机", " No selected host")}
	if ok {
		details = []string{" " + s.label("已选", "Selected") + ": " + a.Title + " · " + a.IP + " · " + a.Account}
		if height >= 20 {
			metrics := s.label("监控: 暂无指标，按 m 检测", "Monitoring: no metrics; press m to probe")
			if a.Monitor.Metrics != nil {
				x := a.Monitor.Metrics
				metrics = fmt.Sprintf("CPU %.1f%%   RAM %.1f%%   DISK %.1f%%   ↑%s  ↓%s", x.CPUPercent, x.MemoryPercent, x.DiskPercent, rate(a.Monitor.NetworkSentBytesPerSecond), rate(a.Monitor.NetworkReceivedBytesPerSecond))
			}
			details = append(details, " "+metrics, " "+a.Desc)
		}
		if m.info {
			details[0] = " " + s.label("固定连接", "Pinned login") + ": " + m.actor + "#" + a.ID
			if len(details) > 1 {
				details[1] = " " + a.Account + " | " + a.IP
			}
			if len(details) > 2 {
				details[2] = " SFTP: /" + a.ID + "/"
			}
		}
	}
	for _, line := range details {
		lines = append(lines, ansi(menuMuted, strings.TrimRight(fit(line, width), " ")))
	}
	if height >= 20 {
		for len(details) < 3 {
			lines = append(lines, "")
			details = append(details, "")
		}
	}
	notice := m.notice
	noticeCode := menuAccent
	if m.busy != "" {
		notice = string([]rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")[frame%10]) + " " + s.busyLabel(m.busy)
	} else if m.failed {
		noticeCode = "1;38;2;255;163;163"
	}
	lines = append(lines, ansi(noticeCode, strings.TrimRight(fit(" "+notice, width), " ")))
	for _, line := range legend(s, width) {
		lines = append(lines, legendLine(line, width))
	}
	return lines
}

func (s *terminalState) compactWorkbenchFrame(m *hostWorkbench, width, height, frame int) []string {
	rows := m.matches()
	size := workbenchSize(width, height)
	start := m.selected / size * size
	q := m.query
	if m.searching {
		q += "▏"
	}
	if m.number != "" {
		q = "#" + m.number
	}
	lines := []string{ansi("1;"+menuAccent, fit(" JumpServer233", width)), ansi(menuMuted, fit(" "+s.label("搜索或编号", "Search or number")+" "+q, width)), s.tableLine(assetChoice{}, 0, false, true, width), ansi(menuBorder, strings.Repeat("─", width))}
	if len(rows) == 0 {
		lines = append(lines, fit(s.label(" 没有匹配主机", " No matching hosts"), width))
	} else {
		for i := start; i < min(start+size, len(rows)); i++ {
			lines = append(lines, s.tableLine(rows[i], i, i == m.selected, false, width))
		}
	}
	lines = append(lines, ansi(menuBorder, strings.Repeat("─", width)))
	if height >= 14 {
		a, ok := m.selection()
		v := ""
		if ok {
			v = " " + a.IP + " · " + a.Account
		}
		lines = append(lines, ansi(menuMuted, fit(v, width)))
	}
	v := m.notice
	if m.busy != "" {
		v = string([]rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")[frame%10]) + " " + s.busyLabel(m.busy)
	}
	lines = append(lines, ansi(menuAccent, fit(" "+v, width)))
	for _, v := range []string{s.label(" ↑↓ 选择  Enter 连接", " ↑↓ Select  Enter Connect"), s.label(" / 搜索  Esc 返回  q 退出", " / Search  Esc Back  q Quit")} {
		lines = append(lines, legendLine(v, width))
	}
	if height >= 14 {
		lines = append(lines, legendLine(s.label(" r 刷新  m 监控  l EN", " r Refresh  m Monitor  l 中"), width))
	}
	return lines
}

// Redraw only changed rows. Avoid a full clear and flicker on every keypress,
// and restore the normal screen/cursor before handing bytes to the real shell.
type menuScreen struct {
	writer   io.Writer
	previous []string
	width    int
	active   bool
}

func (v *menuScreen) draw(s *terminalState, m *hostWorkbench, width, height, frame int, force bool) error {
	lines := s.workbenchFrame(m, width, height, frame)
	var b strings.Builder
	if !v.active {
		b.WriteString("\x1b[?1049h\x1b[?25l\x1b[?2004h")
		v.active = true
		force = true
	}
	if force || v.width != width {
		b.WriteString(menuBackground + menuForeground + "\x1b[2J\x1b[H")
		v.previous = nil
	}
	for i, line := range lines {
		if i >= len(v.previous) || v.previous[i] != line {
			fmt.Fprintf(&b, "\x1b[%d;1H%s%s\x1b[2K%s", i+1, menuBackground, menuForeground, line)
		}
	}
	for i := len(lines); i < len(v.previous); i++ {
		fmt.Fprintf(&b, "\x1b[%d;1H\x1b[2K", i+1)
	}
	v.previous = append(v.previous[:0], lines...)
	v.width = width
	if b.Len() == 0 {
		return nil
	}
	_, e := io.WriteString(v.writer, b.String())
	return e
}
func (v *menuScreen) leave() {
	if v.active {
		_, _ = io.WriteString(v.writer, "\x1b[0m\x1b[?2004l\x1b[?25h\x1b[?1049l")
		v.active = false
		v.previous = nil
	}
}
