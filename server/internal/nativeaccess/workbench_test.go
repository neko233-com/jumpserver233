package nativeaccess

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/stretchr/testify/require"
)

func workbenchRows() []assetChoice {
	return []assetChoice{
		{ID: "asset-api", Title: "生产 API · 上海", IP: "192.0.2.8", Account: "ops", Desc: "核心业务服务 · 连接已固定主机密钥", Connect: true, Monitor: coreassets.MonitorStatus{State: "online", Metrics: &sshclient.Metrics{CPUPercent: 12.4, MemoryPercent: 43.2, DiskPercent: 61.8}, NetworkSentBytesPerSecond: 2048, NetworkReceivedBytesPerSecond: 4096}},
		{ID: "asset-db", Title: "业务数据库 · 新加坡", IP: "198.51.100.16", Account: "dba", Desc: "Singapore standby database", Connect: true, Monitor: coreassets.MonitorStatus{State: "online", Metrics: &sshclient.Metrics{CPUPercent: 3.6, MemoryPercent: 27.1, DiskPercent: 42.0}}},
		{ID: "asset-build", Title: "构建归档 · Build archive", IP: "203.0.113.24", Account: "archive", Desc: "只读归档 / file access", SFTP: true},
	}
}
func TestNativeWorkbenchKeyboardSelectionAndLiveSearch(t *testing.T) {
	m := &hostWorkbench{rows: workbenchRows()}
	require.Equal(t, "redraw", m.key("down", 2))
	require.Equal(t, 1, m.selected)
	require.Equal(t, "connect", m.key("enter", 2))
	a, ok := m.selection()
	require.True(t, ok)
	require.Equal(t, "asset-db", a.ID)
	m.key("page-down", 2)
	require.Equal(t, 2, m.selected)
	m.key("up", 2)
	require.Equal(t, 1, m.selected)
	m.key("home", 2)
	require.Zero(t, m.selected)
	m.key("end", 2)
	require.Equal(t, 2, m.selected)
	m.key("/", 2)
	for _, r := range "SINGAPORE standby" {
		m.key(string(r), 2)
	}
	require.Len(t, m.matches(), 1)
	a, _ = m.selection()
	require.Equal(t, "asset-db", a.ID)
	require.Equal(t, "snapshot", m.key("escape", 2))
	require.False(t, m.searching)
	require.NotEmpty(t, m.query)
	m.key("escape", 2)
	require.Empty(t, m.query)
	require.Len(t, m.matches(), 3)
	m.key("2", 2)
	require.Equal(t, "connect", m.key("enter", 2))
	require.Equal(t, 1, m.selected)
	m.key("9", 2)
	require.Equal(t, "invalid-number", m.key("enter", 2))
	require.Equal(t, 1, m.selected)
	m.key("/", 2)
	m.key("中", 2)
	m.key("文", 2)
	m.key("backspace", 2)
	require.Equal(t, "中", m.query)
	m.key("enter", 2)
	require.False(t, m.searching)
	m.key("/", 2)
	m.key("paste-start", 2)
	m.key("q", 2)
	m.key("enter", 2)
	m.key("r", 2)
	m.key("paste-end", 2)
	require.Equal(t, "q r", m.query)
	require.True(t, m.searching)
	m.key("escape", 2)
	m.key("escape", 2)
	require.Equal(t, "quit", m.key("q", 2))
}
func TestNativeWorkbenchSelectionSurvivesRefreshAndRemoval(t *testing.T) {
	m := &hostWorkbench{rows: workbenchRows(), selected: 1}
	rows := workbenchRows()
	m.replace([]assetChoice{rows[1], rows[0]})
	require.Zero(t, m.selected)
	a, _ := m.selection()
	require.Equal(t, "asset-db", a.ID)
	m.replace(nil)
	_, ok := m.selection()
	require.False(t, ok)
	require.Zero(t, m.selected)
}
func TestNativeWorkbenchKeyDecoderSplitUnicodeAndEscapes(t *testing.T) {
	for _, tc := range []struct{ in, out string }{{"\x1b[A", "up"}, {"\x1bOB", "down"}, {"\x1b[6~", "page-down"}, {"\x1b[200~", "paste-start"}, {"\x1b[201~", "paste-end"}, {"中", "中"}, {"\r", "enter"}, {"\x7f", "backspace"}, {"\x03", "interrupt"}} {
		t.Run(tc.out, func(t *testing.T) {
			d := &menuKeys{}
			var key string
			for _, b := range []byte(tc.in) {
				if k := d.feed(b); k != "" {
					key = k
				}
			}
			require.Equal(t, tc.out, key)
		})
	}
	d := &menuKeys{}
	require.Empty(t, d.feed(27))
	require.Equal(t, "escape", d.expire(time.Now().Add(time.Second)))
	d = &menuKeys{}
	d.feed(27)
	require.Equal(t, "escape", d.feed('r'))
	require.True(t, d.hasReplay)
	require.Equal(t, byte('r'), d.replay)
}
func TestNativeWorkbenchTableFitsEverySupportedPane(t *testing.T) {
	strip := regexp.MustCompile("\x1b\\[[0-?]*[ -/]*[@-~]")
	for _, width := range []int{1, 12, 24, 40, 56, 80, 110, 160} {
		for _, height := range []int{1, 8, 10, 14, 20, 24, 32} {
			for _, english := range []bool{false, true} {
				t.Run(fmt.Sprintf("%dx%d/%t", width, height, english), func(t *testing.T) {
					s := &terminalState{english: english}
					m := &hostWorkbench{rows: workbenchRows(), selected: 1}
					lines := s.workbenchFrame(m, width, height, 0)
					require.LessOrEqual(t, len(lines), height)
					for _, line := range lines {
						require.LessOrEqual(t, visibleWidth(strip.ReplaceAllString(line, "")), width, line)
					}
					if width >= 56 && height >= 20 {
						if width >= 62 {
							require.Contains(t, strings.Join(lines, "\n"), "192.0.2.8")
						} else {
							require.Contains(t, strings.Join(lines, "\n"), "198.51.100.16")
						}
						require.Contains(t, strings.Join(lines, "\n"), menuSelected)
						require.NotContains(t, strings.Join(lines, "\n"), "\x1b[90m")
					}
					if width >= 40 && height >= 20 {
						text := strip.ReplaceAllString(strings.Join(lines, "\n"), "")
						for _, key := range []string{"Enter", "/", "Esc", "r ", "m ", "i ", "l ", "q "} {
							require.Contains(t, text, key)
						}
					}
				})
			}
		}
	}
}
func TestNativeWorkbenchFrameDiffAndIdempotentScreenRestore(t *testing.T) {
	s := &terminalState{}
	m := &hostWorkbench{rows: workbenchRows()}
	var output bytes.Buffer
	v := &menuScreen{writer: &output}
	require.NoError(t, v.draw(s, m, 110, 28, 0, false))
	require.Contains(t, output.String(), "\x1b[?1049h")
	output.Reset()
	require.NoError(t, v.draw(s, m, 110, 28, 0, false))
	require.Empty(t, output.String())
	m.key("down", 10)
	require.NoError(t, v.draw(s, m, 110, 28, 0, false))
	require.NotContains(t, output.String(), "\x1b[2J")
	output.Reset()
	v.leave()
	first := output.String()
	require.Contains(t, first, "\x1b[?25h")
	v.leave()
	require.Equal(t, first, output.String())
}
func TestNativeWorkbenchTextContrast(t *testing.T) {
	luminance := func(rgb [3]float64) float64 {
		var v [3]float64
		for i, x := range rgb {
			x /= 255
			if x <= .04045 {
				v[i] = x / 12.92
			} else {
				v[i] = math.Pow((x+.055)/1.055, 2.4)
			}
		}
		return .2126*v[0] + .7152*v[1] + .0722*v[2]
	}
	bg := luminance([3]float64{15, 17, 28})
	for _, rgb := range [][3]float64{{180, 193, 215}, {232, 237, 247}, {105, 223, 224}, {126, 151, 180}} {
		require.GreaterOrEqual(t, (luminance(rgb)+.05)/(bg+.05), 4.5)
	}
}
func TestNativeWorkbenchExportVisualCases(t *testing.T) {
	dir := os.Getenv("JMS_NATIVE_MENU_REPORT_DIR")
	if dir == "" {
		return
	}
	require.NoError(t, os.MkdirAll(dir, 0700))
	for _, tc := range []struct {
		name     string
		width    int
		english  bool
		selected int
	}{{"workbench-wide", 110, false, 1}, {"workbench-narrow", 56, false, 0}, {"workbench-english", 110, true, 1}} {
		s := &terminalState{english: tc.english}
		m := &hostWorkbench{rows: workbenchRows(), selected: tc.selected}
		var output bytes.Buffer
		v := &menuScreen{writer: &output}
		require.NoError(t, v.draw(s, m, tc.width, 28, 0, true))
		require.NoError(t, os.WriteFile(filepath.Join(dir, tc.name+".ansi"), output.Bytes(), 0600))
	}
}
