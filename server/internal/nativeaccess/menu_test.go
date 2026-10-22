package nativeaccess

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/stretchr/testify/require"
)

func TestNativeMenuLayoutLanguageMetricsAndSanitization(t *testing.T) {
	rows := []assetChoice{{ID: "asset-synthetic", Title: "生产 API · 上海", IP: "192.0.2.8", Account: "ops", Desc: "核心 API 服务 · 已固定主机密钥", Monitor: coreassets.MonitorStatus{State: "online", Metrics: &sshclient.Metrics{CPUPercent: 12.4, MemoryPercent: 43.2, DiskPercent: 61.8}, NetworkSentBytesPerSecond: 2048, NetworkReceivedBytesPerSecond: 4096}}}
	for _, tc := range []struct {
		name    string
		width   int
		english bool
	}{{"wide", 110, false}, {"narrow", 56, false}, {"english", 110, true}} {
		t.Run(tc.name, func(t *testing.T) {
			state := &terminalState{english: tc.english}
			output := state.menuPage(rows, "", 0, tc.width, 28, true)
			clean := regexp.MustCompile("\x1b\\[[0-?]*[ -/]*[@-~]").ReplaceAllString(output, "")
			require.Contains(t, clean, "12.4%")
			require.NotContains(t, clean, "asset-synthetic")
			require.NotContains(t, clean, "SFTP: sftp")
			for _, line := range strings.Split(clean, "\n") {
				width := 0
				for _, r := range strings.TrimSuffix(line, "\r") {
					width += cellWidth(r)
				}
				require.LessOrEqual(t, width, tc.width, line)
			}
			if tc.english {
				require.Contains(t, clean, "Hosts")
				require.NotContains(t, clean, "搜索或编号")
			} else {
				require.Contains(t, clean, "主机")
			}
			if folder := os.Getenv("JMS_NATIVE_MENU_REPORT_DIR"); folder != "" {
				require.NoError(t, os.MkdirAll(folder, 0700))
				require.NoError(t, os.WriteFile(filepath.Join(folder, tc.name+".ansi"), []byte(output+state.prompt()), 0600))
			}
		})
	}
	state := &terminalState{plain: true}
	require.NotContains(t, state.menuPage(rows, "", 0, 80, 24, false), "\x1b")
	require.Equal(t, 4, menuSize(56, 24))
	require.Equal(t, 7, menuSize(100, 24))
	require.NotContains(t, fit("恶意\x1b]52;clipboard\x07\n", 18), "\x1b")
}
