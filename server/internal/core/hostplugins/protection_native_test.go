package hostplugins_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/stretchr/testify/require"
)

func TestNativeRootProtectionBlocksOnlySSHAndPreservesManagementSourceAndForeignTables(t *testing.T) {
	h := newNativeTools(t, "root")
	h.success(t, "banhack233", "install", "", nil)
	h.success(t, "banhack233", "start", "", nil)
	p, e := (hostplugins.ProtectionPolicy{Mode: "audit", IgnoreIPs: []string{"198.51.100.23"}, MaxAttempts: 2, FindSeconds: 60, BanSeconds: 60, IntervalSeconds: 1}).Normalize()
	require.NoError(t, e)
	audit := h.success(t, "banhack233", "protection_apply", "", &p)
	require.True(t, audit.DryRun)
	p.Mode = "enforce"
	h.interrupt.Store(true)
	_, e = h.perform(t, "banhack233", "protection_apply", "", &p)
	require.Error(t, e)
	interrupted := h.success(t, "banhack233", "detect", "", nil)
	require.True(t, interrupted.TransitionPending)
	enforced := h.success(t, "banhack233", "protection_apply", "", &p)
	require.False(t, enforced.DryRun)
	require.Equal(t, "enforce", enforced.ProtectionMode)
	require.True(t, enforced.Running)
	require.Contains(t, enforced.Protection.IgnoreIPs, "127.0.0.0/8")
	require.Contains(t, enforced.Protection.IgnoreIPs, "::1")
	require.Contains(t, enforced.Protection.SSHPorts, 22)
	status := h.success(t, "banhack233", "protection_status", "", nil)
	require.Equal(t, "owned", status.FirewallState)
	require.Contains(t, status.Output, "banhack233")
	raw := h.run(t, "read -r v b c < /root/.jumpserver233/plugins/banhack233/manifest; cat /root/.jumpserver233/plugins/banhack233/config-\"$c\".json")
	require.Zero(t, raw.ExitCode)
	var cfg map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw.Stdout), &cfg))
	require.Equal(t, false, cfg["hardening"].(map[string]any)["ssh"].(map[string]any)["enabled"])
	require.Equal(t, false, cfg["malware"].(map[string]any)["direct_kill"])
	require.Zero(t, h.run(t, "ip addr replace 203.0.113.99/32 dev lo; nc -z -w 1 -s 203.0.113.99 127.0.0.1 22").ExitCode)
	management := h.run(t, "printf '%s' \"$SSH_CONNECTION\"")
	peer := strings.Fields(management.Stdout)[0]
	for _, ip := range []string{"203.0.113.99", "198.51.100.23", peer} {
		script := fmt.Sprintf("for n in 1 2 3; do printf 'Oct 16 01:00:00 qa sshd[99]: Failed password for attacker from %s port 5555 ssh2\\n' >> /var/log/auth.log; done", ip)
		require.Zero(t, h.run(t, script).ExitCode)
	}
	require.Eventually(t, func() bool {
		return h.run(t, "nft get element inet banhack233 blocked '{ 203.0.113.99 }'").ExitCode == 0
	}, 15*time.Second, 500*time.Millisecond)
	require.NotZero(t, h.run(t, "nc -z -w 1 -s 203.0.113.99 127.0.0.1 22").ExitCode)
	require.NotZero(t, h.run(t, "nft get element inet banhack233 blocked '{ 198.51.100.23 }'").ExitCode)
	require.NotZero(t, h.run(t, "nft get element inet banhack233 blocked '{ "+peer+" }'").ExitCode)
	require.Zero(t, h.run(t, "nohup nc -l 127.0.0.1 18080 >/dev/null 2>&1 </dev/null & sleep 0.1; nc -z -w 1 -s 203.0.113.99 127.0.0.1 18080").ExitCode)
	restored := h.success(t, "banhack233", "protection_rollback", "", nil)
	require.True(t, restored.DryRun)
	require.True(t, restored.Running)
	require.Zero(t, h.run(t, "nc -z -w 1 -s 203.0.113.99 127.0.0.1 22").ExitCode)
	require.NotZero(t, h.run(t, "nft list table inet banhack233").ExitCode)
	require.Zero(t, h.run(t, "nft add table inet banhack233").ExitCode)
	_, e = h.perform(t, "banhack233", "protection_apply", "", &p)
	require.ErrorIs(t, e, hostplugins.ErrConflict)
	require.False(t, h.success(t, "banhack233", "uninstall", "", nil).Installed)
	require.Zero(t, h.run(t, "nft list table inet banhack233").ExitCode)
	require.Zero(t, h.run(t, "nft delete table inet banhack233").ExitCode)
}
