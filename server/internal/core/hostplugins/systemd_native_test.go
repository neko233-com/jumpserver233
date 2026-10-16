package hostplugins_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
	"github.com/stretchr/testify/require"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func systemdTools(t *testing.T, user string) *nativeTools {
	t.Helper()
	endpoint := os.Getenv("JMS_TEST_SYSTEMD_FIXTURE_URL")
	if endpoint == "" {
		t.Skip("requires isolated real systemd VM")
	}
	resp, e := http.Get(endpoint)
	require.NoError(t, e)
	defer resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)
	var metadata struct {
		Address     string `json:"address"`
		Fingerprint string `json:"fingerprint"`
		Name        string `json:"container_name"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&metadata))
	require.Regexp(t, `^jms233-systemdvm-[a-f0-9-]{36}$`, metadata.Name)
	address := metadata.Address
	if value := os.Getenv("JMS_TEST_SYSTEMD_NETWORK_ADDR"); value != "" {
		address = value
	}
	host, port, e := net.SplitHostPort(address)
	require.NoError(t, e)
	n, e := strconv.Atoi(port)
	require.NoError(t, e)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	t.Cleanup(cancel)
	h := &nativeTools{ctx: ctx, target: sshclient.Target{Host: host, Port: n, Username: user, HostKeyFingerprint: metadata.Fingerprint}, credentials: sshclient.Credentials{Password: "synthetic-keyhost-password-233"}}
	if user == "root" {
		h.credentials.Password = "synthetic-protection-root-password-233"
	}
	cache, e := hostplugins.NewCache(t.TempDir())
	require.NoError(t, e)
	h.service = hostplugins.New(func(ctx context.Context, _ string) (hostplugins.Transport, error) {
		return sshclient.OpenManagedHost(ctx, h.target, h.credentials)
	}, cache)
	return h
}
func systemdUnit(dir, plugin string) string {
	return "jms233-agent-" + plugin + "-" + hostagent.SHA([]byte(dir))[:16] + ".service"
}
func TestRealSystemdRootSupervisionPreservesPoliciesUpgradesAndBootRecovery(t *testing.T) {
	h := systemdTools(t, "root")
	dir := "/root/.jumpserver233/plugins/banhack233"
	unit := systemdUnit(dir, "banhack233")
	h.success(t, "banhack233", "install", "0.2.2", nil)
	t.Cleanup(func() { h.success(t, "banhack233", "uninstall", "", nil) })
	status := h.success(t, "banhack233", "systemd_status", "", nil)
	require.Equal(t, "disabled", status.SystemdState)
	require.Equal(t, "unavailable", status.AutostartState)
	enabled := h.success(t, "banhack233", "systemd_enable", "", nil)
	require.True(t, enabled.Running)
	require.True(t, enabled.Autostart)
	require.Equal(t, "active", enabled.SystemdState)
	_, e := h.perform(t, "banhack233", "install", "0.2.3", nil)
	require.ErrorIs(t, e, hostplugins.ErrConflict)
	require.Equal(t, "active", h.success(t, "banhack233", "status", "", nil).SystemdState)
	require.Zero(t, h.run(t, "main=$(systemctl show "+unit+" -p MainPID --value); read -r daemon stamp < "+dir+"/pid; [ \"$(cat /proc/$main/cgroup)\" = \"$(cat /proc/$daemon/cgroup)\" ]").ExitCode)
	p, e := (hostplugins.ProtectionPolicy{Mode: "enforce", MaxAttempts: 2, FindSeconds: 60, BanSeconds: 3600, IntervalSeconds: 1}).Normalize()
	require.NoError(t, e)
	protected := h.success(t, "banhack233", "protection_apply", "", &p)
	require.Equal(t, "active", protected.SystemdState)
	require.Equal(t, "ready", protected.RecoveryState)
	existing := h.run(t, "if [ -f "+dir+"/state.json ]; then cat "+dir+"/state.json; else printf '{}'; fi").Stdout
	var prior struct {
		Bans map[string]json.RawMessage `json:"bans"`
	}
	require.NoError(t, json.Unmarshal([]byte(existing), &prior))
	used := map[string]bool{}
	for key := range prior.Bans {
		parts := strings.Split(key, "|")
		if len(parts) > 1 {
			used[parts[1]] = true
		}
	}
	ip := ""
	for n := 10; n < 250; n++ {
		candidate := fmt.Sprintf("203.0.113.%d", n)
		if !used[candidate] {
			ip = candidate
			break
		}
	}
	require.NotEmpty(t, ip)
	require.Zero(t, h.run(t, "ip addr replace "+ip+"/32 dev lo; for n in 1 2 3; do printf 'Oct 16 01:00:00 qa sshd[99]: Failed password for systemdqa from "+ip+" port 5555 ssh2\\n' >> /var/log/auth.log; done").ExitCode)
	blocked := "nft get element inet banhack233 blocked '{ " + ip + " }' >/dev/null"
	require.Eventually(t, func() bool { return h.run(t, blocked).ExitCode == 0 }, 20*time.Second, time.Second)
	oldPID := strings.TrimSpace(h.run(t, "cut -d ' ' -f 1 "+dir+"/pid").Stdout)
	require.Zero(t, h.run(t, "kill -KILL "+oldPID+"; nft delete table inet banhack233").ExitCode)
	require.Eventually(t, func() bool {
		return h.run(t, blocked+"; read -r pid stamp < "+dir+"/pid; [ \"$pid\" != "+oldPID+" ]").ExitCode == 0
	}, 40*time.Second, time.Second)
	up := h.success(t, "banhack233", "upgrade", "", nil)
	require.Equal(t, "0.2.3", up.Version)
	require.Equal(t, "active", up.SystemdState)
	_, e = h.perform(t, "banhack233", "upgrade", "0.2.2", nil)
	require.ErrorIs(t, e, hostplugins.ErrInvalid)
	require.Equal(t, "active", h.success(t, "banhack233", "status", "", nil).SystemdState)
	rolled := h.success(t, "banhack233", "rollback", "", nil)
	require.Equal(t, "0.2.2", rolled.Version)
	require.Equal(t, "active", rolled.SystemdState)
	require.Zero(t, h.run(t, "mkdir -m 700 /etc/systemd/system/"+unit+".d; printf '[Service]\\nEnvironment=JMS_QA_FOREIGN=true\\n' > /etc/systemd/system/"+unit+".d/10-foreign.conf; systemctl daemon-reload").ExitCode)
	_, e = h.perform(t, "banhack233", "start", "", nil)
	require.ErrorIs(t, e, hostplugins.ErrConflict)
	require.Zero(t, h.run(t, "rm /etc/systemd/system/"+unit+".d/10-foreign.conf; rmdir /etc/systemd/system/"+unit+".d; systemctl daemon-reload").ExitCode)
	disabled := h.success(t, "banhack233", "systemd_disable", "", nil)
	require.False(t, disabled.Autostart)
	require.True(t, disabled.Running)
	require.Equal(t, "disabled", disabled.SystemdState)
	h.success(t, "banhack233", "systemd_enable", "", nil)
	// A guest reboot is a real kernel/systemd boot, with the platform idle.
	remote, e := sshclient.OpenManagedHost(h.ctx, h.target, h.credentials)
	require.NoError(t, e)
	_, _ = remote.Run(h.ctx, "systemctl reboot")
	remote.Close()
	time.Sleep(3 * time.Second)
	require.Eventually(t, func() bool {
		remote, e := sshclient.OpenManagedHost(h.ctx, h.target, h.credentials)
		if e != nil {
			return false
		}
		defer remote.Close()
		r, e := remote.Run(h.ctx, "systemctl is-active "+unit+" >/dev/null; "+blocked)
		return e == nil && r.ExitCode == 0
	}, 150*time.Second, 3*time.Second)
	after := h.success(t, "banhack233", "status", "", nil)
	require.True(t, after.Running)
	require.Equal(t, "active", after.SystemdState)
	require.Equal(t, "ready", after.RecoveryState)
	events := h.success(t, "banhack233", "events", "", nil)
	require.NotNil(t, events.Events)
	require.GreaterOrEqual(t, len(events.Events.Events), 4)
	h.success(t, "banhack233", "uninstall", "", nil)
	require.Zero(t, h.run(t, "test \"$(systemctl show "+unit+" -p LoadState --value)\" = not-found; test -f "+dir+"/state.json; test -f "+dir+"/agent-events.json").ExitCode)
}
func TestRealSystemdUserExporterHasNoSystemScopeAndKeepsManualLifecycle(t *testing.T) {
	h := systemdTools(t, "systemdqa")
	dir := "/home/systemdqa/.jumpserver233/plugins/node_exporter"
	unit := systemdUnit(dir, "node_exporter")
	h.success(t, "node_exporter", "install", "1.12.0", nil)
	t.Cleanup(func() { h.success(t, "node_exporter", "uninstall", "", nil) })
	enabled := h.success(t, "node_exporter", "systemd_enable", "", nil)
	require.Equal(t, "active", enabled.SystemdState)
	require.NotEqual(t, "0", enabled.UID)
	require.Zero(t, h.run(t, "test -f /home/systemdqa/.config/systemd/user/"+unit+"; test ! -e /etc/systemd/system/"+unit).ExitCode)
	metrics := h.success(t, "node_exporter", "metrics", "", nil)
	require.Contains(t, metrics.Output, "node_cpu_seconds_total")
	up := h.success(t, "node_exporter", "upgrade", "", nil)
	require.Equal(t, "1.12.1", up.Version)
	require.Equal(t, "active", up.SystemdState)
	h.success(t, "node_exporter", "rollback", "", nil)
	disabled := h.success(t, "node_exporter", "autostart_disable", "", nil)
	require.True(t, disabled.Running)
	require.False(t, disabled.Autostart)
	require.Equal(t, "disabled", disabled.SystemdState)
	h.success(t, "node_exporter", "stop", "", nil)
	h.success(t, "node_exporter", "start", "", nil)
	h.success(t, "node_exporter", "systemd_enable", "", nil)
	removed := h.success(t, "node_exporter", "uninstall", "", nil)
	require.False(t, removed.Installed)
	require.False(t, removed.Running)
}
