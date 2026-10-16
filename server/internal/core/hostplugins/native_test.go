package hostplugins_test

import (
	"context"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/stretchr/testify/require"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNativePinnedPluginsInstallLifecycleDiagnosticsAndLoopbackMetrics(t *testing.T) {
	address := os.Getenv("JMS_TEST_KEY_HOST_ADDR")
	if address == "" {
		t.Skip("requires disposable OpenSSH fixture")
	}
	require.True(t, strings.HasPrefix(os.Getenv("JMS_TEST_KEY_HOST_NAME"), "jms233-keyhost-"))
	host, portText, e := net.SplitHostPort(address)
	require.NoError(t, e)
	port, e := strconv.Atoi(portText)
	require.NoError(t, e)
	target := sshclient.Target{Host: host, Port: port, Username: "pluginqa", HostKeyFingerprint: os.Getenv("JMS_TEST_KEY_HOST_FINGERPRINT")}
	credentials := sshclient.Credentials{Password: "synthetic-keyhost-password-233"}
	cache, e := hostplugins.NewCache(t.TempDir())
	require.NoError(t, e)
	s := hostplugins.New(func(ctx context.Context, _ string) (hostplugins.Transport, error) {
		return sshclient.OpenManagedHost(ctx, target, credentials)
	}, cache)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sequence := 0
	remoteRun := func(command string) sshclient.ExecResult {
		t.Helper()
		h, e := sshclient.OpenManagedHost(ctx, target, credentials)
		require.NoError(t, e)
		defer h.Close()
		r, e := h.Run(ctx, command)
		require.NoError(t, e)
		return r
	}
	const independent = "17 2 * * * /bin/true # independent-plugin-qa"
	require.Zero(t, remoteRun("printf '%s\\n' '"+independent+"' | crontab -").ExitCode)
	for _, plugin := range hostplugins.Catalog() {
		perform := func(action string) hostplugins.Result {
			t.Helper()
			sequence++
			op := hostplugins.Operation{Plugin: plugin.ID, Version: plugin.Version, Action: action, Binding: strings.Repeat("a", 64)}
			r, e := s.Execute(ctx, "asset", "job-"+fmtID(sequence), op)
			require.NoError(t, e, r.Stdout)
			require.Equal(t, 0, r.ExitCode, r.Stdout)
			var result hostplugins.Result
			require.NoError(t, json.Unmarshal([]byte(r.Stdout), &result))
			return result
		}
		before := perform("detect")
		require.Equal(t, "linux-amd64", before.Platform)
		require.False(t, before.Installed)
		require.True(t, perform("install").Installed)
		require.True(t, perform("install").Installed)
		require.True(t, perform("start").Running)
		supervised := perform("autostart_enable")
		require.True(t, supervised.Autostart)
		require.Equal(t, "enabled", supervised.AutostartState)
		require.True(t, perform("autostart_enable").Autostart)
		cron := remoteRun("crontab -l")
		require.Zero(t, cron.ExitCode)
		require.Contains(t, cron.Stdout, independent)
		require.Equal(t, 2, strings.Count(cron.Stdout, "# jumpserver233-agent:"+plugin.ID))
		running := perform("status")
		require.True(t, running.Running)
		remote, e := sshclient.OpenManagedHost(ctx, target, credentials)
		require.NoError(t, e)
		lost, e := remote.Run(ctx, "rm -f "+running.ManagedPath+"/pid")
		require.NoError(t, e)
		require.Equal(t, 0, lost.ExitCode)
		remote.Close()
		require.True(t, perform("status").Running)
		require.True(t, perform("start").Running)
		// Exercise the same on-host recovery launcher with a genuinely killed
		// native process, without disrupting other Go packages' shared SSH host.
		require.Zero(t, remoteRun("read -r pid stamp < "+running.ManagedPath+"/pid; kill -KILL \"$pid\"; sleep 0.1; /bin/sh "+running.ManagedPath+"/agent-launcher.sh").ExitCode)
		require.True(t, perform("status").Running)
		// Tampered launchers cannot pass status/start validation, while explicit
		// stop/disable still remove supervision without executing that launcher.
		require.Zero(t, remoteRun("printf '\\n# synthetic integrity drift\\n' >> "+running.ManagedPath+"/agent-launcher.sh").ExitCode)
		sequence++
		_, integrityErr := s.Execute(ctx, "asset", "job-"+fmtID(sequence), hostplugins.Operation{Plugin: plugin.ID, Version: plugin.Version, Action: "status", Binding: strings.Repeat("a", 64)})
		require.ErrorIs(t, integrityErr, hostplugins.ErrIntegrity)
		require.False(t, perform("stop").Running)
		require.False(t, perform("autostart_disable").Autostart)
		require.True(t, perform("autostart_enable").Running)
		if plugin.ID == "node_exporter" {
			metrics := perform("metrics")
			require.Contains(t, metrics.Output, "node_cpu_seconds_total")
			require.Contains(t, metrics.Output, "node_memory_MemTotal_bytes")
		} else {
			require.True(t, perform("doctor").DryRun)
			require.True(t, perform("scan").DryRun)
			require.NotEmpty(t, perform("keepalive_preview").Output)
		}
		disabled := perform("autostart_disable")
		require.True(t, disabled.Running)
		require.False(t, disabled.Autostart)
		require.True(t, perform("autostart_enable").Autostart)
		stopped := perform("stop")
		require.False(t, stopped.Running)
		require.False(t, stopped.Autostart)
		require.False(t, perform("stop").Running)
		require.False(t, perform("status").Running)
		// Disabling marker blocks stale launcher execution after stop.
		require.NotZero(t, remoteRun("/bin/sh "+running.ManagedPath+"/agent-launcher.sh").ExitCode)
		require.True(t, perform("autostart_enable").Running)
		require.False(t, perform("uninstall").Installed)
		require.False(t, perform("uninstall").Installed)
		require.False(t, perform("detect").Running)
		cron = remoteRun("crontab -l")
		require.Contains(t, cron.Stdout, independent)
		require.NotContains(t, cron.Stdout, "# jumpserver233-agent:"+plugin.ID)
		if plugin.ID == "banhack233" {
			require.Zero(t, remoteRun("test -f "+running.ManagedPath+"/config.json; test -f "+running.ManagedPath+"/agent.log").ExitCode)
		}
		require.True(t, perform("install").Installed)
		require.False(t, perform("uninstall").Installed)
	}
}
func fmtID(n int) string {
	v := strconv.FormatInt(int64(n), 16)
	return strings.Repeat("0", 32-len(v)) + v
}
