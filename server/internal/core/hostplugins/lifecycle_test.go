package hostplugins

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSupervisorScriptsPinIntegrityAndPreserveOtherCrontabEntries(t *testing.T) {
	p := newCronPlan("/home/qa' quoted/.jumpserver233/plugins/banhack233", "banhack233")
	require.True(t, p.supported())
	require.Contains(t, p.boot, "@reboot /bin/sh ")
	require.Contains(t, p.boot, "'\"'\"'")
	require.Contains(t, p.tick, "* * * * * ")
	require.Contains(t, p.probe("/home/qa' quoted"), "summary=conflict")
	for _, home := range []string{"/home/qa%user", `/home/qa\user`} {
		require.False(t, newCronPlan(home, "banhack233").supported())
	}
	for _, enable := range []bool{false, true} {
		script := p.replace("/home/qa' quoted/.jumpserver233", enable)
		require.Contains(t, script, "cron.lock")
		require.Contains(t, script, "[ \"$cron\" = \"$previous\" ]")
		require.Contains(t, script, "$0!=boot && $0!=tick")
		require.NotContains(t, script, "crontab -r")
		require.NotContains(t, script, "sudo")
	}
	launcher := p.launcherScript("/home/qa/.jumpserver233", "identity; ", "pinned_hash; ", "node_exporter")
	require.Contains(t, launcher, "autostart.enabled")
	require.Contains(t, launcher, "operation.lock")
	require.Contains(t, launcher, "identity; pinned_hash; ")
	require.Contains(t, launcher, "--web.listen-address=127.0.0.1:19100")
	require.Contains(t, launcher, "pid.next")
	require.NotContains(t, launcher, "sudo")
}

func TestLifecycleMutationsRequireManageAndNeverFetchForOfflineRemoval(t *testing.T) {
	for _, action := range []string{"autostart_enable", "autostart_disable", "uninstall", "stop"} {
		t.Run(action, func(t *testing.T) {
			d, e := Lookup("node_exporter")
			require.NoError(t, e)
			require.True(t, d.Allows(action))
			op := Operation{Plugin: d.ID, Version: d.Version, Action: action, Binding: strings.Repeat("b", 64)}
			require.Equal(t, "plugins.manage", op.Permission())
			if action == "autostart_enable" {
				return
			}
			remote := &fakeTransport{installed: true, uploads: map[string][]byte{}}
			cache := &fakeFetcher{}
			s := New(func(context.Context, string) (Transport, error) { return remote, nil }, cache)
			r, e := s.Execute(context.Background(), "asset", "job-"+strings.Repeat("b", 32), op)
			require.NoError(t, e, r.Stdout)
			require.Zero(t, cache.calls)
			var value Result
			require.NoError(t, json.Unmarshal([]byte(r.Stdout), &value))
			require.False(t, value.Autostart)
			require.Equal(t, "disabled", value.AutostartState)
			script := remote.scripts[len(remote.scripts)-1]
			require.Contains(t, script, "autostart.enabled")
			require.NotContains(t, script, "rm -rf")
			require.NotContains(t, script, "rm \"$c\"")
		})
	}
}

func TestSupervisorRefusesUnknownRegistrationAndUnavailableCron(t *testing.T) {
	for _, state := range []string{"conflict", "unavailable"} {
		t.Run(state, func(t *testing.T) {
			remote := &fakeTransport{installed: true, cronState: state, uploads: map[string][]byte{}}
			s := New(func(context.Context, string) (Transport, error) { return remote, nil }, &fakeFetcher{})
			op := Operation{Plugin: "node_exporter", Version: "1.12.1", Action: "autostart_enable", Binding: strings.Repeat("c", 64)}
			_, e := s.Execute(context.Background(), "asset", "job-"+strings.Repeat("c", 32), op)
			if state == "conflict" {
				require.ErrorIs(t, e, ErrConflict)
			} else {
				require.ErrorIs(t, e, ErrAutostart)
			}
			require.Empty(t, remote.uploads)
			require.NotContains(t, strings.Join(remote.scripts, "\n"), "crontab -;")
		})
	}
}
