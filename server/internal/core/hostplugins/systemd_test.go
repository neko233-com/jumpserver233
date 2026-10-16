package hostplugins

import (
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestSystemdUnitPinsNativeHelperAndEscapesExecArguments(t *testing.T) {
	for _, uid := range []string{"0", "1001"} {
		r := systemdRecord{Format: 1, UID: uid, Plugin: "banhack233", Version: "0.2.3", ConfigSHA: strings.Repeat("a", 64), ConfigFile: "config.json", HelperSHA: strings.Repeat("b", 64), LauncherSHA: strings.Repeat("c", 64)}
		p := newSystemdPlan("/home/qa$u/%' quoted", "/home/qa$u/%' quoted/.jumpserver233/plugins/banhack233", r)
		text := p.unitText()
		require.Contains(t, text, "Type=exec")
		require.Contains(t, text, "KillMode=control-group")
		require.Contains(t, text, "Restart=on-failure")
		require.Contains(t, text, "qa$$u/%%' quoted")
		require.Contains(t, text, "Environment=\"HOME=/home/qa$u/%%' quoted")
		require.NotContains(t, text, "WorkingDirectory=")
		require.Contains(t, text, "--launcher-sha "+r.LauncherSHA)
		require.NotContains(t, text, "/bin/sh")
		require.NotContains(t, text, "sudo")
		p.record.UnitSHA = digest([]byte(text))
		require.True(t, validSystemdRecord(p.record, "banhack233"))
		if uid == "0" {
			require.Contains(t, p.file, "/etc/systemd/system/")
			require.Contains(t, text, "WantedBy=multi-user.target")
		} else {
			require.Contains(t, p.file, ".config/systemd/user")
			require.Contains(t, p.manager, "--user")
			require.Contains(t, text, "WantedBy=default.target")
		}
	}
}
func TestSystemdMetadataRejectsUnknownPathsIdentitiesAndMalformedJSON(t *testing.T) {
	good := systemdRecord{Format: 1, UID: "1001", Plugin: "banhack233", Version: "0.2.3", ConfigSHA: strings.Repeat("a", 64), ConfigFile: "config.json", HelperSHA: strings.Repeat("b", 64), LauncherSHA: strings.Repeat("c", 64), UnitSHA: strings.Repeat("d", 64)}
	for name, mutate := range map[string]func(*systemdRecord){"uid": func(r *systemdRecord) { r.UID = "0;echo injected" }, "identity": func(r *systemdRecord) { r.Plugin = "sshd" }, "version": func(r *systemdRecord) { r.Version = "../../sshd" }, "config": func(r *systemdRecord) { r.ConfigFile = "/etc/shadow" }, "hash": func(r *systemdRecord) { r.HelperSHA = "x" }, "format": func(r *systemdRecord) { r.Format = 8 }} {
		t.Run(name, func(t *testing.T) { r := good; mutate(&r); require.False(t, validSystemdRecord(r, "banhack233")) })
	}
	var r systemdRecord
	require.Error(t, decodeStrict([]byte(`{} {}`), &r))
	require.Error(t, decodeStrict([]byte(`{"unknown":true}`), &r))
}
func TestSystemdLauncherUsesIndependentMarkerAndAllLifecycleActionsAreManaged(t *testing.T) {
	p := newCronPlan("/home/autostart.enabled/.jumpserver233/plugins/node_exporter", "node_exporter")
	p.launcher = "/home/autostart.enabled/.jumpserver233/plugins/node_exporter/systemd-launcher.sh"
	s := p.launcherWithMarker("/home/autostart.enabled/.jumpserver233", "state; ", "check; ", "node_exporter", "systemd.enabled")
	require.Contains(t, s, "$d/systemd.enabled")
	require.Contains(t, s, "/home/autostart.enabled")
	require.NotContains(t, s, "$d/autostart.enabled")
	for _, action := range []string{"systemd_enable", "systemd_disable", "systemd_status"} {
		d, e := Lookup("node_exporter")
		require.NoError(t, e)
		require.True(t, d.Allows(action))
		o := Operation{Plugin: d.ID, Version: d.Version, Action: action, Binding: strings.Repeat("a", 64)}
		require.NoError(t, o.Validate())
		want := "plugins.manage"
		if action == "systemd_status" {
			want = "plugins.inspect"
		}
		require.Equal(t, want, o.Permission())
	}
}

func TestSystemdRejectsVersionMismatchBeforePausingHealthyService(t *testing.T) {
	p := systemdPlan{record: systemdRecord{Plugin: "banhack233", Version: "0.2.3"}}
	require.ErrorIs(t, p.validateRequestedVersion(Operation{Plugin: "banhack233", Action: "install", Version: "0.2.2"}), ErrConflict)
	require.ErrorIs(t, p.validateRequestedVersion(Operation{Plugin: "banhack233", Action: "upgrade", Version: "0.2.2"}), ErrInvalid)
	require.ErrorIs(t, p.validateRequestedVersion(Operation{Plugin: "banhack233", Action: "start", Version: "0.2.2"}), ErrConflict)
	require.NoError(t, p.validateRequestedVersion(Operation{Plugin: "banhack233", Action: "start", Version: "0.2.2", Selection: "installed"}))
	require.NoError(t, p.validateRequestedVersion(Operation{Plugin: "banhack233", Action: "rollback", Version: "0.2.2"}))
	r := Result{Running: true}
	p.state, p.record.Desired = "active", true
	p.decorate(&r)
	require.Equal(t, "active", r.SystemdState)
	require.True(t, r.Autostart)
}
