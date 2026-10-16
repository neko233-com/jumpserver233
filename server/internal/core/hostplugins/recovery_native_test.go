package hostplugins_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/agentbundle"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/stretchr/testify/require"
)

func TestNativeRecoveryRestoresPersistedBansThroughActualCronAndRefusesHelperDrift(t *testing.T) {
	h := newNativeTools(t, "root")
	h.success(t, "banhack233", "install", "", nil)
	t.Cleanup(func() { h.success(t, "banhack233", "uninstall", "", nil) })
	h.success(t, "banhack233", "start", "", nil)
	p, e := (hostplugins.ProtectionPolicy{Mode: "enforce", IgnoreIPs: []string{"198.51.100.0/24"}, MaxAttempts: 2, FindSeconds: 60, BanSeconds: 180, IntervalSeconds: 1}).Normalize()
	require.NoError(t, e)
	enforced := h.success(t, "banhack233", "protection_apply", "", &p)
	require.Equal(t, "ready", enforced.RecoveryState)
	require.Equal(t, "3", enforced.RecoveryVersion)
	h.success(t, "banhack233", "autostart_enable", "", nil)
	require.Zero(t, h.run(t, "ip addr replace 203.0.113.100/32 dev lo; for n in 1 2 3; do printf 'Oct 16 01:00:00 qa sshd[99]: Failed password for recover;$(untrusted)|user from 203.0.113.100 port 5555 ssh2\\n' >> /var/log/auth.log; done").ExitCode)
	require.Zero(t, h.run(t, "for n in 1 2 3; do printf 'Oct 16 01:00:00 qa sshd[99]: Failed password for recover from 2001:db8::100 port 5555 ssh2\\n' >> /var/log/auth.log; done").ExitCode)
	require.Eventually(t, func() bool {
		return h.run(t, "nft get element inet banhack233 blocked '{ 203.0.113.100 }'").ExitCode == 0
	}, 15*time.Second, 500*time.Millisecond)
	before := h.success(t, "banhack233", "status", "", nil)
	require.Equal(t, "ready", before.RecoveryState)
	require.GreaterOrEqual(t, before.ActiveBans, 2)
	stateBefore := h.run(t, "cat /root/.jumpserver233/plugins/banhack233/state.json").Stdout
	require.NotZero(t, h.run(t, "nc -z -w 1 -s 203.0.113.100 127.0.0.1 22").ExitCode)
	require.Zero(t, h.run(t, "nft get element inet banhack233 blocked6 '{ 2001:db8::100 }'").ExitCode)
	// Simulate a lost kernel table and an abruptly stopped native process. Leave
	// the enabled marker and actual cron service untouched; do not call start.
	require.Zero(t, h.run(t, "d=/root/.jumpserver233/plugins/banhack233; read -r pid stamp < \"$d/pid\"; kill -KILL \"$pid\"; nft delete table inet banhack233").ExitCode)
	missing := h.success(t, "banhack233", "status", "", nil)
	require.Equal(t, "required", missing.RecoveryState)
	require.Eventually(t, func() bool {
		return h.run(t, "nft get element inet banhack233 blocked '{ 203.0.113.100 }'").ExitCode == 0
	}, 90*time.Second, 2*time.Second)
	after := h.success(t, "banhack233", "status", "", nil)
	require.True(t, after.Running)
	require.True(t, after.Autostart)
	require.Equal(t, "ready", after.RecoveryState)
	require.NotZero(t, h.run(t, "nc -z -w 1 -s 203.0.113.100 127.0.0.1 22").ExitCode)
	require.Contains(t, h.run(t, "nft -j get element inet banhack233 blocked '{ 203.0.113.100 }'").Stdout, "expires")
	require.Contains(t, h.run(t, "nft -j get element inet banhack233 blocked6 '{ 2001:db8::100 }'").Stdout, "expires")
	// Native state expiry is unchanged; recovery never manufactures a new ban.
	stateAfter := h.run(t, "cat /root/.jumpserver233/plugins/banhack233/state.json").Stdout
	var oldState, newState struct {
		Bans map[string]time.Time `json:"bans"`
	}
	require.NoError(t, json.Unmarshal([]byte(stateBefore), &oldState))
	require.NoError(t, json.Unmarshal([]byte(stateAfter), &newState))
	matched := 0
	for key, until := range oldState.Bans {
		if strings.HasPrefix(key, "ssh-auth-failure|203.0.113.100|") || strings.HasPrefix(key, "ssh-auth-failure|2001:db8::100|") {
			require.Equal(t, until, newState.Bans[key])
			matched++
		}
	}
	require.Equal(t, 2, matched)
	events := h.success(t, "banhack233", "events", "", nil)
	require.NotNil(t, events.Events)
	require.GreaterOrEqual(t, len(events.Events.Events), 4)
	found := false
	for _, event := range events.Events.Events {
		if event.Trigger == "supervisor" && event.Kind == "repair_completed" {
			found = true
		}
	}
	require.True(t, found)
	// A transient unavailable kernel tool cannot turn a healthy running monitor
	// off. The trap restores the isolated fixture executable even on failure.
	require.Zero(t, h.run(t, `set -eu; d=/root/.jumpserver233/plugins/banhack233; read -r before stamp < "$d/pid"; test ! -e /usr/sbin/nft.qa-recovery-hold; trap 'if [ -f /usr/sbin/nft.qa-recovery-hold ]; then mv /usr/sbin/nft.qa-recovery-hold /usr/sbin/nft; fi' EXIT; mv /usr/sbin/nft /usr/sbin/nft.qa-recovery-hold; rc=0; for attempt in 1 2 3; do if /bin/sh "$d/agent-launcher.sh" >/dev/null 2>&1; then sleep 0.1; else rc=$?; break; fi; done; test "$rc" = 1; test -r "/proc/$before/exe"; mv /usr/sbin/nft.qa-recovery-hold /usr/sbin/nft; trap - EXIT`).ExitCode)
	// A forged or corrupted helper is never executed. Stop/uninstall still work.
	binary, e := agentbundle.Get("linux-amd64")
	require.NoError(t, e)
	helper := "/root/.jumpserver233/plugins/banhack233/agent-recovery-" + binary.SHA256

	// Every integrity check must fail as a standalone shell statement. A failed
	// non-final && operand is exempt from set -e and must not reach execution.
	require.Zero(t, h.run(t, "mv "+helper+" "+helper+".symlink-qa-valid; printf '#!/bin/sh\\ntouch /root/.jumpserver233/plugins/banhack233/untrusted-executed\\n' > "+helper+".symlink-qa-fake; chmod 700 "+helper+".symlink-qa-fake; ln -s "+helper+".symlink-qa-fake "+helper).ExitCode)
	_, symlinkError := h.perform(t, "banhack233", "events", "", nil)
	require.ErrorIs(t, symlinkError, hostplugins.ErrIntegrity)
	require.Zero(t, h.run(t, "test ! -e /root/.jumpserver233/plugins/banhack233/untrusted-executed; rm "+helper+"; mv "+helper+".symlink-qa-valid "+helper).ExitCode)
	require.Zero(t, h.run(t, "printf '\\n# synthetic binary drift\\n' >> "+helper).ExitCode)
	_, e = h.perform(t, "banhack233", "start", "", nil)
	require.ErrorIs(t, e, hostplugins.ErrIntegrity)
	require.False(t, h.success(t, "banhack233", "stop", "", nil).Running)
	// Explicit update preserves the drifted executable and deploys the verified helper.
	updated := h.success(t, "banhack233", "agent_update", "", nil)
	require.Equal(t, "3", updated.RecoveryVersion)
	repaired := h.success(t, "banhack233", "start", "", nil)
	require.Equal(t, "ready", repaired.RecoveryState)
}
