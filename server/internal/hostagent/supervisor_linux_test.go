//go:build linux

package hostagent

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func supervisorDirectory(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "plugins", "node_exporter")
	require.NoError(t, os.MkdirAll(dir, 0700))
	return dir
}
func TestNativeSupervisorDoesNotExecuteSymlinkOrUnpinnedLauncher(t *testing.T) {
	dir := supervisorDirectory(t)
	outside := filepath.Join(t.TempDir(), "launcher")
	require.NoError(t, os.WriteFile(outside, []byte("touch "+filepath.Join(dir, "should-not-run")), 0700))
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, "systemd-launcher.sh")))
	ctx := context.Background()
	raw, e := os.ReadFile(outside)
	require.NoError(t, e)
	require.Equal(t, "launcher_integrity_failed", supervisorTick(ctx, dir, "node_exporter", SHA(raw)))
	_, e = os.Stat(filepath.Join(dir, "should-not-run"))
	require.True(t, os.IsNotExist(e))
	require.NoError(t, os.Remove(filepath.Join(dir, "systemd-launcher.sh")))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "systemd-launcher.sh"), raw, 0700))
	require.Equal(t, "launcher_integrity_failed", supervisorTick(ctx, dir, "node_exporter", SHA(nil)))
	require.Equal(t, "agent_not_running", supervisorTick(ctx, dir, "node_exporter", SHA(raw)))
	require.FileExists(t, filepath.Join(dir, "should-not-run"))
}
func TestNativeSupervisorKeepsRetryStateAndRejectsUnknownStatusFile(t *testing.T) {
	dir := supervisorDirectory(t)
	script := []byte("#!/bin/sh\nexit 1\n")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "systemd-launcher.sh"), script, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "systemd.enabled"), []byte("enabled"), 0600))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Supervise(ctx, dir, "node_exporter", SHA(script)) }()
	require.Eventually(t, func() bool {
		r, e := readSupervisorStatus(dir)
		return e == nil && r.ErrorCode == "launcher_failed" && r.Ticks == 1
	}, 3*time.Second, 10*time.Millisecond)
	cancel()
	require.NoError(t, <-done)
	raw := []byte(`{"unknown":true}`)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "systemd-status.json"), raw, 0600))
	require.Error(t, writeSupervisorStatus(dir, SupervisorStatus{Version: "3", LauncherSHA: strings.Repeat("a", 64), LastTick: time.Now().UTC()}))
	after, e := os.ReadFile(filepath.Join(dir, "systemd-status.json"))
	require.NoError(t, e)
	require.Equal(t, raw, after)
}
func TestNativeSupervisorMarkerMissingStopsWithoutInitializingAnything(t *testing.T) {
	dir := supervisorDirectory(t)
	require.NoError(t, Supervise(context.Background(), dir, "node_exporter", SHA(nil)))
	_, e := os.Stat(filepath.Join(dir, "systemd-status.json"))
	require.True(t, os.IsNotExist(e))
	require.Error(t, Supervise(context.Background(), dir, "other", SHA(nil)))
	var out SupervisorStatus
	require.Error(t, json.Unmarshal([]byte(`{"last_tick":3}`), &out))
}
