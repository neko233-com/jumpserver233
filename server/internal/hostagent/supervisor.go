// Native supervision runs only the platform-generated, pinned local launcher.
// It has no listener or remote credentials. systemd owns its full process group.
package hostagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type SupervisorStatus struct {
	Version     string    `json:"version"`
	LauncherSHA string    `json:"launcher_sha"`
	LastTick    time.Time `json:"last_tick"`
	LastSuccess time.Time `json:"last_success,omitzero"`
	ErrorCode   string    `json:"error_code,omitempty"`
	Ticks       uint64    `json:"ticks"`
}

func validPlugin(id string) bool { return id == "banhack233" || id == "node_exporter" }
func validateManagedDirectory(dir, plugin string) error {
	if !validPlugin(plugin) || filepath.Base(dir) != plugin {
		return ErrConfiguration
	}
	return validateDirectoryFor(dir, plugin)
}
func readSupervisorStatus(dir string) (SupervisorStatus, error) {
	var s SupervisorStatus
	b, e := regularRead(filepath.Join(dir, "systemd-status.json"), 4096)
	if e != nil {
		return s, e
	}
	if validateJSON(b) != nil {
		return s, ErrState
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil || d.Decode(new(any)) != io.EOF || s.Version != "3" || !validHex(s.LauncherSHA, 32) || s.LastTick.IsZero() || s.Ticks > MaxSequence {
		return s, ErrState
	}
	return s, nil
}
func writeSupervisorStatus(dir string, s SupervisorStatus) error {
	if _, e := readSupervisorStatus(dir); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	raw, _ := json.Marshal(s)
	f, e := os.CreateTemp(dir, ".systemd-status-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(raw); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if e = os.Rename(name, filepath.Join(dir, "systemd-status.json")); e != nil {
		return e
	}
	return syncDirectory(dir)
}
func supervisorTick(ctx context.Context, dir, plugin, hash string) string {
	if validateManagedDirectory(dir, plugin) != nil {
		return "invalid_directory"
	}
	raw, e := regularRead(filepath.Join(dir, "systemd-launcher.sh"), 128<<10)
	if e != nil || SHA(raw) != hash {
		return "launcher_integrity_failed"
	}
	// Read the verified snapshot through stdin; a rename cannot substitute a
	// different script between hashing and interpreter startup.
	task, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(task, "/bin/sh", "-s", "--")
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 3 * time.Second
	cmd.Stdin = bytes.NewReader(raw)
	cmd.Dir = dir
	home, e := os.UserHomeDir()
	if e != nil {
		return "invalid_directory"
	}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=" + home}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if cmd.Run() != nil {
		return "launcher_failed"
	}
	if !managedProcessRunning(dir, plugin) {
		return "agent_not_running"
	}
	return ""
}
func Supervise(ctx context.Context, dir, plugin, hash string) error {
	if validateManagedDirectory(dir, plugin) != nil || !validHex(hash, 32) {
		return ErrConfiguration
	}
	unlock, e := stateLock(filepath.Join(dir, "systemd-supervisor.lock"))
	if e != nil {
		return e
	}
	defer unlock()
	status := SupervisorStatus{Version: "3", LauncherSHA: hash}
	for {
		if ctx.Err() != nil {
			return nil
		}
		if _, e := regularRead(filepath.Join(dir, "systemd.enabled"), 64); e != nil {
			if errors.Is(e, os.ErrNotExist) {
				return nil
			}
			return ErrState
		}
		status.LastTick = time.Now().UTC()
		status.Ticks++
		status.ErrorCode = supervisorTick(ctx, dir, plugin, hash)
		if ctx.Err() != nil {
			return nil
		}
		if status.ErrorCode == "" {
			status.LastSuccess = status.LastTick
		}
		if e = writeSupervisorStatus(dir, status); e != nil {
			return e
		}
		// A transient kernel inspection failure must not terminate the manager and
		// let systemd kill a still healthy monitor. Keep retrying the pinned script.
		timer := time.NewTimer(10 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func managedProcessRunning(dir, plugin string) bool {
	raw, e := regularRead(filepath.Join(dir, "manifest"), 1024)
	if e != nil {
		return false
	}
	parts := strings.Fields(string(raw))
	if len(parts) != 3 || len(parts[0]) > 32 || strings.Trim(parts[0], "0123456789.") != "" || strings.Contains(parts[0], "..") {
		return false
	}
	pidRaw, e := regularRead(filepath.Join(dir, "pid"), 128)
	if e != nil {
		return false
	}
	pid := strings.Fields(string(pidRaw))
	if len(pid) != 2 {
		return false
	}
	n, e := strconv.ParseUint(pid[0], 10, 32)
	if e != nil || n == 0 {
		return false
	}
	proc := filepath.Join("/proc", pid[0])
	exe, e := os.Readlink(filepath.Join(proc, "exe"))
	if e != nil || exe != filepath.Join(dir, parts[0], plugin) {
		return false
	}
	stat, e := os.ReadFile(filepath.Join(proc, "stat"))
	if e != nil {
		return false
	}
	tail := strings.LastIndexByte(string(stat), ')')
	if tail < 0 {
		return false
	}
	fields := strings.Fields(string(stat[tail+1:]))
	return len(fields) > 19 && fields[19] == pid[1]
}
