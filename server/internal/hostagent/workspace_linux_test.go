//go:build linux && (amd64 || arm64)

package hostagent

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkspaceKernelConfinementSurvivesShellsSymlinksAndRawSyscalls(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "workspace")
	out := filepath.Join(base, "outside")
	require.NoError(t, os.Mkdir(root, 0700))
	require.NoError(t, os.Mkdir(out, 0700))
	if _, e := CheckWorkspace(root); e != nil {
		if os.Getenv("JMS_REQUIRE_WORKSPACE") == "1" {
			t.Fatal(e)
		}
		t.Skip("Landlock ABI 3+ required")
	}
	require.NoError(t, os.WriteFile(filepath.Join(out, "sentinel"), []byte("preserve"), 0600))
	require.NoError(t, os.Symlink(out, filepath.Join(root, "escape")))
	// Execute generated production bytes, not a race-instrumented test process.
	self := filepath.Join(base, "jms-agent")
	data, e := os.ReadFile(filepath.Join("..", "agentbundle", "artifacts", "jms-agent-linux-"+runtime.GOARCH))
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(self, data, 0700))
	probe := filepath.Join(root, "probe")
	build := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", probe, "../../testsupport/workspaceprobe")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	result, e := build.CombinedOutput()
	require.NoError(t, e, string(result))
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
	for _, tc := range []struct {
		name, command, want string
		success             bool
	}{
		{"inside", "printf allowed > owned; cat owned", "allowed", true},
		{"nested", "mkdir -p child; sh -c 'printf nested > child/owned'; cat child/owned", "nested", true},
		{"outside-read", "cat " + quote(filepath.Join(out, "sentinel")), "", false},
		{"outside-write", "printf changed > " + quote(filepath.Join(out, "sentinel")), "", false},
		{"symlink-read", "cat escape/sentinel", "", false},
		{"symlink-write", "printf changed > escape/new", "", false},
		{"absolute-cd", "cd " + quote(out) + "; printf changed > new", "", false},
		{"hardlink", "ln " + quote(filepath.Join(out, "sentinel")) + " copied", "", false},
		{"rename", "mv owned " + quote(filepath.Join(out, "moved")), "", false},
		{"truncate", "truncate -s 0 " + quote(filepath.Join(out, "sentinel")), "", false},
		{"outside-mode", "chmod 777 " + quote(filepath.Join(out, "sentinel")), "", false},
		{"outside-time", "touch " + quote(filepath.Join(out, "sentinel")), "", false},
		{"system-write", "printf changed > /etc/workspace-should-not-exist", "", false},
		{"inherited-environment", "printf '%s' \"${JMS_TEST_PRIVATE-unset}\"", "unset", true},
		{"raw-syscalls", quote(probe), "workspace-syscalls-denied", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, self, "workspace", "--directory", root, "--exec-stdin")
			input, e := json.Marshal(struct {
				Command string `json:"command"`
			}{tc.command})
			require.NoError(t, e)
			cmd.Stdin = bytes.NewReader(input)
			cmd.Env = append(os.Environ(), "JMS_TEST_PRIVATE=must-not-inherit")
			// This open outside descriptor must not survive the helper's exec.
			outside, e := os.OpenFile(filepath.Join(out, "sentinel"), os.O_RDWR, 0)
			require.NoError(t, e)
			defer outside.Close()
			cmd.ExtraFiles = []*os.File{outside}
			output, e := cmd.CombinedOutput()
			if tc.success {
				require.NoError(t, e, string(output))
				assert.Equal(t, tc.want, string(output))
			} else {
				require.Error(t, e, string(output))
			}
			original, e := os.ReadFile(filepath.Join(out, "sentinel"))
			require.NoError(t, e)
			assert.Equal(t, "preserve", string(original))
			assert.NoFileExists(t, filepath.Join(out, "new"))
		})
	}
	alias := filepath.Join(base, "alias")
	require.NoError(t, os.Symlink(root, alias))
	_, e = CheckWorkspace(alias)
	require.ErrorIs(t, e, ErrWorkspaceInvalid)
}
