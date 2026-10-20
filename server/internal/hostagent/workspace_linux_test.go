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
	t.Run("private-stdin-stays-out-of-arguments-and-files", func(t *testing.T) {
		before, e := os.ReadDir(root)
		require.NoError(t, e)
		input, e := json.Marshal(struct {
			Command string `json:"command"`
			Input   []byte `json:"input"`
		}{"cat", []byte("synthetic private stdin")})
		require.NoError(t, e)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, self, "workspace", "--directory", root, "--exec-stdin")
		cmd.Stdin = bytes.NewReader(input)
		assert.NotContains(t, strings.Join(cmd.Args, " "), "synthetic private stdin")
		output, e := cmd.CombinedOutput()
		require.NoError(t, e, string(output))
		assert.Equal(t, "synthetic private stdin", string(output))
		after, e := os.ReadDir(root)
		require.NoError(t, e)
		assert.Len(t, after, len(before))
	})
	alias := filepath.Join(base, "alias")
	require.NoError(t, os.Symlink(root, alias))
	_, e = CheckWorkspace(alias)
	require.ErrorIs(t, e, ErrWorkspaceInvalid)
}

func TestWorkspaceIdentityPinsBirthInodeAndRejectsReplacementBeforeExecution(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "approved")
	require.NoError(t, os.Mkdir(root, 0700))
	before, err := CheckWorkspace(root)
	if err != nil {
		if os.Getenv("JMS_REQUIRE_WORKSPACE") == "1" {
			t.Fatal(err)
		}
		t.Skip("workspace kernel and filesystem identity required")
	}
	assert.True(t, ValidWorkspaceIdentity(before.Identity))
	require.NoError(t, os.WriteFile(filepath.Join(root, "ordinary-write"), []byte("safe"), 0600))
	again, err := CheckWorkspace(root)
	require.NoError(t, err)
	assert.Equal(t, before.Identity, again.Identity)
	require.NoError(t, os.Rename(root, filepath.Join(base, "old-approved")))
	require.NoError(t, os.Mkdir(root, 0700))
	after, err := CheckWorkspace(root)
	require.NoError(t, err)
	assert.NotEqual(t, before.Identity, after.Identity)
	helper := filepath.Join(base, "helper")
	data, err := os.ReadFile(filepath.Join("..", "agentbundle", "artifacts", "jms-agent-linux-"+runtime.GOARCH))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(helper, data, 0700))
	for _, mode := range []string{"--exec-stdin", "--sftp"} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, helper, "workspace", "--directory", root, "--identity", before.Identity, mode)
		cmd.Stdin = strings.NewReader(`{"command":"printf must-not-run > forbidden"}`)
		_, err := cmd.CombinedOutput()
		cancel()
		require.Error(t, err)
		_, err = os.Stat(filepath.Join(root, "forbidden"))
		assert.True(t, os.IsNotExist(err))
	}
}

func TestExecutionDirectoryPinsActualCwdAndRejectsSymlinksAndReplacement(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "workspace")
	child := filepath.Join(root, "app")
	require.NoError(t, os.MkdirAll(child, 0700))
	proof, err := CheckWorkspaceAt(root, child)
	if err != nil {
		if os.Getenv("JMS_REQUIRE_WORKSPACE") == "1" {
			t.Fatal(err)
		}
		t.Skip("workspace kernel and filesystem identity required")
	}
	assert.NotEqual(t, proof.Identity, proof.WorkingIdentity)
	helper := filepath.Join(base, "helper")
	data, err := os.ReadFile(filepath.Join("..", "agentbundle", "artifacts", "jms-agent-linux-"+runtime.GOARCH))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(helper, data, 0700))
	run := func(command string, expected WorkspaceStatus) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, helper, "workspace", "--directory", root, "--identity", expected.Identity, "--working-directory", child, "--working-identity", expected.WorkingIdentity, "--exec-stdin")
		raw, err := json.Marshal(map[string]string{"command": command})
		require.NoError(t, err)
		cmd.Stdin = bytes.NewReader(raw)
		return cmd.CombinedOutput()
	}
	out, err := run("pwd; printf verified > receipt", proof)
	require.NoError(t, err, string(out))
	assert.Equal(t, child+"\n", string(out))
	require.FileExists(t, filepath.Join(child, "receipt"))
	again, err := CheckWorkspaceAt(root, child)
	require.NoError(t, err)
	assert.Equal(t, proof.WorkingIdentity, again.WorkingIdentity)
	require.NoError(t, os.Symlink(child, filepath.Join(root, "alias")))
	_, err = CheckWorkspaceAt(root, filepath.Join(root, "alias"))
	require.Error(t, err)
	_, err = CheckWorkspaceAt(root, base)
	require.Error(t, err)
	require.NoError(t, os.Rename(child, filepath.Join(root, "original")))
	require.NoError(t, os.Mkdir(child, 0700))
	after, err := CheckWorkspaceAt(root, child)
	require.NoError(t, err)
	assert.Equal(t, proof.Identity, after.Identity)
	assert.NotEqual(t, proof.WorkingIdentity, after.WorkingIdentity)
	out, err = run("printf forbidden > must-not-run", proof)
	require.Error(t, err, string(out))
	assert.NoFileExists(t, filepath.Join(child, "must-not-run"))
	assert.NoFileExists(t, filepath.Join(root, "original", "must-not-run"))
}
