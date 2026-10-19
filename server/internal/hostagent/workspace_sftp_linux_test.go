//go:build linux && (amd64 || arm64)

package hostagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type workspaceDiagnostics struct {
	mu   sync.Mutex
	body []byte
}

func (d *workspaceDiagnostics) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := min(len(p), 4096-len(d.body))
	d.body = append(d.body, p[:n]...)
	return len(p), nil
}
func (d *workspaceDiagnostics) text() string { d.mu.Lock(); defer d.mu.Unlock(); return string(d.body) }

func workspaceSFTPTestClient(t *testing.T, root string) *sftp.Client {
	t.Helper()
	if _, e := CheckWorkspace(root); e != nil {
		if os.Getenv("JMS_REQUIRE_WORKSPACE") == "1" {
			t.Fatal(e)
		}
		t.Skip("Landlock ABI 3+ required")
	}
	base := t.TempDir()
	data, e := os.ReadFile(filepath.Join("..", "agentbundle", "artifacts", "jms-agent-linux-"+runtime.GOARCH))
	require.NoError(t, e)
	helper := filepath.Join(base, "jms-agent")
	require.NoError(t, os.WriteFile(helper, data, 0700))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	cmd := exec.CommandContext(ctx, helper, "workspace", "--directory", root, "--sftp")
	input, e := cmd.StdinPipe()
	require.NoError(t, e)
	output, e := cmd.StdoutPipe()
	require.NoError(t, e)
	diagnostic := &workspaceDiagnostics{}
	cmd.Stderr = diagnostic
	require.NoError(t, cmd.Start())
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var client *sftp.Client
	t.Cleanup(func() {
		if client != nil {
			_ = client.Close()
		}
		_ = input.Close()
		select {
		case e := <-done:
			assert.NoError(t, e, diagnostic.text())
		case <-time.After(3 * time.Second):
			cancel()
			<-done
			t.Error("workspace SFTP did not stop")
		}
		cancel()
	})
	client, e = sftp.NewClientPipe(output, input)
	require.NoError(t, e, diagnostic.text())
	return client
}

func TestWorkspaceSFTPUsesProductionHelperWithVirtualRootAndAtomicReplacement(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "work")
	outside := filepath.Join(base, "outside")
	require.NoError(t, os.Mkdir(root, 0700))
	require.NoError(t, os.Mkdir(outside, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(outside, "sentinel"), []byte("preserve-outside-data"), 0600))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "escape")))
	client := workspaceSFTPTestClient(t, root)
	wd, e := client.Getwd()
	require.NoError(t, e)
	assert.Equal(t, "/", wd)
	write := func(name, body string) {
		t.Helper()
		f, e := client.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		require.NoError(t, e)
		_, e = f.Write([]byte(body))
		require.NoError(t, e)
		require.NoError(t, f.Close())
	}
	read := func(name string) string {
		t.Helper()
		f, e := client.Open(name)
		require.NoError(t, e)
		defer f.Close()
		b, e := io.ReadAll(f)
		require.NoError(t, e)
		return string(b)
	}
	require.NoError(t, client.Mkdir("/dir"))
	write("/dir/a", "first")
	write("/dir/b", "second")
	require.Error(t, client.Rename("/dir/a", "/dir/b"))
	assert.Equal(t, "first", read("/dir/a"))
	assert.Equal(t, "second", read("/dir/b"))
	require.NoError(t, client.PosixRename("/dir/a", "/dir/b"))
	assert.Equal(t, "first", read("/dir/b"))
	f, e := client.OpenFile("/dir/b", os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if f != nil {
		f.Close()
	}
	require.Error(t, e)
	for _, name := range []string{"/escape/sentinel", filepath.ToSlash(filepath.Join(outside, "sentinel")), "/etc/ld.so.cache", "/proc/self/fd/3"} {
		_, e := client.Stat(name)
		require.Error(t, e, name)
		f, e := client.OpenFile(name, os.O_WRONLY|os.O_TRUNC)
		if f != nil {
			f.Close()
		}
		require.Error(t, e, name)
	}
	_, e = client.ReadLink("/escape")
	require.Error(t, e)
	require.Error(t, client.Symlink("/escape/sentinel", "/linked"))
	require.Error(t, client.Link("/dir/b", "/hardlink"))
	require.Error(t, client.Chmod("/dir/b", 0777))
	for i := range 350 {
		require.NoError(t, os.WriteFile(filepath.Join(root, fmt.Sprintf("page-%03d", i)), []byte("x"), 0600))
	}
	entries, e := client.ReadDir("/")
	require.NoError(t, e)
	assert.Len(t, entries, 352)
	content := bytes.Repeat([]byte("sftp-stream-"), 1<<17)
	f, e = client.Create("/large")
	require.NoError(t, e)
	_, e = f.Write(content)
	require.NoError(t, e)
	require.NoError(t, f.Close())
	r, e := client.Open("/large")
	require.NoError(t, e)
	received, e := io.ReadAll(r)
	require.NoError(t, e)
	require.NoError(t, r.Close())
	assert.Equal(t, len(content), len(received))
	assert.Equal(t, sha256.Sum256(content), sha256.Sum256(received))
	assert.Equal(t, "preserve-outside-data", func() string {
		b, e := os.ReadFile(filepath.Join(outside, "sentinel"))
		require.NoError(t, e)
		return string(b)
	}())
	require.NoError(t, client.Remove("/dir/b"))
	require.NoError(t, client.RemoveDirectory("/dir"))
}

func TestWorkspaceSFTPSymlinkSwapsCannotWriteOrStatOutside(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "work")
	outside := filepath.Join(base, "outside")
	swap := filepath.Join(root, "swap")
	held := filepath.Join(root, "held")
	require.NoError(t, os.Mkdir(root, 0700))
	require.NoError(t, os.Mkdir(outside, 0700))
	require.NoError(t, os.Mkdir(swap, 0700))
	marker := []byte("private-outside-sentinel-do-not-change")
	require.NoError(t, os.WriteFile(filepath.Join(outside, "sentinel"), marker, 0600))
	client := workspaceSFTPTestClient(t, root)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if os.Rename(swap, held) != nil {
				continue
			}
			if os.Symlink(outside, swap) == nil {
				_ = os.Remove(swap)
			}
			_ = os.Rename(held, swap)
		}
	}()
	t.Cleanup(func() { close(stop); <-done })
	for range 128 {
		if st, e := client.Stat("/swap/sentinel"); e == nil {
			assert.NotEqual(t, int64(len(marker)), st.Size())
		}
		if f, e := client.OpenFile("/swap/sentinel", os.O_WRONLY|os.O_CREATE|os.O_TRUNC); e == nil {
			_, _ = f.Write([]byte("x"))
			_ = f.Close()
		}
	}
	got, e := os.ReadFile(filepath.Join(outside, "sentinel"))
	require.NoError(t, e)
	assert.Equal(t, marker, got)
}

func TestWorkspaceSFTPRejectsDirectInternalStageWithoutSealedHandoff(t *testing.T) {
	base := t.TempDir()
	data, e := os.ReadFile(filepath.Join("..", "agentbundle", "artifacts", "jms-agent-linux-"+runtime.GOARCH))
	require.NoError(t, e)
	helper := filepath.Join(base, "jms-agent")
	require.NoError(t, os.WriteFile(helper, data, 0700))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, helper, "workspace-sftp-internal")
	output, e := cmd.CombinedOutput()
	require.Error(t, e)
	assert.Contains(t, string(output), "workspace_sftp_unavailable")
}
