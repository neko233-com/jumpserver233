package api

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func openNativeWorkbench(t *testing.T, f *nativeFixture, user string, password ...string) (*ssh.Session, io.WriteCloser, *nativeOutput) {
	t.Helper()
	credential := "root"
	if len(password) > 0 {
		credential = password[0]
	}
	c := f.connect(t, user, credential)
	session, e := c.NewSession()
	require.NoError(t, e)
	t.Cleanup(func() { session.Close() })
	out := &nativeOutput{}
	session.Stdout = out
	session.Stderr = out
	input, e := session.StdinPipe()
	require.NoError(t, e)
	require.NoError(t, session.RequestPty("xterm-256color", 28, 110, ssh.TerminalModes{}))
	require.NoError(t, session.Shell())
	waitNative(t, out, "搜索或编号")
	return session, input, out
}
func TestNativeWorkbenchArrowSearchResizeReturnAndAudit(t *testing.T) {
	f := newNativeFixture(t)
	other, e := f.assets.Create(coreassets.Input{Name: "运维数据库", Remark: "Singapore standby", Host: "198.51.100.16", Port: 22, Username: "ops", Password: "synthetic-only", HostKeyFingerprint: validTestFingerprint()})
	require.NoError(t, e)
	s, input, out := openNativeWorkbench(t, f, "root")
	waitNative(t, out, "运维数据库")
	_, e = io.WriteString(input, "\x1b[B\r")
	require.NoError(t, e)
	waitNative(t, out, "ops@native:~$ ")
	require.NoError(t, s.WindowChange(16, 56))
	before := out.count("搜索或编号")
	_, _ = io.WriteString(input, "exit\r")
	require.Eventually(t, func() bool { return out.count("搜索或编号") > before }, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, s.WindowChange(28, 110))
	before = out.count("搜索或编号")
	_, _ = io.WriteString(input, "/192.0.2\x1b")
	require.Eventually(t, func() bool { return out.count("搜索或编号") > before+1 }, 5*time.Second, 10*time.Millisecond)
	prompts := out.count("ops@native:~$ ")
	_, _ = io.WriteString(input, "\r")
	require.Eventually(t, func() bool { return out.count("ops@native:~$ ") > prompts }, 5*time.Second, 10*time.Millisecond)
	before = out.count("搜索或编号")
	_, _ = io.WriteString(input, "exit\r")
	require.Eventually(t, func() bool { return out.count("搜索或编号") > before }, 5*time.Second, 10*time.Millisecond)
	_, _ = io.WriteString(input, "q")
	require.NoError(t, s.Wait())
	rows, total, active, e := f.broker.ListSessions(0, 20)
	require.NoError(t, e)
	require.Equal(t, 2, total)
	require.Zero(t, active)
	ids := map[string]bool{}
	for _, r := range rows {
		ids[r.AssetID] = true
		require.True(t, r.ReplayAvailable)
	}
	require.True(t, ids[f.asset.ID])
	require.True(t, ids[other.ID])
}
func TestNativeWorkbenchLiveSearchAvoidsInventoryRequestsAndPasteExecution(t *testing.T) {
	f := newNativeFixture(t)
	s, input, out := openNativeWorkbench(t, f, "root")
	waitNative(t, out, f.asset.Name)
	reads := f.assetReads.Load()
	_, _ = io.WriteString(input, "/Shanghai database")
	waitNative(t, out, "Shanghai database")
	require.Equal(t, reads, f.assetReads.Load())
	_, _ = io.WriteString(input, "\x1b[200~q\nr\x1b[201~")
	waitNative(t, out, "q r")
	_, total, active, e := f.broker.ListSessions(0, 20)
	require.NoError(t, e)
	require.Zero(t, total)
	require.Zero(t, active)
	_, _ = io.WriteString(input, "\x1b")
	require.Eventually(t, func() bool { return out.contains("q r") }, time.Second, 10*time.Millisecond)
	_, _ = io.WriteString(input, "\x1br")
	require.Eventually(t, func() bool { return f.assetReads.Load() > reads }, 5*time.Second, 10*time.Millisecond)
	_, _ = io.WriteString(input, "q")
	require.NoError(t, s.Wait())
}
func TestNativeWorkbenchFileOnlySelectionCannotOpenSSH(t *testing.T) {
	f := newNativeFixture(t)
	const password = "synthetic-workbench-password"
	u, e := f.auth.CreateUser("files-only-workbench", password, "operator")
	require.NoError(t, e)
	_, e = f.grants.Create(grants.Input{UserID: u.ID, AssetID: f.asset.ID, Account: "ops", Actions: []string{"sftp"}}, "root")
	require.NoError(t, e)
	s, input, out := openNativeWorkbench(t, f, u.Username, password)
	waitNative(t, out, f.asset.Name)
	_, _ = io.WriteString(input, "\r")
	waitNative(t, out, "尚未授予 SSH")
	_, total, _, e := f.broker.ListSessions(0, 20)
	require.NoError(t, e)
	require.Zero(t, total)
	_, _ = io.WriteString(input, "q")
	require.NoError(t, s.Wait())
}
func TestNativeWorkbenchDisconnectCancelsPendingInventory(t *testing.T) {
	f := newNativeFixture(t)
	started := make(chan struct{})
	var once sync.Once
	f.beforeAssets = func(ctx context.Context) { once.Do(func() { close(started) }); <-ctx.Done() }
	s, _, _ := openNativeWorkbench(t, f, "root")
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("inventory did not start")
	}
	_ = s.Close()
	done := make(chan error, 1)
	go func() { done <- f.server.Close() }()
	select {
	case e := <-done:
		require.NoError(t, e)
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled inventory kept native shutdown blocked")
	}
}

func TestNativeWorkbenchRealOpenSSHSelectionMonitorAndReturn(t *testing.T) {
	f := newNativeFixture(t, true)
	s, input, out := openNativeWorkbench(t, f, "root")
	waitNative(t, out, f.asset.Name)
	_, e := io.WriteString(input, "m")
	require.NoError(t, e)
	require.Eventually(t, func() bool {
		rows := f.assets.List()
		return len(rows) == 1 && rows[0].Monitor.State == "online" && rows[0].Monitor.Metrics != nil
	}, 15*time.Second, 20*time.Millisecond)
	waitNative(t, out, "在线")
	_, e = io.WriteString(input, "/Shanghai\x1b\r")
	require.NoError(t, e)
	require.Eventually(t, func() bool { return out.contains("$ ") || out.contains("# ") }, 10*time.Second, 20*time.Millisecond)
	_, e = io.WriteString(input, "printf 'WORKBENCH_REAL_ACCEPTED\\n'; uname -s\r")
	require.NoError(t, e)
	waitNative(t, out, "Linux")
	require.True(t, out.contains("WORKBENCH_REAL_ACCEPTED"))
	before := out.count("搜索或编号")
	_, e = io.WriteString(input, "exit\r")
	require.NoError(t, e)
	require.Eventually(t, func() bool { return out.count("搜索或编号") > before }, 5*time.Second, 10*time.Millisecond)
	_, e = io.WriteString(input, "q")
	require.NoError(t, e)
	require.NoError(t, s.Wait())
	rows, total, active, e := f.broker.ListSessions(0, 20)
	require.NoError(t, e)
	require.Equal(t, 1, total)
	require.Zero(t, active)
	require.True(t, rows[0].ReplayAvailable)
}
