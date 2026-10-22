package api

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	"github.com/neko233-com/jumpserver233/server/internal/core/files"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
	"github.com/neko233-com/jumpserver233/server/internal/nativeaccess"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type nativeFixture struct {
	address, remote string
	asset           coreassets.Asset
	assets          *coreassets.Service
	assetReads      atomic.Int32
	beforeAssets    func(context.Context)
	server          *nativeaccess.Server
	auth            *coreauth.Service
	grants          *grants.Store
	filters         *commandfilters.Store
	broker          *gateway.Broker
	files           *files.Service
	gate            *workgate.Gate
	commands        chan string
	jobs            *jobs.Service
}

func newNativeFixture(t *testing.T, real ...bool) *nativeFixture {
	t.Helper()
	dir := t.TempDir()
	f := &nativeFixture{remote: t.TempDir(), gate: workgate.New(), commands: make(chan string, 50)}
	var e error
	f.auth, e = coreauth.OpenServiceWithVaultKey(filepath.Join(dir, "users.json"), []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, e)
	require.NoError(t, f.auth.InitializeDefaultAdministrator())
	assets := testAssetService(t)
	f.assets = assets
	remark := "Shanghai production database"
	input := coreassets.Input{Name: "生产 API", Remark: remark, Host: "192.0.2.8", Port: 22, Username: "ops", Password: "synthetic-only", HostKeyFingerprint: validTestFingerprint()}
	if len(real) > 0 && real[0] {
		address := os.Getenv("JMS_TEST_KEY_HOST_ADDR")
		if address == "" {
			t.Skip("requires disposable OpenSSH fixture")
		}
		require.True(t, strings.HasPrefix(os.Getenv("JMS_TEST_KEY_HOST_NAME"), "jms233-keyhost-"))
		var portText string
		input.Host, portText, e = net.SplitHostPort(address)
		require.NoError(t, e)
		input.Port, e = strconv.Atoi(portText)
		require.NoError(t, e)
		input.Username = "keyqa"
		input.Password = "synthetic-keyhost-password-233"
		input.HostKeyFingerprint = os.Getenv("JMS_TEST_KEY_HOST_FINGERPRINT")
	}
	f.asset, e = assets.Create(input)
	require.NoError(t, e)
	f.grants, e = grants.OpenStore(filepath.Join(dir, "grants.json"))
	require.NoError(t, e)
	f.filters, e = commandfilters.OpenStore(filepath.Join(dir, "filters.json"))
	require.NoError(t, e)
	roles, e := rbac.Open(filepath.Join(dir, "rbac.json"), nil)
	require.NoError(t, e)
	f.broker = gateway.NewBroker(dir, []byte("0123456789abcdef0123456789abcdef"), func(ctx context.Context, id string, cols, rows int) (gateway.AssetInfo, gateway.Terminal, error) {
		if len(real) > 0 && real[0] {
			a, terminal, e := assets.OpenShell(ctx, id, cols, rows)
			return gateway.AssetInfo{ID: a.ID, Name: a.Name, Username: a.Username}, terminal, e
		}
		terminal := newNativeTerminal(f.commands)
		return gateway.AssetInfo{ID: id, Name: "native-fixture", Username: "ops"}, terminal, nil
	})
	audit, e := files.OpenAuditStore(filepath.Join(dir, "files.jsonl"))
	require.NoError(t, e)
	f.files = files.NewService(func(ctx context.Context, id string) (files.Remote, error) {
		if len(real) > 0 && real[0] {
			_, remote, e := assets.OpenSFTP(ctx, id)
			return remote, e
		}
		return &nativeRemote{f.remote}, nil
	}, audit)
	f.jobs, e = jobs.Open(filepath.Join(dir, "jobs.enc"), []byte("0123456789abcdef0123456789abcdef"), nil, func(ctx context.Context, id, command string) (sshclient.ExecResult, error) {
		if command == "aux-wait" {
			<-ctx.Done()
			return sshclient.ExecResult{ExitCode: -1}, ctx.Err()
		}
		if len(real) > 0 && real[0] {
			return assets.Exec(ctx, id, command)
		}
		return sshclient.ExecResult{Stdout: "native-exec:" + command + "\n", ExitCode: 0}, nil
	})
	require.NoError(t, e)
	t.Cleanup(f.jobs.Close)
	handler := NewRouter("native-test", Dependencies{Auth: f.auth, Assets: assets, Grants: f.grants, RBAC: roles, CommandFilters: f.filters, Sessions: f.broker, Files: f.files, Jobs: f.jobs})
	f.server, e = nativeaccess.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/api/v1/assets" {
			f.assetReads.Add(1)
			if f.beforeAssets != nil {
				f.beforeAssets(r.Context())
			}
		}
		handler.ServeHTTP(w, r)
	}), []byte("0123456789abcdef0123456789abcdef"), f.gate)
	require.NoError(t, e)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, e)
	f.address = listener.Addr().String()
	done := make(chan error, 1)
	go func() { done <- f.server.Serve(listener) }()
	t.Cleanup(func() {
		require.NoError(t, f.server.Close())
		require.NoError(t, f.server.Close())
		f.broker.CloseAll()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("native server did not stop")
		}
	})
	return f
}
func (f *nativeFixture) connect(t *testing.T, user, password string) *ssh.Client {
	t.Helper()
	c, e := ssh.Dial("tcp", f.address, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.Password(password)}, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		require.Equal(t, f.server.Fingerprint(), ssh.FingerprintSHA256(key))
		return nil
	}, Timeout: 5 * time.Second})
	require.NoError(t, e)
	t.Cleanup(func() { c.Close() })
	return c
}

type nativeOutput struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (o *nativeOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.data.Write(p)
}
func (o *nativeOutput) contains(text string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return strings.Contains(o.data.String(), text)
}
func (o *nativeOutput) count(text string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return strings.Count(o.data.String(), text)
}
func waitNative(t *testing.T, out *nativeOutput, text string) {
	t.Helper()
	require.Eventually(t, func() bool { return out.contains(text) }, 5*time.Second, 10*time.Millisecond, "missing native output: %s", text)
}
func TestNativeSSHDefaultLoginSearchRelayApprovalsAndAudit(t *testing.T) {
	f := newNativeFixture(t)
	for _, rule := range []commandfilters.Input{{Name: "native-deny", Match: "exact", Pattern: "forbidden", Action: "deny", Account: "*", Priority: 100}, {Name: "native-review", Match: "exact", Pattern: "reviewme", Action: "review", Account: "*", Priority: 100}} {
		_, e := f.filters.Create(rule, "root")
		require.NoError(t, e)
	}
	c := f.connect(t, "root", "root")
	session, e := c.NewSession()
	require.NoError(t, e)
	defer session.Close()
	out := &nativeOutput{}
	session.Stdout = out
	session.Stderr = out
	input, e := session.StdinPipe()
	require.NoError(t, e)
	require.NoError(t, session.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{}))
	require.NoError(t, session.Shell())
	waitNative(t, out, "搜索或编号")
	_, e = io.WriteString(input, "/SHANGHAI\x1b")
	require.NoError(t, e)
	require.Eventually(t, func() bool { return out.count("搜索或编号") >= 3 }, 5*time.Second, 10*time.Millisecond)
	_, _ = io.WriteString(input, "1\r")
	waitNative(t, out, "ops@native:~$ ")
	require.NoError(t, session.WindowChange(32, 110))
	_, _ = io.WriteString(input, "hello\r")
	waitNative(t, out, "OK:hello")
	_, _ = io.WriteString(input, "forbidden\r")
	waitNative(t, out, "command_blocked")
	_, _ = io.WriteString(input, "reviewme\r")
	waitNative(t, out, "command_review_pending")
	require.Eventually(t, func() bool { return len(f.broker.ListPendingCommandReviews()) == 1 }, 5*time.Second, 10*time.Millisecond)
	review := f.broker.ListPendingCommandReviews()[0]
	require.NoError(t, f.broker.ResolveCommandReview(review.ID, "root", true))
	require.Error(t, f.broker.ResolveCommandReview(review.ID, "root", true))
	waitNative(t, out, "OK:reviewme")
	beforeReturn := out.count("搜索或编号")
	_, _ = io.WriteString(input, "exit\r")
	require.Eventually(t, func() bool { return out.count("搜索或编号") > beforeReturn }, 5*time.Second, 10*time.Millisecond)
	// Return to the menu and connect again without a stranded input reader.
	prompts := out.count("ops@native:~$ ")
	_, _ = io.WriteString(input, "1\r")
	require.Eventually(t, func() bool { return out.count("ops@native:~$ ") > prompts }, 5*time.Second, 10*time.Millisecond)
	beforeReturn = out.count("搜索或编号")
	_, _ = io.WriteString(input, "exit\r")
	require.Eventually(t, func() bool { return out.count("搜索或编号") > beforeReturn }, 5*time.Second, 10*time.Millisecond)
	_, _ = io.WriteString(input, "q\r")
	require.NoError(t, session.Wait())
	records, total, active, e := f.broker.ListSessions(0, 20)
	require.NoError(t, e)
	require.Equal(t, 2, total)
	require.Zero(t, active)
	for _, r := range records {
		require.True(t, r.ReplayAvailable)
		commands, _, e := f.broker.ListCommands(r.SessionID, 0, 30)
		require.NoError(t, e)
		for _, command := range commands {
			require.NotContains(t, command.Command, "synthetic-only")
		}
	}
	for len(f.commands) > 0 {
		require.NotEqual(t, "forbidden", <-f.commands)
	}
}
func TestNativeSFTPAtomicUploadDownloadRenameTraversalAndCleanup(t *testing.T) {
	f := newNativeFixture(t)
	c := f.connect(t, "root", "root")
	client, e := sftp.NewClient(c)
	require.NoError(t, e)
	defer client.Close()
	rows, e := client.ReadDir("/")
	require.NoError(t, e)
	require.Empty(t, rows)
	base := "/" + f.asset.ID
	require.NoError(t, client.Mkdir(base+"/folder"))
	data := bytes.Repeat([]byte("原生 SFTP byte-safe\n"), 12000)
	file, e := client.Create(base + "/folder/test.bin")
	require.NoError(t, e)
	_, e = file.Write(data)
	require.NoError(t, e)
	require.NoError(t, file.Close())
	file, e = client.Open(base + "/folder/test.bin")
	require.NoError(t, e)
	got, e := io.ReadAll(file)
	require.NoError(t, e)
	require.NoError(t, file.Close())
	require.Equal(t, data, got)
	require.NoError(t, client.Rename(base+"/folder/test.bin", base+"/folder/renamed.bin"))
	require.Error(t, client.Rename(base+"/folder/renamed.bin", "/other/no"))
	_, e = client.Open(base + "/../escape")
	require.Error(t, e)
	// A disconnected upload must never replace an existing remote file.
	file, e = client.Create(base + "/folder/renamed.bin")
	require.NoError(t, e)
	_, e = file.WriteAt([]byte("partial"), 16)
	require.NoError(t, e)
	require.Error(t, file.Close())
	stored, e := os.ReadFile(filepath.Join(f.remote, "folder/renamed.bin"))
	require.NoError(t, e)
	require.Equal(t, data, stored)
	require.NoError(t, client.Remove(base+"/folder/renamed.bin"))
	require.NoError(t, client.RemoveDirectory(base+"/folder"))
	audit, _, e := f.files.ListAudit("root", 0, 30)
	require.NoError(t, e)
	actions := map[string]bool{}
	for _, a := range audit {
		actions[a.Action] = true
	}
	for _, a := range []string{"mkdir", "upload", "download", "rename", "delete"} {
		require.True(t, actions[a], a)
	}
}
func TestNativePermissionsRevokeOpenHandlesAndDenyRawForwarding(t *testing.T) {
	f := newNativeFixture(t)
	user, e := f.auth.CreateUser("native-operator", "synthetic-native-password-233", coreauth.RoleOperator)
	require.NoError(t, e)
	c := f.connect(t, user.Username, "synthetic-native-password-233")
	filesClient, e := sftp.NewClient(c)
	require.NoError(t, e)
	defer filesClient.Close()
	rows, e := filesClient.ReadDir("/")
	require.NoError(t, e)
	require.Empty(t, rows)
	_, e = c.Dial("tcp", "192.0.2.8:22")
	require.Error(t, e)
	grant, e := f.grants.Create(grants.Input{UserID: user.ID, AssetID: f.asset.ID, Account: "ops", Actions: []string{"sftp"}}, "root")
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(filepath.Join(f.remote, "proof"), []byte("proof"), 0600))
	file, e := filesClient.Open("/" + f.asset.ID + "/proof")
	require.NoError(t, e)
	buffer := make([]byte, 2)
	_, e = file.ReadAt(buffer, 0)
	require.NoError(t, e)
	require.NoError(t, f.grants.Delete(grant.ID))
	_, e = file.ReadAt(buffer, 2)
	require.Error(t, e)
	_ = file.Close()
	// No connect grant can be bypassed by exec, even with a known asset ID.
	session, e := c.NewSession()
	require.NoError(t, e)
	e = session.Run("connect " + f.asset.ID)
	require.Error(t, e)
	f.gate.SetClosed(true)
	_, e = ssh.Dial("tcp", f.address, &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.Password("root")}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Second})
	require.Error(t, e)
}

func TestNativeSSHKeyboardMFAAndReplayProtection(t *testing.T) {
	f := newNativeFixture(t)
	u, e := f.auth.CreateUser("native-mfa", "synthetic-native-mfa-password", coreauth.RoleOperator)
	require.NoError(t, e)
	enrollment, e := f.auth.StartMFAEnrollment(u.ID)
	require.NoError(t, e)
	step := uint64(time.Now().Unix() / 30)
	_, e = f.auth.ConfirmMFAEnrollment(u.ID, apiTOTPCode(t, enrollment.Secret, step))
	require.NoError(t, e)
	config := &ssh.ClientConfig{User: u.Username, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second, Auth: []ssh.AuthMethod{ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
		require.Len(t, questions, 1)
		if strings.Contains(questions[0], "Password") {
			return []string{"synthetic-native-mfa-password"}, nil
		}
		return []string{apiTOTPCode(t, enrollment.Secret, step+1)}, nil
	})}}
	c, e := ssh.Dial("tcp", f.address, config)
	require.NoError(t, e)
	require.NoError(t, c.Close())
	_, e = ssh.Dial("tcp", f.address, config)
	require.Error(t, e, "a consumed MFA code cannot open another SSH connection")
	_, e = ssh.Dial("tcp", f.address, &ssh.ClientConfig{User: u.Username, Auth: []ssh.AuthMethod{ssh.Password("synthetic-native-mfa-password")}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
	require.Error(t, e)
}

func TestNativeSSHRealPinnedTargetAndSFTP(t *testing.T) {
	f := newNativeFixture(t, true)
	c := f.connect(t, "root", "root")
	session, e := c.NewSession()
	require.NoError(t, e)
	defer session.Close()
	out := &nativeOutput{}
	session.Stdout = out
	session.Stderr = out
	input, e := session.StdinPipe()
	require.NoError(t, e)
	require.NoError(t, session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
	require.NoError(t, session.Start("connect "+f.asset.ID))
	require.Eventually(t, func() bool { return out.contains("$ ") || out.contains("# ") }, 10*time.Second, 20*time.Millisecond)
	_, _ = io.WriteString(input, "printf 'NATIVE_REAL_ACCEPTED\\n'; uname -s; exit\r")
	waitNative(t, out, "Linux")
	require.NoError(t, session.Wait())
	require.True(t, out.contains("NATIVE_REAL_ACCEPTED"))
	client, e := sftp.NewClient(c)
	require.NoError(t, e)
	name := "/" + f.asset.ID + "/native-qa-" + strconv.FormatInt(time.Now().UnixNano(), 10) + ".txt"
	defer func() { _ = client.Remove(name); _ = client.Close() }()
	file, e := client.Create(name)
	require.NoError(t, e)
	_, e = file.Write([]byte("native real transfer proof"))
	require.NoError(t, e)
	require.NoError(t, file.Close())
	file, e = client.Open(name)
	require.NoError(t, e)
	data, e := io.ReadAll(file)
	require.NoError(t, e)
	require.NoError(t, file.Close())
	require.Equal(t, "native real transfer proof", string(data))
	require.NoError(t, client.Remove(name))
	rows, _, e := f.files.ListAudit("root", 0, 20)
	require.NoError(t, e)
	require.GreaterOrEqual(t, len(rows), 3)
}

type nativeRemote struct{ root string }

func (r *nativeRemote) Root() string { return "/home/operator" }
func (r *nativeRemote) Close() error { return nil }
func (r *nativeRemote) local(name string) string {
	return filepath.Join(r.root, filepath.FromSlash(strings.TrimPrefix(strings.TrimPrefix(name, "/home/operator"), "/")))
}
func nativeInfo(info os.FileInfo) sshclient.FileInfo {
	return sshclient.FileInfo{Name: info.Name(), Size: info.Size(), Mode: info.Mode().String(), ModTime: info.ModTime(), IsDir: info.IsDir(), IsRegular: info.Mode().IsRegular(), IsSymlink: info.Mode()&os.ModeSymlink != 0}
}
func (r *nativeRemote) ReadDir(_ context.Context, name string) ([]sshclient.FileInfo, error) {
	rows, e := os.ReadDir(r.local(name))
	if e != nil {
		return nil, e
	}
	out := []sshclient.FileInfo{}
	for _, row := range rows {
		info, e := row.Info()
		if e != nil {
			return nil, e
		}
		out = append(out, nativeInfo(info))
	}
	return out, nil
}
func (r *nativeRemote) Lstat(_ context.Context, name string) (sshclient.FileInfo, error) {
	info, e := os.Lstat(r.local(name))
	if e != nil {
		return sshclient.FileInfo{}, e
	}
	return nativeInfo(info), nil
}
func (r *nativeRemote) Mkdir(_ context.Context, name string) error {
	return os.Mkdir(r.local(name), 0700)
}
func (r *nativeRemote) Remove(_ context.Context, name string) error { return os.Remove(r.local(name)) }
func (r *nativeRemote) RemoveDirectory(ctx context.Context, name string) error {
	return r.Remove(ctx, name)
}
func (r *nativeRemote) OpenRead(_ context.Context, name string) (io.ReadCloser, error) {
	return os.Open(r.local(name))
}
func (r *nativeRemote) CreateExclusive(_ context.Context, name string) (io.WriteCloser, error) {
	return os.OpenFile(r.local(name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
}
func (r *nativeRemote) Rename(_ context.Context, from, to string, overwrite bool) error {
	if !overwrite {
		if _, e := os.Lstat(r.local(to)); e == nil {
			return os.ErrExist
		}
	}
	return os.Rename(r.local(from), r.local(to))
}

type nativeTerminal struct {
	reader   *io.PipeReader
	writer   *io.PipeWriter
	once     sync.Once
	mu       sync.Mutex
	line     string
	commands chan string
}

func newNativeTerminal(commands chan string) *nativeTerminal {
	reader, writer := io.Pipe()
	t := &nativeTerminal{reader: reader, writer: writer, commands: commands}
	go func() { _, _ = io.WriteString(writer, "ops@native:~$ ") }()
	return t
}
func (t *nativeTerminal) Read(p []byte) (int, error) { return t.reader.Read(p) }
func (t *nativeTerminal) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, b := range p {
		switch b {
		case 3:
			t.line = ""
			_, _ = io.WriteString(t.writer, "^C\r\nops@native:~$ ")
		case '\r', '\n':
			line := t.line
			t.line = ""
			if line == "exit" {
				_ = t.writer.Close()
				return len(p), nil
			}
			t.commands <- line
			_, _ = io.WriteString(t.writer, "\r\nOK:"+line+"\r\nops@native:~$ ")
		default:
			t.line += string(b)
			_, _ = t.writer.Write([]byte{b})
		}
	}
	return len(p), nil
}
func (t *nativeTerminal) Resize(int, int) error { return nil }
func (t *nativeTerminal) Close() error {
	t.once.Do(func() { t.reader.Close(); t.writer.Close() })
	return nil
}
