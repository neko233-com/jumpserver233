package hostplugins

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/stretchr/testify/require"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

type fakeTransport struct {
	scripts   []string
	uploads   map[string][]byte
	installed bool
	platform  string
	home      string
	closed    bool
	failCheck bool
	cronState string
	version   string
	plugin    string
}

func (f *fakeTransport) Root() string {
	if f.home != "" {
		return f.home
	}
	return "/home/qa'quoted"
}
func (f *fakeTransport) Close() error                                   { f.closed = true; return nil }
func (f *fakeTransport) DialLoopback(context.Context) (net.Conn, error) { return nil, ErrConflict }
func (f *fakeTransport) Upload(_ context.Context, p string, r io.Reader) error {
	b, e := io.ReadAll(r)
	f.uploads[p] = b
	return e
}
func (f *fakeTransport) Run(_ context.Context, s string) (sshclient.ExecResult, error) {
	f.scripts = append(f.scripts, s)
	out := ""
	code := 0
	switch {
	case strings.Contains(s, "uname -s"):
		f.plugin = "banhack233"
		if strings.Contains(s, "command -v node_exporter") {
			f.plugin = "node_exporter"
		}
		out = "Linux\nx86_64\n1000\n/usr/local/bin/banhack233"
		if f.platform != "" {
			out = f.platform
		}
	case strings.Contains(s, "else printf none"):
		out = "none"
		if f.installed && strings.Contains(s, "read -r version binary_hash config_hash") {
			version := f.version
			if version == "" {
				version = "0.2.3"
				if f.plugin == "node_exporter" {
					version = "1.12.1"
				}
			}
			out = version + " " + strings.Repeat("a", 64) + " " + digest(managedConfig(path.Join(f.Root(), ".jumpserver233/plugins", f.plugin)))
		}
	case strings.Contains(s, "then printf pending; else printf clean"):
		out = "clean"
	case strings.Contains(s, "printf installed; else printf missing"):
		if f.installed {
			out = "installed 0 0"
		} else {
			out = "missing 0 0"
		}
	case strings.Contains(s, "summary=conflict") || strings.Contains(s, "printf unavailable"):
		out = "disabled"
		if f.cronState != "" {
			out = f.cronState
		}
	case strings.Contains(s, "printf installed"):
		f.installed = true
		out = "installed"
	case strings.Contains(s, "sha256sum") && f.failCheck:
		code = 1
	case strings.Contains(s, "malware-scan"):
		out = "synthetic read-only scan"
	case strings.Contains(s, "printf running"):
		out = "running"
	case strings.Contains(s, "printf stopped"):
		out = "stopped"
	}
	return sshclient.ExecResult{Stdout: out, ExitCode: code}, nil
}

type fakeFetcher struct {
	blob    Blob
	calls   int
	onFetch func()
}

func (f *fakeFetcher) Fetch(context.Context, Artifact) (Blob, error) {
	f.calls++
	if f.onFetch != nil {
		f.onFetch()
	}
	return f.blob, nil
}
func TestAuthorizationIsRecheckedAfterConnectAndDownloadBeforeEffects(t *testing.T) {
	denied := errors.New("synthetic authorization revoked")
	for _, phase := range []string{"connect", "download"} {
		t.Run(phase, func(t *testing.T) {
			revoked := false
			remote := &fakeTransport{uploads: map[string][]byte{}}
			cache := &fakeFetcher{onFetch: func() {
				if phase == "download" {
					revoked = true
				}
			}}
			s := New(func(context.Context, string) (Transport, error) {
				if phase == "connect" {
					revoked = true
				}
				return remote, nil
			}, cache)
			op := Operation{Plugin: "banhack233", Action: "install", Version: "0.2.3", Binding: strings.Repeat("a", 64)}
			_, e := s.Execute(context.Background(), "asset", "job-"+strings.Repeat("a", 32), op, func() error {
				if revoked {
					return denied
				}
				return nil
			})
			require.ErrorIs(t, e, denied)
			require.Empty(t, remote.uploads)
			require.True(t, remote.closed)
			if phase == "connect" {
				require.Empty(t, remote.scripts)
			} else {
				require.NotEmpty(t, remote.scripts)
				require.NotContains(t, strings.Join(remote.scripts, "\n"), "stage=")
			}
		})
	}
}
func TestManagedInstallConfigIsolationAndIdempotency(t *testing.T) {
	raw := []byte("synthetic executable")
	file := filepath.Join(t.TempDir(), "binary")
	require.NoError(t, os.WriteFile(file, raw, 0600))
	cache := &fakeFetcher{blob: Blob{Path: file, Size: int64(len(raw)), SHA256: sha(raw)}}
	remote := &fakeTransport{uploads: map[string][]byte{}}
	s := New(func(context.Context, string) (Transport, error) { return remote, nil }, cache)
	op := Operation{Plugin: "banhack233", Version: "0.2.3", Action: "install", Binding: strings.Repeat("a", 64)}
	r, e := s.Execute(context.Background(), "asset", "job-"+strings.Repeat("1", 32), op)
	require.NoError(t, e)
	require.Equal(t, 0, r.ExitCode)
	require.True(t, remote.closed)
	var result Result
	require.NoError(t, json.Unmarshal([]byte(r.Stdout), &result))
	require.True(t, result.Installed)
	require.False(t, result.Autostart)
	require.True(t, result.DryRun)
	require.Len(t, remote.uploads, 2)
	var cfg map[string]any
	for p, b := range remote.uploads {
		if strings.HasSuffix(p, "/config") {
			require.NoError(t, json.Unmarshal(b, &cfg))
		}
	}
	require.Equal(t, true, cfg["dry_run"])
	require.Equal(t, false, cfg["malware"].(map[string]any)["direct_kill"])
	require.NotContains(t, cfg["notifications"], "enabled")
	scripts := strings.Join(remote.scripts, "\n")
	require.Contains(t, scripts, "'\"'\"'")
	require.NotContains(t, scripts, "sudo")
	require.NotContains(t, scripts, "curl")
	require.NotContains(t, scripts, " -kill")
	require.NotContains(t, scripts, "--tcp")
	_, e = s.Execute(context.Background(), "asset", "job-"+strings.Repeat("2", 32), op)
	require.NoError(t, e)
	require.Len(t, remote.uploads, 2)
	op.Action = "scan"
	_, e = s.Execute(context.Background(), "asset", "job-"+strings.Repeat("3", 32), op)
	require.NoError(t, e)
	require.Contains(t, remote.scripts[len(remote.scripts)-1], "malware-scan -config")
	require.Contains(t, remote.scripts[len(remote.scripts)-1], "sha256sum")
	remote.failCheck = true
	op.Action = "start"
	_, e = s.Execute(context.Background(), "asset", "job-"+strings.Repeat("4", 32), op)
	require.ErrorIs(t, e, ErrIntegrity)
}
func TestDetectIsReadOnlyAndInvalidOperationsNeverConnect(t *testing.T) {
	remote := &fakeTransport{uploads: map[string][]byte{}}
	calls := 0
	s := New(func(context.Context, string) (Transport, error) { calls++; return remote, nil }, nil)
	op := Operation{Plugin: "node_exporter", Version: "1.12.1", Action: "detect", Binding: strings.Repeat("a", 64)}
	_, e := s.Execute(context.Background(), "asset", "job-"+strings.Repeat("a", 32), op)
	require.NoError(t, e)
	require.NotContains(t, strings.Join(remote.scripts, "\n"), "mkdir")
	require.Empty(t, remote.uploads)
	for _, bad := range []Operation{{Plugin: "x;id", Action: "detect"}, {Plugin: op.Plugin, Version: op.Version, Action: "exec", Binding: op.Binding}, {Plugin: op.Plugin, Version: "latest", Action: "install", Binding: op.Binding}} {
		_, e = s.Execute(context.Background(), "asset", "job-"+strings.Repeat("a", 32), bad)
		require.ErrorIs(t, e, ErrInvalid)
	}
	require.Equal(t, 1, calls)
	_, e = s.Execute(context.Background(), "asset", "job-../../inject", op)
	require.ErrorIs(t, e, ErrInvalid)
	require.Equal(t, 1, calls)
	remote.platform = "Linux\nmips\n1000"
	_, e = s.Execute(context.Background(), "asset", "job-"+strings.Repeat("a", 32), op)
	require.ErrorIs(t, e, ErrUnsupported)
}
