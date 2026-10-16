package hostplugins_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/stretchr/testify/require"
)

type interruptedHost struct {
	hostplugins.Transport
	cut *atomic.Bool
}

func (h *interruptedHost) Run(ctx context.Context, script string) (sshclient.ExecResult, error) {
	for _, marker := range []string{"# transition-start\n", "# protection-start\n"} {
		if prefix, _, found := strings.Cut(script, marker); found && h.cut.CompareAndSwap(true, false) {
			return h.Transport.Run(ctx, prefix+"exit 54")
		}
	}
	return h.Transport.Run(ctx, script)
}

type nativeTools struct {
	service     *hostplugins.Service
	ctx         context.Context
	target      sshclient.Target
	credentials sshclient.Credentials
	sequence    int
	interrupt   atomic.Bool
}

func newNativeTools(t *testing.T, user string) *nativeTools {
	t.Helper()
	address := os.Getenv("JMS_TEST_KEY_HOST_ADDR")
	if address == "" {
		t.Skip("requires owned disposable OpenSSH fixture")
	}
	require.Regexp(t, `^jms233-keyhost-[a-f0-9-]{36}$`, os.Getenv("JMS_TEST_KEY_HOST_NAME"))
	if user == "root" && os.Getenv("JMS_TEST_KEY_HOST_PROTECTION") != "true" {
		t.Skip("requires optional isolated firewall QA capability")
	}
	host, port, e := net.SplitHostPort(address)
	require.NoError(t, e)
	n, e := strconv.Atoi(port)
	require.NoError(t, e)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	t.Cleanup(cancel)
	h := &nativeTools{ctx: ctx, target: sshclient.Target{Host: host, Port: n, Username: user, HostKeyFingerprint: os.Getenv("JMS_TEST_KEY_HOST_FINGERPRINT")}, credentials: sshclient.Credentials{Password: "synthetic-keyhost-password-233"}, sequence: 9000}
	if user == "root" {
		h.credentials.Password = "synthetic-protection-root-password-233"
	}
	cache, e := hostplugins.NewCache(t.TempDir())
	require.NoError(t, e)
	h.service = hostplugins.New(func(ctx context.Context, _ string) (hostplugins.Transport, error) {
		remote, e := sshclient.OpenManagedHost(ctx, h.target, h.credentials)
		if e != nil {
			return nil, e
		}
		return &interruptedHost{Transport: remote, cut: &h.interrupt}, nil
	}, cache)
	return h
}

func (h *nativeTools) perform(t *testing.T, plugin, action, version string, policy *hostplugins.ProtectionPolicy) (hostplugins.Result, error) {
	t.Helper()
	var nonce [16]byte
	_, nonceErr := rand.Read(nonce[:])
	require.NoError(t, nonceErr)
	d, e := hostplugins.Lookup(plugin)
	require.NoError(t, e)
	op := hostplugins.Operation{Plugin: plugin, Action: action, Version: d.Version, Binding: strings.Repeat("e", 64), Protection: policy}
	if version != "" {
		op.Version = version
	} else if action != "install" && action != "upgrade" {
		op.Selection = "installed"
	}
	r, e := h.service.Execute(h.ctx, "fixture", "job-"+hex.EncodeToString(nonce[:]), op)
	var result hostplugins.Result
	require.NoError(t, json.Unmarshal([]byte(r.Stdout), &result))
	return result, e
}

func (h *nativeTools) success(t *testing.T, plugin, action, version string, policy *hostplugins.ProtectionPolicy) hostplugins.Result {
	t.Helper()
	result, e := h.perform(t, plugin, action, version, policy)
	require.NoError(t, e, "%s %s %s", plugin, action, result.Detail)
	return result
}

func (h *nativeTools) run(t *testing.T, script string) sshclient.ExecResult {
	t.Helper()
	remote, e := sshclient.OpenManagedHost(h.ctx, h.target, h.credentials)
	require.NoError(t, e)
	defer remote.Close()
	r, e := remote.Run(h.ctx, script)
	require.NoError(t, e)
	return r
}

func TestNativePinnedReleasesUpgradeRollbackAndExplicitInterruptedRecovery(t *testing.T) {
	h := newNativeTools(t, "pluginqa")
	for _, d := range hostplugins.Catalog() {
		t.Run(d.ID, func(t *testing.T) {
			old := d.Releases[0].Version
			require.Equal(t, old, h.success(t, d.ID, "install", old, nil).Version)
			status := h.success(t, d.ID, "status", "", nil)
			require.Equal(t, old, status.Version)
			require.True(t, status.UpgradeAvailable)
			require.True(t, h.success(t, d.ID, "autostart_enable", "", nil).Autostart)
			h.interrupt.Store(true)
			failed, e := h.perform(t, d.ID, "upgrade", "", nil)
			require.Error(t, e)
			require.True(t, failed.TransitionPending)
			pending := h.success(t, d.ID, "detect", "", nil)
			require.True(t, pending.TransitionPending)
			require.False(t, pending.Running)
			_, e = h.perform(t, d.ID, "start", "", nil)
			require.ErrorIs(t, e, hostplugins.ErrConflict)
			restored := h.success(t, d.ID, "rollback", "", nil)
			require.Equal(t, old, restored.Version)
			require.True(t, restored.Running)
			require.True(t, restored.Autostart)
			updated := h.success(t, d.ID, "upgrade", "", nil)
			require.Equal(t, d.Version, updated.Version)
			require.True(t, updated.Running)
			require.False(t, updated.UpgradeAvailable)
			require.Equal(t, d.Version, h.success(t, d.ID, "upgrade", "", nil).Version)
			require.Equal(t, old, h.success(t, d.ID, "rollback", "", nil).Version)
			require.Equal(t, d.Version, h.success(t, d.ID, "upgrade", "", nil).Version)
			require.False(t, h.success(t, d.ID, "uninstall", "", nil).Installed)
		})
	}
}
