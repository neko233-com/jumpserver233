package hostplugins_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/agentbundle"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xssh "golang.org/x/crypto/ssh"
)

func TestNativeRemoteAccountCreatesKeyIdentityDisablesRestoresAndDeletesWithoutRemovingHome(t *testing.T) {
	if os.Getenv("JMS_TEST_KEY_HOST_ADDR") == "" || os.Getenv("JMS_TEST_KEY_HOST_ACCOUNT_ADMIN") != "true" && os.Getenv("JMS_TEST_KEY_HOST_PROTECTION") != "true" {
		t.Skip("requires an owned root-enabled OpenSSH fixture")
	}
	require.Regexp(t, `^jms233-keyhost-[a-f0-9-]{36}$`, os.Getenv("JMS_TEST_KEY_HOST_NAME"))
	host, portText, e := net.SplitHostPort(os.Getenv("JMS_TEST_KEY_HOST_ADDR"))
	require.NoError(t, e)
	require.True(t, net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback() || host == "host.docker.internal", "native mutation requires a local Docker fixture")
	labelsRaw, e := exec.Command("docker", "inspect", "--format", "{{json .Config.Labels}}", os.Getenv("JMS_TEST_KEY_HOST_NAME")).Output()
	require.NoError(t, e)
	var labels map[string]string
	require.NoError(t, json.Unmarshal(labelsRaw, &labels))
	owner := labels["com.jumpserver233.qa.owner"]
	require.True(t, owner == os.Getenv("JMS_TEST_KEY_HOST_NAME") || strings.HasPrefix(owner, "jumpserver233-e2e-"), "fixture owner label must match")
	port, e := strconv.Atoi(portText)
	require.NoError(t, e)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	target := sshclient.Target{Host: host, Port: port, Username: "root", HostKeyFingerprint: os.Getenv("JMS_TEST_KEY_HOST_FINGERPRINT")}
	rootPassword := "synthetic-account-admin-root-password-233"
	if os.Getenv("JMS_TEST_KEY_HOST_PROTECTION") == "true" {
		rootPassword = "synthetic-protection-root-password-233"
	}
	rootCredentials := sshclient.Credentials{Password: rootPassword}
	service := hostplugins.New(func(ctx context.Context, _ string) (hostplugins.Transport, error) {
		return sshclient.OpenManagedHost(ctx, target, rootCredentials)
	}, nil)
	var nonce [16]byte
	_, e = rand.Read(nonce[:])
	require.NoError(t, e)
	suffix := hex.EncodeToString(nonce[:])
	username := "remoteqa_" + suffix[:16]
	_, private, e := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, e)
	block, e := xssh.MarshalPrivateKey(private, "")
	require.NoError(t, e)
	privatePEM := pem.EncodeToMemory(block)
	signer, e := xssh.NewSignerFromKey(private)
	require.NoError(t, e)
	task := hostagent.AccountAdminTask{ID: "ra-" + suffix, Action: "create", Username: username, Shell: "/bin/sh", PublicKey: strings.TrimSpace(string(xssh.MarshalAuthorizedKey(signer.PublicKey())))}
	op := hostagent.AccountOperation{CollectorAccount: "root", Task: task, Mode: "apply", Attempt: 1, Binding: strings.Repeat("a", 64), Target: strings.Repeat("b", 64), ParentAssetID: "physical-fixture", AccountID: "managed-fixture"}
	job := func() string {
		var b [16]byte
		_, e := rand.Read(b[:])
		require.NoError(t, e)
		return "job-" + hex.EncodeToString(b[:])
	}
	created, e := service.ExecuteAccountAdmin(ctx, "root-fixture", job(), op.ParentAssetID, op, func() error { return nil })
	require.NoError(t, e, created.ErrorCode)
	require.Equal(t, "applied", created.State)
	assert.GreaterOrEqual(t, created.UID, uint32(1000))
	assert.Equal(t, "/home/"+username, created.Home)
	userTarget := target
	userTarget.Username = username
	require.NoError(t, sshclient.VerifyPassword(ctx, userTarget, sshclient.Credentials{PrivateKey: privatePEM}, 5*time.Second))
	op.Mode = "inspect"
	inspected, e := service.ExecuteAccountAdmin(ctx, "root-fixture", job(), op.ParentAssetID, op, func() error { return nil })
	require.NoError(t, e)
	assert.Equal(t, created, inspected)
	root, e := sshclient.OpenManagedHost(ctx, target, rootCredentials)
	require.NoError(t, e)
	defer root.Close()
	sudoPath := "/etc/sudoers.d/jms233-qa-" + suffix
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		cleanup, e := sshclient.OpenManagedHost(cleanupCtx, target, rootCredentials)
		if e != nil {
			return
		}
		defer cleanup.Close()
		_, _ = cleanup.Run(cleanupCtx, "rm -f '"+sudoPath+"'")
	})
	bundle, e := agentbundle.Get("linux-amd64")
	require.NoError(t, e)
	global := hostagent.AccountAdminBinaryDirectory + "/agent-recovery-" + bundle.SHA256
	r, e := root.Run(ctx, "set -eu; set -C; printf '%s\\n' 'pluginqa ALL=(root) NOPASSWD: "+global+" account-admin' > '"+sudoPath+"'; chmod 0440 '"+sudoPath+"'")
	require.NoError(t, e)
	require.Zero(t, r.ExitCode)
	delegatedTarget := target
	delegatedTarget.Username = "pluginqa"
	delegated := hostplugins.New(func(ctx context.Context, _ string) (hostplugins.Transport, error) {
		return sshclient.OpenManagedHost(ctx, delegatedTarget, sshclient.Credentials{Password: "synthetic-keyhost-password-233"})
	}, nil)
	for _, action := range []string{"disable", "enable", "delete"} {
		var next [16]byte
		_, e = rand.Read(next[:])
		require.NoError(t, e)
		op.Task = hostagent.AccountAdminTask{ID: "ra-" + hex.EncodeToString(next[:]), Action: action, Username: username, UID: created.UID}
		op.Mode = "apply"
		op.CollectorAccount = "pluginqa"
		result, e := delegated.ExecuteAccountAdmin(ctx, "delegated-fixture", job(), op.ParentAssetID, op, func() error { return nil })
		require.NoError(t, e, result.ErrorCode)
		assert.Equal(t, "applied", result.State)
		login := sshclient.VerifyPassword(ctx, userTarget, sshclient.Credentials{PrivateKey: privatePEM}, 5*time.Second)
		if action == "enable" {
			require.NoError(t, login)
		} else {
			require.Error(t, login)
		}
	}
	r, e = root.Run(ctx, "stat -c '%u:%a' '/home/"+username+"'; test -f '/home/"+username+"/.ssh/authorized_keys'")
	require.NoError(t, e)
	require.Zero(t, r.ExitCode)
	assert.Equal(t, "0:700", strings.TrimSpace(r.Stdout), "deleted home remains quarantined rather than removed")
}
