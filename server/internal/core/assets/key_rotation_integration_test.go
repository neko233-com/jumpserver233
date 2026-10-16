package assets

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshidentity"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xssh "golang.org/x/crypto/ssh"
)

type interruptKeyUpdater struct {
	KeyUpdater
	beforeInstall func()
	failRetire    bool
}

func (u *interruptKeyUpdater) Install(p sshclient.KeyPlan) error {
	if u.beforeInstall != nil {
		u.beforeInstall()
	}
	return u.KeyUpdater.Install(p)
}
func (u *interruptKeyUpdater) Retire(p sshclient.KeyPlan) error {
	if u.failRetire {
		return errors.New("synthetic interruption after vault commit")
	}
	return u.KeyUpdater.Retire(p)
}

func TestRealOpenSSHKeyLifecycleRecoveryAndFileSafety(t *testing.T) {
	address := os.Getenv("JMS_TEST_KEY_HOST_ADDR")
	if address == "" {
		t.Skip("set JMS_TEST_KEY_HOST_ADDR/FINGERPRINT/NAME from the disposable OpenSSH provisioner")
	}
	require.True(t, strings.HasPrefix(os.Getenv("JMS_TEST_KEY_HOST_NAME"), "jms233-keyhost-"))
	fingerprint := os.Getenv("JMS_TEST_KEY_HOST_FINGERPRINT")
	require.True(t, strings.HasPrefix(fingerprint, "SHA256:"))
	host, portText, e := net.SplitHostPort(address)
	require.NoError(t, e)
	port, e := strconv.Atoi(portText)
	require.NoError(t, e)
	config := &xssh.ClientConfig{User: "keyqa", Auth: []xssh.AuthMethod{xssh.Password("synthetic-keyhost-password-233")}, HostKeyCallback: func(_ string, _ net.Addr, key xssh.PublicKey) error {
		if xssh.FingerprintSHA256(key) != fingerprint {
			return errors.New("fixture fingerprint mismatch")
		}
		return nil
	}, Timeout: 5 * time.Second}
	transport, e := xssh.Dial("tcp", address, config)
	require.NoError(t, e)
	defer transport.Close()
	remote, e := sftp.NewClient(transport)
	require.NoError(t, e)
	defer remote.Close()
	home, e := remote.RealPath(".")
	require.NoError(t, e)
	filename := path.Join(home, ".ssh", "authorized_keys")
	read := func() []byte {
		t.Helper()
		f, e := remote.Open(filename)
		require.NoError(t, e)
		defer f.Close()
		data, e := io.ReadAll(f)
		require.NoError(t, e)
		return data
	}
	write := func(data []byte) {
		t.Helper()
		f, e := remote.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		require.NoError(t, e)
		_, e = f.Write(data)
		require.NoError(t, e)
		require.NoError(t, f.Chmod(0600))
		require.NoError(t, f.Sync())
		require.NoError(t, f.Close())
	}
	original := read()
	defer func() {
		_ = remote.Remove(filename)
		_ = remote.PosixRename(filename+".saved", filename)
		f, e := remote.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		if e == nil {
			_, _ = f.Write(original)
			_ = f.Chmod(0600)
			_ = f.Close()
		}
		_ = remote.Remove(path.Join(home, ".ssh", ".jumpserver233-key.lock"))
	}()
	_, authorityPrivate, e := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, e)
	authority, e := xssh.NewSignerFromKey(authorityPrivate)
	require.NoError(t, e)
	unrelated := "# preserved fixture comment\n" + strings.TrimSpace(string(xssh.MarshalAuthorizedKey(sshidentity.Signer().PublicKey()))) + " unrelated-key\ncert-authority " + strings.TrimSpace(string(xssh.MarshalAuthorizedKey(authority.PublicKey()))) + " unrelated-ca\n"
	write([]byte(unrelated))
	file := filepath.Join(t.TempDir(), "assets.json")
	store, e := OpenStore(file, make([]byte, 32))
	require.NoError(t, e)
	service := NewService(store, nil)
	input := Input{Name: "real Linux SSH", Host: host, Port: port, Username: "keyqa", Password: "synthetic-keyhost-password-233", HostKeyFingerprint: fingerprint}
	asset, e := service.Create(input)
	require.NoError(t, e)
	ctx := context.Background()
	installed, e := service.RotateSSHKey(ctx, asset.ID, "real-install-request", 1, "fixture-admin")
	require.NoError(t, e)
	assert.Equal(t, CredentialSSHKey, installed.CredentialType)
	assert.EqualValues(t, 2, installed.CredentialRevision)
	_, target, oldKey, e := store.connection(asset.ID)
	require.NoError(t, e)
	require.NoError(t, sshclient.VerifyPassword(ctx, target, oldKey, time.Second))
	result, e := service.Exec(ctx, asset.ID, "printf linux-key-ok")
	require.NoError(t, e)
	assert.Equal(t, "linux-key-ok", result.Stdout)
	assert.Contains(t, string(read()), unrelated)
	// Preserve an actual OpenSSH forwarding restriction while rotating the key.
	oldSigner, e := xssh.ParsePrivateKey(oldKey.PrivateKey)
	require.NoError(t, e)
	oldLine := strings.TrimSpace(string(xssh.MarshalAuthorizedKey(oldSigner.PublicKey())))
	contents := string(read())
	contents = strings.Replace(contents, oldLine, "no-port-forwarding,no-agent-forwarding "+oldLine, 1)
	write([]byte(contents))
	rotated, e := service.RotateSSHKey(ctx, asset.ID, "real-rotate-request", 2, "fixture-admin")
	require.NoError(t, e)
	assert.EqualValues(t, 3, rotated.CredentialRevision)
	assert.NotEqual(t, installed.KeyFingerprint, rotated.KeyFingerprint)
	require.Error(t, sshclient.VerifyPassword(ctx, target, oldKey, time.Second))
	_, target, current, e := store.connection(asset.ID)
	require.NoError(t, e)
	require.NoError(t, sshclient.VerifyPassword(ctx, target, current, time.Second))
	assert.Contains(t, string(read()), "no-port-forwarding,no-agent-forwarding ")
	assert.Contains(t, string(read()), unrelated)
	signer, e := xssh.ParsePrivateKey(current.PrivateKey)
	require.NoError(t, e)
	restrictedConfig := *config
	restrictedConfig.Auth = []xssh.AuthMethod{xssh.PublicKeys(signer)}
	restricted, e := xssh.Dial("tcp", address, &restrictedConfig)
	require.NoError(t, e)
	forwardCtx, cancel := context.WithTimeout(ctx, time.Second)
	_, e = restricted.DialContext(forwardCtx, "tcp", "127.0.0.1:22")
	cancel()
	var denied *xssh.OpenChannelError
	require.ErrorAs(t, e, &denied)
	assert.Equal(t, xssh.Prohibited, denied.Reason)
	_ = restricted.Close()
	replay, e := service.RotateSSHKey(ctx, asset.ID, "real-rotate-request", 2, "fixture-admin")
	require.NoError(t, e)
	assert.Equal(t, rotated.KeyFingerprint, replay.KeyFingerprint)
	// Interrupt cleanup after the encrypted new credential has committed.
	service.keyUpdater = func(ctx context.Context, target sshclient.Target, c sshclient.Credentials, id string) (KeyUpdater, error) {
		u, e := sshclient.OpenAuthorizedKeys(ctx, target, c, id)
		if e != nil {
			return nil, e
		}
		return &interruptKeyUpdater{KeyUpdater: u, failRetire: true}, nil
	}
	_, e = service.RotateSSHKey(ctx, asset.ID, "real-interrupted-cleanup", 3, "fixture-admin")
	require.ErrorIs(t, e, ErrSSHKeyRotationFailed)
	p, pending, e := store.PendingSSHKeyChange(asset.ID)
	require.NoError(t, e)
	assert.Equal(t, "cleanup", p.Phase)
	require.NoError(t, sshclient.VerifyPassword(ctx, target, current, time.Second))
	reopened, e := OpenStore(file, make([]byte, 32))
	require.NoError(t, e)
	recovery := NewService(reopened, nil)
	require.NoError(t, reopened.RecordSSHKeyAttempt(asset.ID, "", time.Now().Add(-2*time.Hour)))
	recovery.RecoverPendingSSHKeyChanges(ctx)
	assert.False(t, reopened.HasPendingSSHKeyChange(asset.ID))
	recovered, e := recovery.Get(asset.ID)
	require.NoError(t, e)
	assert.Equal(t, pending.NewFingerprint, recovered.KeyFingerprint)
	assert.EqualValues(t, 4, recovered.CredentialRevision)
	require.Error(t, sshclient.VerifyPassword(ctx, target, current, time.Second))
	_, target, current, e = reopened.connection(asset.ID)
	require.NoError(t, e)
	// A candidate that has not committed can be removed without reverting edits.
	originalVerify := recovery.verifyPassword
	recovery.verifyPassword = func(ctx context.Context, target sshclient.Target, c sshclient.Credentials, d time.Duration) error {
		if len(c.PrivateKey) > 0 {
			key, e := xssh.ParsePrivateKey(c.PrivateKey)
			if e == nil && xssh.FingerprintSHA256(key.PublicKey()) != recovered.KeyFingerprint {
				return errors.New("synthetic verification interruption")
			}
		}
		return originalVerify(ctx, target, c, d)
	}
	_, e = recovery.RotateSSHKey(ctx, asset.ID, "real-cancel-request", 4, "fixture-admin")
	require.ErrorIs(t, e, ErrSSHKeyRotationFailed)
	p, candidate, e := reopened.PendingSSHKeyChange(asset.ID)
	require.NoError(t, e)
	recovery.verifyPassword = originalVerify
	cancelled, e := recovery.CancelSSHKeyChange(ctx, asset.ID, p.OperationID, "fixture-admin")
	require.NoError(t, e)
	assert.Equal(t, recovered.KeyFingerprint, cancelled.KeyFingerprint)
	assert.EqualValues(t, 5, cancelled.CredentialRevision)
	require.Error(t, sshclient.VerifyPassword(ctx, target, candidate.New, time.Second))
	require.NoError(t, sshclient.VerifyPassword(ctx, target, current, time.Second))
	assert.Contains(t, string(read()), unrelated)
	// Unsupported permissions and symlinks fail in the read-only preflight.
	passwordAsset, e := recovery.Create(Input{Name: "preflight fixture", Host: host, Port: port, Username: "keyqa", Password: input.Password, HostKeyFingerprint: fingerprint})
	require.NoError(t, e)
	require.NoError(t, remote.Chmod(filename, 0666))
	_, e = recovery.RotateSSHKey(ctx, passwordAsset.ID, "real-unsafe-permissions", 1, "fixture-admin")
	require.ErrorIs(t, e, ErrSSHKeyRotationFailed)
	assert.False(t, reopened.HasPendingSSHKeyChange(passwordAsset.ID))
	require.NoError(t, remote.Chmod(filename, 0600))
	require.NoError(t, remote.PosixRename(filename, filename+".saved"))
	require.NoError(t, remote.Symlink(filename+".saved", filename))
	_, e = recovery.RotateSSHKey(ctx, passwordAsset.ID, "real-symlink-preflight", 1, "fixture-admin")
	require.ErrorIs(t, e, ErrSSHKeyRotationFailed)
	assert.False(t, reopened.HasPendingSSHKeyChange(passwordAsset.ID))
	info, e := remote.Lstat(filename)
	require.NoError(t, e)
	assert.NotZero(t, info.Mode()&os.ModeSymlink)
	require.NoError(t, remote.Remove(filename))
	require.NoError(t, remote.PosixRename(filename+".saved", filename))
	info, e = remote.Stat(filename)
	require.NoError(t, e)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	assert.NotContains(t, string(read()), "PRIVATE KEY")
	assert.NotContains(t, string(read()), input.Password)
}
