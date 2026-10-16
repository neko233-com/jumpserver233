package sshclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshidentity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xssh "golang.org/x/crypto/ssh"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestImportPrivateKeyValidatesFormatsPassphrasePolicyAndWorkLimit(t *testing.T) {
	for _, passphrase := range []string{"", sshidentity.Passphrase} {
		normalized, pin, e := ImportPrivateKey(sshidentity.PEM(passphrase), passphrase)
		require.NoError(t, e)
		signer, e := xssh.ParsePrivateKey(normalized)
		require.NoError(t, e)
		assert.Equal(t, xssh.FingerprintSHA256(signer.PublicKey()), pin)
		assert.Equal(t, xssh.FingerprintSHA256(sshidentity.Signer().PublicKey()), pin)
	}
	for _, input := range [][]byte{nil, []byte("not a key"), make([]byte, MaxPrivateKeyBytes+1), append(sshidentity.PEM(""), sshidentity.PEM("")...), sshidentity.PEM(sshidentity.Passphrase)} {
		_, _, e := ImportPrivateKey(input, "")
		assert.ErrorIs(t, e, ErrPrivateKey)
	}
	_, _, e := ImportPrivateKey(sshidentity.PEM(sshidentity.Passphrase), "wrong")
	assert.ErrorIs(t, e, ErrPrivateKey)
	weak, e := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, e)
	block, e := xssh.MarshalPrivateKey(weak, "")
	require.NoError(t, e)
	_, _, e = ImportPrivateKey(pem.EncodeToMemory(block), "")
	assert.ErrorIs(t, e, ErrPrivateKey)
	strong, e := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, e)
	block, e = xssh.MarshalPrivateKey(strong, "")
	require.NoError(t, e)
	_, _, e = ImportPrivateKey(pem.EncodeToMemory(block), "")
	require.NoError(t, e)
	ec, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, e)
	block, e = xssh.MarshalPrivateKey(ec, "")
	require.NoError(t, e)
	_, _, e = ImportPrivateKey(pem.EncodeToMemory(block), "")
	require.NoError(t, e)
	block, _ = pem.Decode(sshidentity.PEM(sshidentity.Passphrase))
	var header struct {
		Cipher, KDF, Options string
		Count                uint32
		Public, Private      []byte
	}
	magic := []byte("openssh-key-v1\x00")
	require.NoError(t, xssh.Unmarshal(block.Bytes[len(magic):], &header))
	header.Options = string(xssh.Marshal(struct {
		Salt   string
		Rounds uint32
	}{Salt: "synthetic", Rounds: 1 << 30}))
	block.Bytes = append(magic, xssh.Marshal(header)...)
	started := time.Now()
	_, _, e = ImportPrivateKey(pem.EncodeToMemory(block), sshidentity.Passphrase)
	require.ErrorIs(t, e, ErrPrivateKey)
	assert.Less(t, time.Since(started), 250*time.Millisecond)
}
func TestPrivateKeyAuthenticatesTargetAndEveryGatewayForMetricsExecSFTPAndRotation(t *testing.T) {
	key, _, e := ImportPrivateKey(sshidentity.PEM(sshidentity.Passphrase), sshidentity.Passphrase)
	require.NoError(t, e)
	credentials := Credentials{PrivateKey: key}
	listener, pin := startMetricsServer(t)
	t.Cleanup(func() { _ = listener.Close() })
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	p, _ := strconv.Atoi(port)
	target, servers := routedTarget(t, Target{Host: host, Port: p, Username: "monitor", HostKeyFingerprint: pin}, 3)
	for i := range target.Gateways {
		target.Gateways[i].Credentials = credentials
	}
	metrics, e := Probe(context.Background(), target, credentials, 3*time.Second)
	require.NoError(t, e)
	assert.Equal(t, 21.5, metrics.CPUPercent)
	result, e := Exec(context.Background(), target, credentials, metricsCommand)
	require.NoError(t, e)
	assert.Equal(t, 0, result.ExitCode)
	for _, s := range servers {
		assert.EqualValues(t, 2, s.Forwards())
	}
	files, ft := startSFTPTestServer(t, t.TempDir())
	t.Cleanup(func() { _ = files.Close() })
	ft, _ = routedTarget(t, ft, 1)
	remote, e := OpenSFTP(context.Background(), ft, credentials, time.Second)
	require.NoError(t, e)
	_, e = remote.ReadDir(context.Background(), remote.Root())
	require.NoError(t, e)
	require.NoError(t, remote.Close())
	rotation, rt := startRotationServer(t, "0", "synthetic-current-password")
	t.Cleanup(func() { _ = rotation.listener.Close() })
	require.NoError(t, ChangePassword(context.Background(), rt, credentials, "synthetic-restored-password-with-key-auth-233", 3*time.Second))
	require.NoError(t, VerifyPassword(context.Background(), rt, Credentials{Password: "synthetic-restored-password-with-key-auth-233"}, time.Second))
}

func TestHistoricalPasswordRestoreKeepsGeneratedPolicyAndRejectsRecordInjection(t *testing.T) {
	server, target := startRotationServer(t, "0", "initial-password")
	t.Cleanup(func() { _ = server.listener.Close() })
	require.NoError(t, RestorePassword(context.Background(), target, Credentials{PrivateKey: sshidentity.PEM("")}, "Historical:password!233", 2*time.Second))
	require.NoError(t, VerifyPassword(context.Background(), target, Credentials{Password: "Historical:password!233"}, time.Second))
	for _, bad := range []string{"", "bad\nroot:injected", "bad\rline", "bad\x00value"} {
		assert.ErrorIs(t, RestorePassword(context.Background(), target, Credentials{}, bad, time.Second), ErrInvalidGeneratedPassword)
	}
	assert.ErrorIs(t, ChangePassword(context.Background(), target, Credentials{}, "too-short", time.Second), ErrInvalidGeneratedPassword)
}
