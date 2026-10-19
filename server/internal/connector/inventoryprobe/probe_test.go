package inventoryprobe

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xssh "golang.org/x/crypto/ssh"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestProbeSSHObservesPinBeforeAuthentication(t *testing.T) {
	_, key, e := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, e)
	signer, e := xssh.NewSignerFromKey(key)
	require.NoError(t, e)
	var authenticated atomic.Int32
	config := &xssh.ServerConfig{NoClientAuth: true, NoClientAuthCallback: func(xssh.ConnMetadata) (*xssh.Permissions, error) { authenticated.Add(1); return nil, nil }}
	config.AddHostKey(signer)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, e)
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := listener.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_, _, _, _ = xssh.NewServerConn(c, config)
	}()
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	p, _ := strconv.Atoi(port)
	result := Probe(context.Background(), host, p, "ssh", time.Second, nil)
	assert.True(t, result.Open)
	assert.True(t, result.SSHVerified)
	assert.Equal(t, xssh.FingerprintSHA256(signer.PublicKey()), result.HostKeyFingerprint)
	<-done
	assert.Zero(t, authenticated.Load(), "discovery must stop before any user authentication")
}
func TestProbeBoundsCancellationAndTCPOnly(t *testing.T) {
	for _, host := range []string{"example.invalid", "127.0.0.1%zone", "not-an-ip"} {
		r := Probe(context.Background(), host, 22, "ssh", time.Second, nil)
		assert.Equal(t, "scan_invalid_target", r.ErrorCode)
	}
	assert.Equal(t, "scan_invalid_target", Probe(context.Background(), "127.0.0.1", 0, "ssh", time.Second, nil).ErrorCode)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, e)
	defer listener.Close()
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	p, _ := strconv.Atoi(port)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 2 {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(io.Discard, c) }()
		}
	}()
	r := Probe(context.Background(), host, p, "mysql", time.Second, nil)
	assert.True(t, r.Open)
	assert.False(t, r.SSHVerified)
	assert.Empty(t, r.HostKeyFingerprint)
	started := time.Now()
	r = Probe(context.Background(), host, p, "ssh", 100*time.Millisecond, nil)
	assert.Less(t, time.Since(started), time.Second)
	assert.False(t, r.SSHVerified)
	assert.Equal(t, "scan_ssh_handshake", r.ErrorCode)
	<-done
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = Probe(ctx, host, p, "ssh", time.Second, nil)
	assert.False(t, r.Open)
}
