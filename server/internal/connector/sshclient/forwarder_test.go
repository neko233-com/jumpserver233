package sshclient

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshgateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestForwarderPinsGatewayReusesConnectionAndIsolatesChannelDeadlines(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, e)
	defer listener.Close()
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	gateway, e := sshgateway.Start("127.0.0.1:0", map[string]string{"192.0.2.1:22": listener.Addr().String()})
	require.NoError(t, e)
	defer gateway.Close()
	host, port, _ := net.SplitHostPort(gateway.Address())
	p, _ := strconv.Atoi(port)
	target := Target{Host: host, Port: p, Username: sshgateway.Username, HostKeyFingerprint: gateway.Fingerprint}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f, e := OpenForwarder(ctx, target, Credentials{Password: sshgateway.Password}, time.Second)
	require.NoError(t, e)
	defer f.Close()
	first, e := f.Dial(ctx, "192.0.2.1:22")
	require.NoError(t, e)
	defer first.Close()
	second, e := f.Dial(ctx, "192.0.2.1:22")
	require.NoError(t, e)
	defer second.Close()
	require.NoError(t, first.SetDeadline(time.Now().Add(20*time.Millisecond)))
	_, e = first.Read(make([]byte, 1))
	require.Error(t, e)
	require.NoError(t, second.SetDeadline(time.Now().Add(time.Second)))
	_, e = second.Write([]byte("ok"))
	require.NoError(t, e)
	buffer := make([]byte, 2)
	_, e = io.ReadFull(second, buffer)
	require.NoError(t, e)
	assert.Equal(t, "ok", string(buffer))
	assert.EqualValues(t, 2, gateway.Forwards())
	_, e = f.Dial(ctx, "192.0.2.2:22")
	require.Error(t, e)
	cancel()
	require.Eventually(t, func() bool { return gateway.Active() == 0 }, time.Second, 5*time.Millisecond)
	target.HostKeyFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	_, e = OpenForwarder(context.Background(), target, Credentials{Password: sshgateway.Password}, time.Second)
	require.Error(t, e)
}
