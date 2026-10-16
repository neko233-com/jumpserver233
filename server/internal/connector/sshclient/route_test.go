package sshclient

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"path"
	"strconv"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/testsupport/sshgateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func routedTarget(t *testing.T, target Target, hops int) (Target, []*sshgateway.Server) {
	t.Helper()
	destination := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	target.Host = "private.synthetic.invalid"
	target.Port = 22
	alias := "private.synthetic.invalid:22"
	var gateways []*sshgateway.Server
	var route []Hop
	for i := 0; i < hops; i++ {
		s, e := sshgateway.Start("127.0.0.1:0", map[string]string{alias: destination})
		require.NoError(t, e)
		t.Cleanup(s.Close)
		gateways = append(gateways, s)
		host, port, e := net.SplitHostPort(s.Address())
		require.NoError(t, e)
		p, e := strconv.Atoi(port)
		require.NoError(t, e)
		hop := Hop{Target: Target{Host: host, Port: p, Username: sshgateway.Username, HostKeyFingerprint: s.Fingerprint}, Credentials: Credentials{Password: sshgateway.Password}}
		if i > 0 {
			route[0].Target.Host = "inner.synthetic.invalid"
			route[0].Target.Port = 22
		}
		route = append([]Hop{hop}, route...)
		destination = s.Address()
		alias = "inner.synthetic.invalid:22"
	}
	target.Gateways = route
	return target, gateways
}
func TestGatewayProbeExecPinsAndClosesEveryHop(t *testing.T) {
	for _, hops := range []int{1, 3} {
		t.Run(strconv.Itoa(hops), func(t *testing.T) {
			listener, pin := startMetricsServer(t)
			t.Cleanup(func() { _ = listener.Close() })
			host, port, e := net.SplitHostPort(listener.Addr().String())
			require.NoError(t, e)
			p, _ := strconv.Atoi(port)
			target, servers := routedTarget(t, Target{Host: host, Port: p, Username: "monitor", HostKeyFingerprint: pin}, hops)
			metrics, e := Probe(context.Background(), target, Credentials{Password: "test-only"}, 3*time.Second)
			require.NoError(t, e)
			assert.Equal(t, 21.5, metrics.CPUPercent)
			result, e := Exec(context.Background(), target, Credentials{Password: "test-only"}, metricsCommand)
			require.NoError(t, e)
			assert.Equal(t, 0, result.ExitCode)
			assert.Contains(t, result.Stdout, "cpu_cores=8")
			for _, s := range servers {
				assert.EqualValues(t, 2, s.Forwards())
				require.Eventually(t, func() bool { return s.Active() == 0 }, time.Second, 10*time.Millisecond)
			}
			secret, e := json.Marshal(target)
			require.NoError(t, e)
			assert.NotContains(t, string(secret), sshgateway.Password)
			assert.NotContains(t, string(secret), sshgateway.Username)
			bad := target
			bad.Gateways = append([]Hop(nil), target.Gateways...)
			bad.Gateways[0].Target.HostKeyFingerprint = "SHA256:incorrect"
			_, e = Probe(context.Background(), bad, Credentials{Password: "test-only"}, time.Second)
			var gateway *GatewayError
			require.ErrorAs(t, e, &gateway)
			assert.Equal(t, "SSH gateway connection failed", e.Error())
			bad = target
			bad.Gateways = append([]Hop(nil), target.Gateways...)
			bad.Gateways[0].Credentials.Password = "wrong"
			_, e = Probe(context.Background(), bad, Credentials{Password: "test-only"}, time.Second)
			require.ErrorAs(t, e, &gateway)
			bad = target
			bad.HostKeyFingerprint = "SHA256:incorrect-target"
			_, e = Probe(context.Background(), bad, Credentials{Password: "test-only"}, time.Second)
			require.Error(t, e)
			assert.False(t, errors.As(e, &gateway))
		})
	}
}
func TestGatewaySFTPAndRotationUseSameRoute(t *testing.T) {
	listener, target := startSFTPTestServer(t, t.TempDir())
	t.Cleanup(func() { _ = listener.Close() })
	target, servers := routedTarget(t, target, 2)
	remote, e := OpenSFTP(context.Background(), target, Credentials{Password: "sftp-test-password"}, 2*time.Second)
	require.NoError(t, e)
	entries, e := remote.ReadDir(context.Background(), remote.Root())
	require.NoError(t, e)
	assert.Empty(t, entries)
	require.NoError(t, remote.Mkdir(context.Background(), path.Join(remote.Root(), "routed")))
	require.NoError(t, remote.Close())
	for _, s := range servers {
		assert.Positive(t, s.Forwards())
	}
	rotation, rt := startRotationServer(t, "0", "initial-password")
	t.Cleanup(func() { _ = rotation.listener.Close() })
	rt, _ = routedTarget(t, rt, 1)
	require.NoError(t, ChangePassword(context.Background(), rt, Credentials{Password: "initial-password"}, "synthetic-new-gateway-target-password", 3*time.Second))
	require.NoError(t, VerifyPassword(context.Background(), rt, Credentials{Password: "synthetic-new-gateway-target-password"}, time.Second))
	require.Error(t, VerifyPassword(context.Background(), rt, Credentials{Password: "initial-password"}, time.Second))
}
func TestGatewayTimeoutAndInvalidRoutesCloseTransport(t *testing.T) {
	stalled, e := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, e)
	t.Cleanup(func() { _ = stalled.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		raw, e := stalled.Accept()
		if e == nil {
			accepted <- raw
		}
	}()
	host, port, _ := net.SplitHostPort(stalled.Addr().String())
	p, _ := strconv.Atoi(port)
	target, servers := routedTarget(t, Target{Host: host, Port: p, Username: "stall", HostKeyFingerprint: "SHA256:unused"}, 1)
	started := time.Now()
	_, _, e = dial(context.Background(), target, Credentials{Password: "unused"}, 100*time.Millisecond)
	require.Error(t, e)
	assert.Less(t, time.Since(started), time.Second)
	select {
	case raw := <-accepted:
		_ = raw.Close()
	case <-time.After(time.Second):
		t.Fatal("target not reached")
	}
	require.Eventually(t, func() bool { return servers[0].Active() == 0 }, time.Second, 10*time.Millisecond)
	target.Gateways = append(target.Gateways, target.Gateways[0], target.Gateways[0], target.Gateways[0])
	_, _, e = dial(context.Background(), target, Credentials{Password: "unused"}, time.Second)
	require.Error(t, e)
	target.Gateways = target.Gateways[:1]
	target.Gateways[0].Target.Gateways = []Hop{{}}
	_, _, e = dial(context.Background(), target, Credentials{Password: "unused"}, time.Second)
	require.Error(t, e)
}
