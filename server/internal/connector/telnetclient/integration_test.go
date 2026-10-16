package telnetclient_test

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/telnetclient"
	"github.com/neko233-com/jumpserver233/server/testsupport/postgresfixture"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshgateway"
	"github.com/neko233-com/jumpserver233/server/testsupport/telnetfixture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNativeLinuxTelnetTLSPlainResizeAndPinnedGateway(t *testing.T) {
	for _, plain := range []bool{false, true} {
		t.Run(map[bool]string{true: "plain", false: "verifiedTLS"}[plain], func(t *testing.T) {
			target := telnetfixture.Load(t, plain)
			ctx, stop := context.WithTimeout(context.Background(), 20*time.Second)
			defer stop()
			s, e := telnetclient.OpenShell(ctx, target, telnetfixture.Username, telnetfixture.Password, 100, 30)
			require.NoError(t, e)
			defer s.Close()
			require.NoError(t, s.Resize(120, 40))
			_, e = s.Write([]byte("printf '__TELNET_NATIVE__\\n'; id -un; stty size; exit\r\n"))
			require.NoError(t, e)
			out, e := io.ReadAll(s)
			require.NoError(t, e)
			assert.Contains(t, string(out), "__TELNET_NATIVE__")
			assert.Contains(t, string(out), "telnetqa")
			assert.Contains(t, string(out), "40 120")
			assert.NotContains(t, string(out), telnetfixture.Password)
		})
	}
	target := telnetfixture.Load(t, false)
	destination := postgresfixture.LoopbackForward(t, net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))
	g, e := sshgateway.Start("127.0.0.1:0", map[string]string{"telnet.synthetic.invalid:992": destination})
	require.NoError(t, e)
	defer g.Close()
	host, portText, _ := net.SplitHostPort(g.Address())
	port, _ := strconv.Atoi(portText)
	target.Host = "telnet.synthetic.invalid"
	target.Port = 992
	target.Gateways = []sshclient.Hop{{Target: sshclient.Target{Host: host, Port: port, Username: sshgateway.Username, HostKeyFingerprint: g.Fingerprint}, Credentials: sshclient.Credentials{Password: sshgateway.Password}}}
	ctx, stop := context.WithTimeout(context.Background(), 20*time.Second)
	defer stop()
	s, e := telnetclient.OpenShell(ctx, target, telnetfixture.Username, telnetfixture.Password, 80, 24)
	require.NoError(t, e)
	_, e = s.Write([]byte("echo __TELNET_GATEWAY__; exit\n"))
	require.NoError(t, e)
	out, e := io.ReadAll(s)
	s.Close()
	require.NoError(t, e)
	assert.True(t, strings.Contains(string(out), "__TELNET_GATEWAY__"))
	target.Gateways[0].Target.HostKeyFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	_, e = telnetclient.OpenShell(ctx, target, telnetfixture.Username, telnetfixture.Password, 80, 24)
	assert.Error(t, e)
}
