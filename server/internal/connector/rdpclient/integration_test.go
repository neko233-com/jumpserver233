package rdpclient_test

import (
	"bytes"
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/connector/rdpclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/testsupport/postgresfixture"
	"github.com/neko233-com/jumpserver233/server/testsupport/rdpfixture"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshgateway"
	"github.com/stretchr/testify/require"
	"image/png"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNativeDesktop(t *testing.T) {
	target := rdpfixture.Load(t)

	target.Clipboard = true
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, rdpclient.Probe(ctx, target))
	client, e := rdpclient.Open(ctx, target, rdpfixture.Username, rdpfixture.Password)
	require.NoError(t, e)
	defer client.Close()
	client.SetClipboardGuard(func(string) error { return nil })
	t.Logf("native server advertised Unicode input: %t", client.SupportsUnicodeInput())
	if !client.SupportsUnicodeInput() {
		require.ErrorIs(t, client.Input(rdpclient.Input{Type: "text", Text: "中文"}), rdpclient.ErrTextUnsupported)
	}
	defer func() {
		if path := os.Getenv("JMS_TEST_RDP_CAPTURE"); path != "" {
			if f, e := client.Snapshot(); e == nil {
				_ = os.WriteFile(path, f.PNG, 0600)
			}
		}
	}()
	require.Eventually(t, func() bool {
		select {
		case <-client.Done():
			return true
		default:
		}
		f, e := client.Snapshot()
		if e != nil {
			return false
		}
		im, e := png.Decode(bytes.NewReader(f.PNG))
		if e != nil {
			return false
		}
		r, g, b, _ := im.At(60, 430).RGBA()
		return r > 45000 && g < 35000 && b < 35000
	}, 20*time.Second, 100*time.Millisecond)
	select {
	case <-client.Done():
		t.Fatalf("native desktop closed before first application frame: %s", client.FailureCode())
	default:
	}
	before, _ := rdpfixture.ReadState()
	require.NoError(t, client.Input(rdpclient.Input{Type: "pointer", Action: "button", Button: "left", Down: true, X: 100, Y: 175}))
	require.NoError(t, client.Input(rdpclient.Input{Type: "pointer", Action: "button", Button: "left", Down: false, X: 100, Y: 175}))
	require.NoError(t, client.Input(rdpclient.Input{Type: "pointer", Action: "button", Button: "left", Down: true, X: 100, Y: 260}))
	require.NoError(t, client.Input(rdpclient.Input{Type: "pointer", Action: "button", Button: "left", Down: false, X: 100, Y: 260}))
	require.Eventually(t, func() bool { s, e := rdpfixture.ReadState(); return e == nil && s.Clicks > before.Clicks && s.Focus }, 5*time.Second, 50*time.Millisecond)
	require.NoError(t, client.Input(rdpclient.Input{Type: "text", Text: "Native RDP 233"}))
	require.Eventually(t, func() bool {
		s, e := rdpfixture.ReadState()
		return e == nil && s.Clicks > 0 && strings.Contains(s.Text, "Native RDP 233") && strings.HasPrefix(s.Display, ":")
	}, 5*time.Second, 50*time.Millisecond)
	click := func(x, y int) {
		require.NoError(t, client.Input(rdpclient.Input{Type: "pointer", Action: "button", Button: "left", Down: true, X: x, Y: y}))
		require.NoError(t, client.Input(rdpclient.Input{Type: "pointer", Action: "button", Button: "left", Down: false, X: x, Y: y}))
	}
	click(800, 175)
	require.Eventually(t, func() bool { return client.Input(rdpclient.Input{Type: "clipboard_read"}) == nil }, 5*time.Second, 100*time.Millisecond)
	require.Eventually(t, func() bool { return strings.Contains(client.Clipboard(), "Native RDP 233") }, 5*time.Second, 100*time.Millisecond)
	require.NoError(t, client.Input(rdpclient.Input{Type: "clipboard_write", Text: "Remote Clipboard 233 中文"}))
	click(800, 260)
	require.Eventually(t, func() bool {
		s, e := rdpfixture.ReadState()
		return e == nil && s.Text == "Remote Clipboard 233 中文"
	}, 5*time.Second, 100*time.Millisecond)
	f, e := client.Snapshot()
	require.NoError(t, e)
	require.Greater(t, f.Sequence, uint64(1))
	if path := os.Getenv("JMS_TEST_RDP_CAPTURE"); path != "" {
		require.NoError(t, os.WriteFile(path, f.PNG, 0600))
	}
}

func TestNativeRDPCertificateModeAndPinnedGateway(t *testing.T) {
	target := rdpfixture.Load(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	bad := target
	bad.ServerName = "wrong.synthetic.invalid"
	require.Error(t, rdpclient.Probe(ctx, bad))
	bad = target
	bad.RootCAPEM = ""
	require.Error(t, rdpclient.Probe(ctx, bad))
	bad = target
	bad.Security = "nla"
	_, e := rdpclient.Open(ctx, bad, rdpfixture.Username, rdpfixture.Password)
	require.Error(t, e)
	destination := postgresfixture.LoopbackForward(t, net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))
	g, e := sshgateway.Start("127.0.0.1:0", map[string]string{"rdp.synthetic.invalid:3389": destination})
	require.NoError(t, e)
	defer g.Close()
	host, portText, _ := net.SplitHostPort(g.Address())
	port, _ := strconv.Atoi(portText)
	target.Host = "rdp.synthetic.invalid"
	target.Port = 3389
	target.Gateways = []sshclient.Hop{{Target: sshclient.Target{Host: host, Port: port, Username: sshgateway.Username, HostKeyFingerprint: g.Fingerprint}, Credentials: sshclient.Credentials{Password: sshgateway.Password}}}
	require.NoError(t, rdpclient.Probe(ctx, target))
	client, e := rdpclient.Open(ctx, target, rdpfixture.Username, rdpfixture.Password)
	require.NoError(t, e)
	f, e := client.Snapshot()
	require.NoError(t, e)
	require.Greater(t, len(f.PNG), 8)
	client.Close()
	target.Gateways[0].Target.HostKeyFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	require.Error(t, rdpclient.Probe(ctx, target))
}
