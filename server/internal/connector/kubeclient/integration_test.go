package kubeclient_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"github.com/neko233-com/jumpserver233/server/internal/connector/kubeclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/testsupport/kubefixture"
	"github.com/neko233-com/jumpserver233/server/testsupport/postgresfixture"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshgateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRealK3sVerifiedTLSListExecResizeExitAndNativeRBAC(t *testing.T) {
	target, token := kubefixture.Load(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pods, e := kubeclient.ListPods(ctx, target, token, "jms-qa")
	require.NoError(t, e)
	require.Len(t, pods, 1)
	assert.Equal(t, []string{"main", "sidecar"}, pods[0].Containers)
	shell, e := kubeclient.OpenShell(ctx, target, token, kubeclient.Selection{Namespace: "jms-qa", Pod: "qa-shell", Container: "sidecar"}, 100, 30)
	require.NoError(t, e)
	defer shell.Close()
	_, e = shell.Write([]byte("printf '__JMS_K3S_NATIVE__\\n'; stty size; exit\n"))
	require.NoError(t, e)
	out, e := io.ReadAll(shell)
	require.NoError(t, e)
	assert.Contains(t, string(out), "__JMS_K3S_NATIVE__")
	assert.Contains(t, string(out), "30 100")
	assert.NotEmpty(t, shell.PodUID)
	require.NoError(t, shell.Wait())
	shell, e = kubeclient.OpenShell(ctx, target, token, kubeclient.Selection{Namespace: "jms-qa", Pod: "qa-shell", Container: "main"}, 80, 24)
	require.NoError(t, e)
	defer shell.Close()
	_, e = shell.Write([]byte("exit 9\n"))
	require.NoError(t, e)
	_, e = io.ReadAll(shell)
	var exit *kubeclient.ExitError
	require.ErrorAs(t, e, &exit)
	assert.Equal(t, 9, exit.Code)
	denied := target
	denied.Namespaces = []string{"jms-forbidden"}
	_, e = kubeclient.ListPods(ctx, denied, token, "jms-forbidden")
	var native *kubeclient.ClusterError
	require.ErrorAs(t, e, &native)
	assert.Equal(t, 403, native.Status)
	assert.NotContains(t, e.Error(), token)
	_, e = kubeclient.ListPods(ctx, target, token, "jms-forbidden")
	assert.ErrorIs(t, e, kubeclient.ErrScope)
	wrong := target
	wrong.ServerName = "wrong.invalid"
	_, e = kubeclient.ListPods(ctx, wrong, token, "jms-qa")
	assert.Error(t, e)
}
func TestRealK3sPinnedGatewayAndSPDYFallback(t *testing.T) {
	target, token := kubefixture.Load(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	address := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	loopback := postgresfixture.LoopbackForward(t, address)
	destination := "kubernetes.synthetic.invalid:" + strconv.Itoa(target.Port)
	g, e := sshgateway.Start("127.0.0.1:0", map[string]string{destination: loopback})
	require.NoError(t, e)
	defer g.Close()
	host, port, _ := net.SplitHostPort(g.Address())
	n, _ := strconv.Atoi(port)
	via := target
	via.Host = "kubernetes.synthetic.invalid"
	via.Gateways = []sshclient.Hop{{Target: sshclient.Target{Host: host, Port: n, Username: sshgateway.Username, HostKeyFingerprint: g.Fingerprint}, Credentials: sshclient.Credentials{Password: sshgateway.Password}}}
	_, e = kubeclient.ListPods(ctx, via, token, "jms-qa")
	require.NoError(t, e)
	shell, e := kubeclient.OpenShell(ctx, via, token, kubeclient.Selection{Namespace: "jms-qa", Pod: "qa-shell"}, 80, 24)
	require.NoError(t, e)
	_, e = shell.Write([]byte("echo gateway-proof; exit\n"))
	require.NoError(t, e)
	out, e := io.ReadAll(shell)
	require.NoError(t, e)
	assert.Contains(t, string(out), "gateway-proof")
	shell.Close()
	via.Gateways[0].Target.HostKeyFingerprint = "SHA256:" + strings.Repeat("A", 43)
	_, e = kubeclient.ListPods(ctx, via, token, "jms-qa")
	assert.Error(t, e)
	// Force only the pre-upgrade WebSocket request to fail; execute the real
	// subsequent SPDY stream against K3s through a verified local reverse proxy.
	u, _ := url.Parse("https://" + address)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM([]byte(target.RootCAPEM)))
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: target.ServerName}}
	defer tr.CloseIdleConnections()
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.Transport = tr
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/exec") {
			w.WriteHeader(400)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	defer s.Close()
	h, p, _ := net.SplitHostPort(strings.TrimPrefix(s.URL, "https://"))
	np, _ := strconv.Atoi(p)
	fallback := target
	fallback.Host = h
	fallback.Port = np
	fallback.ServerName = ""
	fallback.RootCAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}))
	shell, e = kubeclient.OpenShell(ctx, fallback, token, kubeclient.Selection{Namespace: "jms-qa", Pod: "qa-shell"}, 95, 31)
	require.NoError(t, e)
	defer shell.Close()
	_, e = shell.Write([]byte("echo spdy-proof; stty size; exit\n"))
	require.NoError(t, e)
	out, e = io.ReadAll(shell)
	require.NoError(t, e)
	assert.Contains(t, string(out), "spdy-proof")
	assert.Contains(t, string(out), "31 95")
}
