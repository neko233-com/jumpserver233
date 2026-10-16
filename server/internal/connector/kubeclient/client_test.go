package kubeclient

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func tlsTarget(t *testing.T, s *httptest.Server) Target {
	t.Helper()
	host, port, e := net.SplitHostPort(strings.TrimPrefix(s.URL, "https://"))
	require.NoError(t, e)
	n, _ := strconv.Atoi(port)
	return Target{Host: host, Port: n, Settings: Settings{Namespaces: []string{"qa"}, Shell: []string{"/bin/sh"}, RootCAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}))}}
}
func TestConfigurationScopeDeepCopiesAndNoAmbientCredentials(t *testing.T) {
	in := Settings{Namespaces: []string{"z", "a"}, Shell: []string{"/bin/sh"}}
	out, e := Normalize(in)
	require.NoError(t, e)
	out.Namespaces[0] = "mutated"
	assert.Equal(t, "z", in.Namespaces[0])
	out.Shell[0] = "mutated"
	assert.Equal(t, "/bin/sh", in.Shell[0])
	for _, s := range []Settings{{Namespaces: []string{"../outside"}}, {Namespaces: []string{"same", "same"}}, {RootCAPEM: "not a CA"}, {Shell: []string{"/bin/sh\x00"}}, {ServerName: "attacker/path"}} {
		_, e = Normalize(s)
		assert.ErrorIs(t, e, ErrInvalid)
	}
	assert.ErrorIs(t, ValidateSelection(Settings{Namespaces: []string{"qa"}}, Selection{Namespace: "outside", Pod: "pod"}), ErrScope)
	assert.ErrorIs(t, ValidateSelection(Settings{Namespaces: []string{"qa"}}, Selection{Namespace: "qa", Pod: "../pod"}), ErrInvalid)
}
func TestTLSNamespacesBoundedMetadataNativeErrorsAndRedirectIsolation(t *testing.T) {
	var redirected atomic.Int32
	outside := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer outside.Close()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer synthetic-kube-token", r.Header.Get("Authorization"))
		switch r.URL.Query().Get("continue") {
		case "redirect":
			http.Redirect(w, r, outside.URL, 302)
		case "huge":
			w.Write([]byte(strings.Repeat("x", 4*1024*1024+1)))
		default:
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"items":[{"metadata":{"name":"pod","namespace":"qa","uid":"uid"},"spec":{"containers":[{"name":"running"},{"name":"stopped"}]},"status":{"phase":"Running","containerStatuses":[{"name":"running","state":{"running":{}}}]}}]}`)
		}
	}))
	defer s.Close()
	target := tlsTarget(t, s)
	pods, e := ListPods(context.Background(), target, "synthetic-kube-token", "qa")
	require.NoError(t, e)
	require.Len(t, pods, 1)
	assert.Equal(t, []string{"running"}, pods[0].Containers)
	_, e = ListPods(context.Background(), target, "synthetic-kube-token", "outside")
	assert.ErrorIs(t, e, ErrScope)
	wrong := target
	wrong.ServerName = "wrong.synthetic.invalid"
	_, e = ListPods(context.Background(), wrong, "synthetic-kube-token", "qa")
	assert.ErrorIs(t, e, ErrUnavailable)
	for _, v := range []string{"redirect", "huge"} {
		e = get(context.Background(), target, "synthetic-kube-token", "/api/v1/namespaces/qa/pods", map[string][]string{"continue": {v}}, &struct{}{})
		assert.Error(t, e)
		assert.NotContains(t, e.Error(), "synthetic-kube-token")
	}
	assert.Zero(t, redirected.Load())
}
func TestWebSocketV5ResizeStreamsExitStatusAndClose(t *testing.T) {
	frames := make(chan []byte, 4)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/exec") {
			io.WriteString(w, `{"metadata":{"name":"pod","namespace":"qa","uid":"unit-pod-uid"},"spec":{"containers":[{"name":"main"}]},"status":{"phase":"Running","containerStatuses":[{"name":"main","state":{"running":{}}}]}}`)
			return
		}
		assert.Equal(t, []string{"/bin/sh"}, r.URL.Query()["command"])
		assert.Equal(t, "main", r.URL.Query().Get("container"))
		conn, e := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"v5.channel.k8s.io"}})
		if !assert.NoError(t, e) {
			return
		}
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		for i := 0; i < 2; i++ {
			_, raw, e := conn.Read(ctx)
			if e != nil {
				return
			}
			frames <- raw
		}
		conn.Write(ctx, websocket.MessageBinary, append([]byte{1}, []byte("unit-native-output")...))
		status := []byte(`{"status":"Failure","reason":"NonZeroExitCode","message":"private error body","details":{"causes":[{"reason":"ExitCode","message":"7"}]}}`)
		conn.Write(ctx, websocket.MessageBinary, append([]byte{3}, status...))
	}))
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	shell, e := OpenShell(ctx, tlsTarget(t, s), "synthetic-kube-token", Selection{Namespace: "qa", Pod: "pod"}, 90, 30)
	require.NoError(t, e)
	defer shell.Close()
	assert.Equal(t, "unit-pod-uid", shell.PodUID)
	_, e = shell.Write([]byte("echo proof\n"))
	require.NoError(t, e)
	raw, e := io.ReadAll(shell)
	assert.Equal(t, "unit-native-output", string(raw))
	var exit *ExitError
	require.ErrorAs(t, e, &exit)
	assert.Equal(t, 7, exit.Code)
	assert.NotContains(t, e.Error(), "private")
	first := <-frames
	require.Equal(t, byte(4), first[0])
	var size struct{ Width, Height int }
	require.NoError(t, json.Unmarshal(first[1:], &size))
	assert.Equal(t, 90, size.Width)
	second := <-frames
	assert.Equal(t, byte(0), second[0])
	assert.Equal(t, "echo proof\n", string(second[1:]))
	assert.ErrorIs(t, shell.Resize(1, 20), ErrInvalid)
	require.NoError(t, shell.Close())
	require.NoError(t, shell.Close())
}
