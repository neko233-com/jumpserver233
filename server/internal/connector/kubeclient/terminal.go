package kubeclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/go-logr/logr"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/transport/spdy"
	"k8s.io/klog/v2"
)

type ExitError struct{ Code int }

func (e *ExitError) Error() string {
	return "container process exited with code " + strconv.Itoa(e.Code)
}

type sizeQueue struct {
	ctx    context.Context
	values chan remotecommand.TerminalSize
}

func (q *sizeQueue) Next() *remotecommand.TerminalSize {
	select {
	case v := <-q.values:
		return &v
	case <-q.ctx.Done():
		return nil
	}
}

type Shell struct {
	Selection   Selection
	PodUID      string
	socket      *websocket.Conn
	ctx         context.Context
	cancel      context.CancelFunc
	output      *io.PipeReader
	outputWrite *io.PipeWriter
	input       *io.PipeWriter
	inputRead   *io.PipeReader
	sizes       *sizeQueue
	done        chan struct{}
	once        sync.Once
	mu          sync.Mutex
	waitErr     error
}

func execURL(t Target, v Selection) string {
	q := url.Values{"stdin": {"true"}, "stdout": {"true"}, "stderr": {"false"}, "tty": {"true"}, "container": {v.Container}, "command": t.Shell}
	return endpoint(t, "/api/v1/namespaces/"+v.Namespace+"/pods/"+v.Pod+"/exec") + "?" + q.Encode()
}
func OpenShell(ctx context.Context, t Target, token string, v Selection, cols, rows int) (*Shell, error) {
	if cols < 2 || cols > 500 || rows < 2 || rows > 500 || !ValidToken(token) {
		return nil, ErrInvalid
	}
	settings, e := Normalize(t.Settings)
	if e != nil {
		return nil, e
	}
	t.Settings = settings
	v, p, e := resolve(ctx, t, token, v)
	if e != nil {
		return nil, e
	}
	tr, e := transport(t)
	if e != nil {
		return nil, e
	}
	endpoint := execURL(t, v)
	conn, response, e := websocket.Dial(ctx, endpoint, &websocket.DialOptions{HTTPClient: &http.Client{Transport: tr, CheckRedirect: noRedirect}, HTTPHeader: http.Header{"Authorization": {"Bearer " + token}}, Subprotocols: []string{"v5.channel.k8s.io"}, CompressionMode: websocket.CompressionDisabled})
	if response != nil && response.Body != nil {
		response.Body.Close()
	}
	if e != nil {
		tr.CloseIdleConnections()
		if response != nil && (response.StatusCode == 400 || response.StatusCode == 404 || response.StatusCode == 405 || response.StatusCode == 426) {
			return openSPDY(ctx, t, token, v, p.UID, cols, rows)
		}
		if response != nil {
			return nil, &ClusterError{response.StatusCode}
		}
		return nil, ErrUnavailable
	}
	if conn.Subprotocol() != "v5.channel.k8s.io" {
		conn.CloseNow()
		tr.CloseIdleConnections()
		return nil, ErrUnavailable
	}
	life, cancel := context.WithCancel(context.Background())
	reader, writer := io.Pipe()
	s := &Shell{Selection: v, PodUID: p.UID, socket: conn, ctx: life, cancel: cancel, output: reader, outputWrite: writer, done: make(chan struct{})}
	conn.SetReadLimit(1024 * 1024)
	go func() { defer tr.CloseIdleConnections(); s.finish(s.readFrames()) }()
	if e = s.Resize(cols, rows); e != nil {
		s.Close()
		return nil, ErrUnavailable
	}
	return s, nil
}
func (s *Shell) readFrames() error {
	for {
		kind, raw, e := s.socket.Read(s.ctx)
		if e != nil {
			if websocket.CloseStatus(e) == websocket.StatusNormalClosure {
				return nil
			}
			return ErrUnavailable
		}
		if kind != websocket.MessageBinary || len(raw) < 1 {
			return ErrUnavailable
		}
		switch raw[0] {
		case 1, 2:
			if _, e = s.outputWrite.Write(raw[1:]); e != nil {
				return e
			}
		case 3:
			var status struct {
				Status  string `json:"status"`
				Reason  string `json:"reason"`
				Details struct {
					Causes []struct {
						Reason  string `json:"reason"`
						Message string `json:"message"`
					} `json:"causes"`
				} `json:"details"`
			}
			if len(raw) > 65536 || json.Unmarshal(raw[1:], &status) != nil {
				return ErrUnavailable
			}
			if status.Status == "Success" {
				return nil
			}
			if status.Reason == "NonZeroExitCode" {
				for _, c := range status.Details.Causes {
					if c.Reason == "ExitCode" {
						n, e := strconv.Atoi(c.Message)
						if e == nil && n > 0 && n <= 255 {
							return &ExitError{n}
						}
					}
				}
			}
			return ErrUnavailable
		case 255:
			if len(raw) != 2 || raw[1] > 4 {
				return ErrUnavailable
			}
		default:
			return ErrUnavailable
		}
	}
}
func (s *Shell) finish(e error) {
	s.mu.Lock()
	s.waitErr = e
	s.mu.Unlock()
	s.outputWrite.CloseWithError(e)
	close(s.done)
}
func (s *Shell) Read(p []byte) (int, error) { return s.output.Read(p) }
func (s *Shell) Write(p []byte) (int, error) {
	if len(p) > 65536 {
		return 0, ErrInvalid
	}
	if s.socket == nil {
		return s.input.Write(p)
	}
	if e := s.send(append([]byte{0}, p...)); e != nil {
		return 0, e
	}
	return len(p), nil
}
func (s *Shell) send(p []byte) error {
	ctx, stop := context.WithTimeout(s.ctx, 5*time.Second)
	defer stop()
	return s.socket.Write(ctx, websocket.MessageBinary, p)
}
func (s *Shell) Resize(cols, rows int) error {
	if cols < 2 || cols > 500 || rows < 2 || rows > 500 {
		return ErrInvalid
	}
	if s.socket == nil {
		v := remotecommand.TerminalSize{Width: uint16(cols), Height: uint16(rows)}
		select {
		case s.sizes.values <- v:
		default:
			select {
			case <-s.sizes.values:
			default:
			}
			select {
			case s.sizes.values <- v:
			default:
			}
		}
		return nil
	}
	raw, _ := json.Marshal(struct {
		Width  int
		Height int
	}{cols, rows})
	return s.send(append([]byte{4}, raw...))
}
func (s *Shell) Wait() error { <-s.done; s.mu.Lock(); defer s.mu.Unlock(); return s.waitErr }
func (s *Shell) Close() error {
	s.once.Do(func() {
		s.cancel()
		if s.socket != nil {
			s.socket.CloseNow()
		}
		if s.input != nil {
			s.input.Close()
		}
		if s.inputRead != nil {
			s.inputRead.Close()
		}
		s.output.Close()
		s.outputWrite.Close()
	})
	return nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func openSPDY(ctx context.Context, t Target, token string, v Selection, uid string, cols, rows int) (*Shell, error) {
	address := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	ready := make(chan struct{})
	var once sync.Once
	cfg := &rest.Config{Host: "https://" + address, BearerToken: token, Proxy: func(*http.Request) (*url.URL, error) { return nil, nil }, TLSClientConfig: rest.TLSClientConfig{ServerName: t.ServerName, CAData: []byte(t.RootCAPEM)}, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != address {
			return nil, ErrScope
		}
		return sshclient.DialTunnel(ctx, t.Gateways, address, 5*time.Second)
	}}
	cfg.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
		return roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host != address || r.URL.Scheme != "https" {
				return nil, ErrScope
			}
			response, e := next.RoundTrip(r)
			if e == nil && response.StatusCode == 101 {
				once.Do(func() { close(ready) })
			}
			return response, e
		})
	}
	wrapper, upgrader, e := spdy.RoundTripperFor(cfg)
	if e != nil {
		return nil, ErrUnavailable
	}
	u, _ := url.Parse(execURL(t, v))
	executor, e := remotecommand.NewSPDYExecutorRejectRedirects(wrapper, upgrader, http.MethodPost, u)
	if e != nil {
		return nil, ErrUnavailable
	}
	life, cancel := context.WithCancel(klog.NewContext(context.Background(), logr.Discard()))
	out, writer := io.Pipe()
	input, stdin := io.Pipe()
	s := &Shell{Selection: v, PodUID: uid, ctx: life, cancel: cancel, output: out, outputWrite: writer, input: stdin, inputRead: input, done: make(chan struct{})}
	s.sizes = &sizeQueue{life, make(chan remotecommand.TerminalSize, 1)}
	s.Resize(cols, rows)
	stop := context.AfterFunc(ctx, cancel)
	go func() {
		e := executor.StreamWithContext(life, remotecommand.StreamOptions{Stdin: input, Stdout: writer, Tty: true, TerminalSizeQueue: s.sizes})
		if e != nil {
			var status interface{ ExitStatus() int }
			if errors.As(e, &status) && status.ExitStatus() > 0 && status.ExitStatus() <= 255 {
				e = &ExitError{status.ExitStatus()}
			} else {
				e = ErrUnavailable
			}
		}
		s.finish(e)
	}()
	select {
	case <-ready:
		if !stop() {
			s.Close()
			return nil, ErrUnavailable
		}
		return s, nil
	case <-s.done:
		stop()
		s.Close()
		return nil, ErrUnavailable
	case <-ctx.Done():
		stop()
		s.Close()
		return nil, ErrUnavailable
	}
}

var _ io.ReadWriteCloser = (*Shell)(nil)
