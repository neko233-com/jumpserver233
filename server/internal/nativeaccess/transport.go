// Package nativeaccess exposes the existing authenticated API and terminal
// broker to ordinary SSH/SFTP clients. It never opens a second authority path.
package nativeaccess

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

const apiOrigin = "http://native.ssh.invalid"

// handlerTransport runs real HTTP (including WebSocket hijacks and streaming
// bodies) over process-local pipes. No proxy, DNS, TCP API port or admin token
// is involved. The peer address is the original SSH client's address, so source
// restrictions, rate limits and login audits see the actual caller.
type handlerTransport struct {
	client      *http.Client
	server      *http.Server
	listener    *pipeListener
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	closed      bool
	peer        net.Addr
}
type pipeListener struct {
	incoming chan net.Conn
	done     chan struct{}
	once     sync.Once
}
type peerConn struct {
	net.Conn
	peer net.Addr
}

func (c peerConn) RemoteAddr() net.Addr { return c.peer }
func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.incoming:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *pipeListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *pipeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func newHandlerTransport(handler http.Handler, peer net.Addr) *handlerTransport {
	l := &pipeListener{incoming: make(chan net.Conn), done: make(chan struct{})}
	t := &handlerTransport{listener: l, connections: make(map[net.Conn]struct{}), peer: peer}
	t.server = &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	transport := &http.Transport{DisableCompression: true, MaxConnsPerHost: 16, MaxIdleConnsPerHost: 4,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "native.ssh.invalid:80" {
				return nil, errors.New("invalid internal authority")
			}
			local, remote := net.Pipe()
			t.mu.Lock()
			if t.closed {
				t.mu.Unlock()
				local.Close()
				remote.Close()
				return nil, net.ErrClosed
			}
			t.connections[local] = struct{}{}
			t.connections[remote] = struct{}{}
			t.mu.Unlock()
			select {
			case l.incoming <- peerConn{remote, peer}:
				return local, nil
			case <-ctx.Done():
				local.Close()
				remote.Close()
				return nil, ctx.Err()
			case <-l.done:
				local.Close()
				remote.Close()
				return nil, net.ErrClosed
			}
		}}
	t.client = &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	go func() { _ = t.server.Serve(l) }()
	return t
}
func (t *handlerTransport) Close() {
	t.mu.Lock()
	t.closed = true
	for c := range t.connections {
		_ = c.Close()
	}
	t.connections = nil
	t.mu.Unlock()
	t.client.CloseIdleConnections()
	_ = t.listener.Close()
	_ = t.server.Close()
}
