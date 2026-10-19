package sshclient

import (
	"context"
	"errors"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
	"net"
	"strconv"
	"sync"
	"time"

	xssh "golang.org/x/crypto/ssh"
)

const MaxGatewayHops = 3

// Hop contains vault-resolved infrastructure credentials, never API input.
type Hop struct {
	Target      Target      `json:"-"`
	Credentials Credentials `json:"-"`
}
type GatewayError struct{ cause error }

func (e *GatewayError) Error() string { return "SSH gateway connection failed" }
func (e *GatewayError) Unwrap() error { return e.cause }

type routeResources struct {
	mu      sync.Mutex
	closed  bool
	raw     []net.Conn
	ssh     []xssh.Conn
	release func()
}

func (r *routeResources) addRaw(c net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		_ = c.Close()
		return false
	}
	r.raw = append(r.raw, c)
	return true
}
func (r *routeResources) addSSH(c xssh.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		_ = c.Close()
		return false
	}
	r.ssh = append(r.ssh, c)
	return true
}
func (r *routeResources) close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	raw := append([]net.Conn{}, r.raw...)
	conns := append([]xssh.Conn{}, r.ssh...)
	r.mu.Unlock()
	for _, c := range raw {
		_ = c.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
	if r.release != nil {
		r.release()
	}
}

type routeConn struct {
	xssh.Conn
	resources *routeResources
}

func (c *routeConn) Close() error { c.resources.close(); return nil }
func (c *routeConn) Wait() error  { e := c.Conn.Wait(); c.resources.close(); return e }

// Every hop uses an independent pinned handshake. Only direct-tcpip channels
// are opened on gateways; no shell or agent forwarding is requested there.
func dialRoute(ctx context.Context, target Target, credentials Credentials, timeout time.Duration) (*xssh.Client, time.Duration, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if len(target.Gateways) > MaxGatewayHops {
		return nil, 0, fmt.Errorf("SSH gateway route exceeds limit")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	admission := target.Admission
	if admission == nil {
		admission = workgate.FromContext(ctx)
	}
	ctx, release, e := admission.Enter(ctx, "ssh_routes")
	if e != nil {
		return nil, 0, e
	}
	resources := &routeResources{release: release}
	stop := context.AfterFunc(ctx, resources.close)
	success := false
	defer func() {
		stop()
		if !success {
			resources.close()
		}
	}()
	hops := append([]Hop{}, target.Gateways...)
	target.Gateways = nil
	hops = append(hops, Hop{Target: target, Credentials: credentials})
	started := time.Now()
	var parent *xssh.Client
	for i, hop := range hops {
		gateway := i < len(hops)-1
		fail := func(e error) (*xssh.Client, time.Duration, error) {
			if ctx.Err() != nil {
				e = ctx.Err()
			}
			if gateway {
				return nil, 0, &GatewayError{cause: e}
			}
			return nil, 0, e
		}
		if len(hop.Target.Gateways) > 0 {
			return fail(errors.New("nested SSH gateway route"))
		}
		config, e := clientConfig(hop.Target, hop.Credentials)
		if e != nil {
			return fail(e)
		}
		address := net.JoinHostPort(hop.Target.Host, strconv.Itoa(hop.Target.Port))
		var raw net.Conn
		if parent == nil {
			raw, e = (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", address)
		} else {
			raw, e = parent.DialContext(ctx, "tcp", address)
		}
		if e != nil {
			return fail(fmt.Errorf("connect to SSH host: %w", e))
		}
		if !resources.addRaw(raw) {
			return fail(ctx.Err())
		}
		conn, channels, requests, e := xssh.NewClientConn(raw, address, config)
		if e != nil {
			return fail(fmt.Errorf("SSH handshake failed: %w", e))
		}
		if !resources.addSSH(conn) {
			return fail(ctx.Err())
		}
		if gateway {
			parent = xssh.NewClient(conn, channels, requests)
			continue
		}
		if !stop() {
			resources.close()
			return nil, 0, ctx.Err()
		}
		success = true
		return xssh.NewClient(&routeConn{Conn: conn, resources: resources}, channels, requests), time.Since(started), nil
	}
	return nil, 0, errors.New("empty SSH route")
}
