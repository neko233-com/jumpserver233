package sshclient

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	xssh "golang.org/x/crypto/ssh"
)

// DialTunnel opens a non-SSH target through pinned SSH gateways. Closing the
// returned connection closes every hop, without a local listening port.
func DialTunnel(ctx context.Context, hops []Hop, address string, timeout time.Duration) (net.Conn, error) {
	if len(hops) == 0 {
		return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", address)
	}
	if len(hops) > MaxGatewayHops {
		return nil, &GatewayError{cause: errors.New("gateway route exceeds hop limit")}
	}
	last := hops[len(hops)-1]
	target := last.Target
	target.Gateways = append([]Hop(nil), hops[:len(hops)-1]...)
	client, _, e := dialRoute(ctx, target, last.Credentials, timeout)
	if e != nil {
		return nil, e
	}
	raw, e := client.DialContext(ctx, "tcp", address)
	if e != nil {
		client.Close()
		return nil, &GatewayError{cause: e}
	}
	return &tunnelConnection{Conn: raw, client: client}, nil
}

type tunnelConnection struct {
	net.Conn
	client *xssh.Client
	once   sync.Once
	mu     sync.Mutex
	timer  *time.Timer
	closed bool
}

func (c *tunnelConnection) Close() error {
	var e error
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		if c.timer != nil {
			c.timer.Stop()
		}
		c.mu.Unlock()
		e = c.Conn.Close()
		_ = c.client.Close()
	})
	return e
}

// SSH forwarded channels do not implement deadlines. A deadline cancels this
// private tunnel instead; clearing it stops the timer before connection reuse.
func (c *tunnelConnection) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if !t.IsZero() {
		c.timer = time.AfterFunc(time.Until(t), func() { _ = c.Close() })
	}
	return nil
}
func (c *tunnelConnection) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *tunnelConnection) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }
