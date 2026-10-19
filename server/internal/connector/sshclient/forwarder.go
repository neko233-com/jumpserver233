package sshclient

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	xssh "golang.org/x/crypto/ssh"
)

// Forwarder reuses one authenticated pinned gateway route for a bounded scan.
// Closing an individual channel never closes unrelated channels in the scan.
type Forwarder struct {
	client *xssh.Client
	stop   func() bool
}

func OpenForwarder(ctx context.Context, target Target, credentials Credentials, timeout time.Duration) (*Forwarder, error) {
	client, _, e := dialRoute(ctx, target, credentials, timeout)
	if e != nil {
		return nil, e
	}
	f := &Forwarder{client: client}
	f.stop = context.AfterFunc(ctx, func() { _ = client.Close() })
	return f, nil
}
func (f *Forwarder) Close() error { f.stop(); return f.client.Close() }
func (f *Forwarder) Dial(ctx context.Context, address string) (net.Conn, error) {
	raw, e := f.client.DialContext(ctx, "tcp", address)
	if e != nil {
		var open *xssh.OpenChannelError
		if errors.As(e, &open) && open.Reason == xssh.ConnectionFailed {
			return nil, e
		}
		return nil, &GatewayError{cause: e}
	}
	c := &forwardChannel{Conn: raw}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	c.mu.Lock()
	if c.closed {
		stop()
	} else {
		c.stop = stop
	}
	c.mu.Unlock()
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	return c, nil
}

type forwardChannel struct {
	net.Conn
	once   sync.Once
	mu     sync.Mutex
	timer  *time.Timer
	stop   func() bool
	closed bool
}

func (c *forwardChannel) Close() error {
	var e error
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		if c.timer != nil {
			c.timer.Stop()
		}
		stop := c.stop
		c.mu.Unlock()
		if stop != nil {
			stop()
		}
		e = c.Conn.Close()
	})
	return e
}
func (c *forwardChannel) SetDeadline(at time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if !at.IsZero() {
		c.timer = time.AfterFunc(time.Until(at), func() { _ = c.Close() })
	}
	return nil
}
func (c *forwardChannel) SetReadDeadline(at time.Time) error  { return c.SetDeadline(at) }
func (c *forwardChannel) SetWriteDeadline(at time.Time) error { return c.SetDeadline(at) }
