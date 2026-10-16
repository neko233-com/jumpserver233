package mongodbclient

import (
	"context"
	"encoding/binary"
	"github.com/neko233-com/jumpserver233/server/internal/connector/databasewire"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"io"
	"net"
	"strconv"
	"sync/atomic"
)

const MaxWireBytes = 4 * sqlclient.MaxResultBytes

type wireBudget struct {
	remaining atomic.Int64
	exceeded  atomic.Bool
}
type dialer struct {
	target sqlclient.Target
	budget *wireBudget
}

func (d *dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" || address != net.JoinHostPort(d.target.Host, strconv.Itoa(d.target.Port)) {
		return nil, sqlclient.ErrDenied
	}
	conn, e := databasewire.Dial(ctx, d.target)
	if e != nil {
		return nil, e
	}
	return &messageConnection{Conn: conn, budget: d.budget}, nil
}

// The driver reads four bytes and allocates the declared message size. Buffer
// and validate the complete header before exposing those four bytes. TLS is
// established inside the pinned dialer so this guard sees MongoDB frames.
type messageConnection struct {
	net.Conn
	budget *wireBudget
	header [16]byte
	offset int
	body   int
	ready  bool
}

func (c *messageConnection) limited(p []byte) (int, error) {
	left := c.budget.remaining.Load()
	if left <= 0 {
		c.budget.exceeded.Store(true)
		c.Conn.Close()
		return 0, sqlclient.ErrResultLimit
	}
	if int64(len(p)) > left {
		p = p[:left]
	}
	n, e := c.Conn.Read(p)
	c.budget.remaining.Add(-int64(n))
	return n, e
}
func (c *messageConnection) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if !c.ready {
		read := 0
		for read < len(c.header) {
			n, e := c.limited(c.header[read:])
			read += n
			if e != nil {
				return 0, e
			}
			if n == 0 {
				return 0, io.ErrNoProgress
			}
		}
		size := int64(binary.LittleEndian.Uint32(c.header[:4]))
		if size < 16 {
			return 0, sqlclient.ErrUnavailable
		}
		if size > MaxWireBytes || size-16 > c.budget.remaining.Load() {
			c.budget.exceeded.Store(true)
			c.Conn.Close()
			return 0, sqlclient.ErrResultLimit
		}
		if binary.LittleEndian.Uint32(c.header[12:16]) == 2012 {
			c.Conn.Close()
			return 0, sqlclient.ErrUnavailable
		}
		c.offset = 0
		c.body = int(size) - 16
		c.ready = true
	}
	if c.offset < 16 {
		n := copy(p, c.header[c.offset:])
		c.offset += n
		if c.offset == 16 && c.body == 0 {
			c.ready = false
		}
		return n, nil
	}
	if len(p) > c.body {
		p = p[:c.body]
	}
	n, e := c.limited(p)
	c.body -= n
	if c.body == 0 {
		c.ready = false
	}
	return n, e
}
