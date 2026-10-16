package rdpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

func protocol(s Settings) uint32 {
	if s.Security == "tls" {
		return 1
	}
	return 2
}

// The first server packet is checked before the protocol stack can send any
// credential. A peer cannot downgrade NLA to TLS or either mode to legacy RDP.
type negotiatedConn struct {
	net.Conn
	mu        sync.Mutex
	first     bool
	expected  uint32
	initial   *bytes.Reader
	started   chan struct{}
	startOnce sync.Once
}

func (c *negotiatedConn) Write(p []byte) (int, error) {
	if c.started != nil {
		c.startOnce.Do(func() { close(c.started) })
	}
	return c.Conn.Write(p)
}
func (c *negotiatedConn) Read(p []byte) (int, error) {
	if c.started != nil {
		<-c.started
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.first {
		c.first = true
		packet, e := readConfirm(c.Conn, c.expected)
		if e != nil {
			return 0, e
		}
		c.initial = bytes.NewReader(packet)
	}
	if c.initial != nil && c.initial.Len() > 0 {
		return c.initial.Read(p)
	}
	return c.Conn.Read(p)
}
func readConfirm(r io.Reader, wanted uint32) ([]byte, error) {
	header := make([]byte, 4)
	if _, e := io.ReadFull(r, header); e != nil {
		return nil, e
	}
	n := int(binary.BigEndian.Uint16(header[2:]))
	if header[0] != 3 || header[1] != 0 || n < 19 || n > 256 {
		return nil, ErrProtocol
	}
	packet := make([]byte, n)
	copy(packet, header)
	if _, e := io.ReadFull(r, packet[4:]); e != nil {
		return nil, e
	}
	if packet[5] != 0xd0 || packet[11] != 2 || binary.LittleEndian.Uint16(packet[13:15]) != 8 || binary.LittleEndian.Uint32(packet[15:19]) != wanted {
		return nil, ErrProtocol
	}
	return packet, nil
}
func dial(ctx context.Context, t Target) (net.Conn, error) {
	if t.Host == "" || t.Port < 1 || t.Port > 65535 {
		return nil, ErrInvalid
	}
	c, e := sshclient.DialTunnel(ctx, t.Gateways, net.JoinHostPort(t.Host, strconv.Itoa(t.Port)), 5*time.Second)
	if e != nil {
		return nil, ErrUnavailable
	}
	return c, nil
}

// Probe verifies the negotiated security mode and TLS certificate without
// submitting credentials or opening a user desktop.
func Probe(ctx context.Context, t Target) error {
	settings, e := Normalize(t.Settings)
	if e != nil {
		return e
	}
	t.Settings = settings
	conn, e := dial(ctx, t)
	if e != nil {
		return e
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	packet := []byte{3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(packet[15:], protocol(settings))
	if _, e = conn.Write(packet); e != nil {
		return ErrUnavailable
	}
	if _, e = readConfirm(conn, protocol(settings)); e != nil {
		return ErrUnavailable
	}
	cfg, e := tlsConfig(t)
	if e != nil {
		return e
	}
	secured := tls.Client(conn, cfg)
	if e = secured.HandshakeContext(ctx); e != nil {
		return ErrUnavailable
	}
	return nil
}
