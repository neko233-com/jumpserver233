package cloudnotify

import (
	"context"
	"crypto/md5" // CMPP 2.0 mandates MD5 for its mutual connection authenticator.
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// CMPP 2.0 is carried over a certificate-verified TLS gateway. One authenticated
// connection carries one bounded UCS-2 message, without implicit retransmission.
func (c *Client) sendCMPP(ctx context.Context, cfg SMSConfig, secret, ca, to, message string, check func() error) Outcome {
	units := utf16.Encode([]rune(message))
	if len(units) == 0 || len(units) > 70 {
		return fail("invalid_payload")
	}
	for _, u := range units {
		if u >= 0xd800 && u <= 0xdfff {
			return fail("unsupported_destination")
		}
	}
	destination := strings.TrimPrefix(to, "+86")
	if !strings.HasPrefix(to, "+86") || len(destination) != 11 {
		return fail("unsupported_destination")
	}
	tc, e := TLSConfig(ca)
	if e != nil {
		return fail("invalid_configuration")
	}
	endpoint, _ := url.Parse(cfg.Endpoint)
	tc.ServerName = endpoint.Hostname()
	if guard(ctx, check) != nil {
		return Outcome{State: "suppressed", Code: "permission_changed"}
	}
	conn, e := c.DialTLS(ctx, endpoint.Host, tc)
	if e != nil {
		return Outcome{State: "retry", Code: "provider_unavailable"}
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline := c.Now().Add(15 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	stamp := c.Now().In(time.FixedZone("CMPP", 8*3600)).Format("0102150405")
	n, _ := strconv.ParseUint(stamp, 10, 32)
	authInput := append([]byte(cfg.AccessKeyID), make([]byte, 9)...)
	authInput = append(authInput, []byte(secret+stamp)...)
	authSource := md5.Sum(authInput)
	body := append([]byte(cfg.AccessKeyID), authSource[:]...)
	body = append(body, 0x20)
	body = binary.BigEndian.AppendUint32(body, uint32(n))
	if e = writeFrame(conn, 1, 1, body); e != nil {
		return Outcome{State: "retry", Code: "provider_unavailable"}
	}
	reply, e := readFrame(conn, 0x80000001, 1)
	if e != nil {
		return fail("provider_rejected")
	}
	if len(reply) != 18 || reply[0] != 0 || reply[17] != 0x20 {
		return fail("provider_rejected")
	}
	authReply := append([]byte{reply[0]}, authSource[:]...)
	authReply = append(authReply, secret...)
	want := md5.Sum(authReply)
	if subtle.ConstantTimeCompare(want[:], reply[1:17]) != 1 {
		return fail("provider_rejected")
	}
	body = make([]byte, 8)
	body = append(body, 1, 1, 0, 0)
	body = append(body, padded(cfg.ServiceID, 10)...)
	body = append(body, 2)
	body = append(body, padded("", 21)...)
	body = append(body, 0, 0, 8)
	body = append(body, []byte(cfg.AccessKeyID)...)
	body = append(body, []byte("01000000")...)
	body = append(body, make([]byte, 34)...)
	body = append(body, padded(cfg.Sender, 21)...)
	body = append(body, 1)
	body = append(body, padded(destination, 21)...)
	body = append(body, byte(len(units)*2))
	for _, u := range units {
		body = binary.BigEndian.AppendUint16(body, u)
	}
	body = append(body, make([]byte, 8)...)
	if guard(ctx, check) != nil {
		return Outcome{State: "suppressed", Code: "permission_changed"}
	}
	if e = writeFrame(conn, 4, 2, body); e != nil {
		return uncertain("receipt_unavailable")
	}
	reply, e = readFrame(conn, 0x80000004, 2)
	if e != nil || len(reply) != 9 {
		return uncertain("receipt_unavailable")
	}
	if reply[8] != 0 {
		return fail("provider_rejected")
	}
	if binary.BigEndian.Uint64(reply[:8]) == 0 {
		return uncertain("receipt_unavailable")
	}
	return accepted(hex.EncodeToString(reply[:8]))
}
func padded(v string, n int) []byte { b := make([]byte, n); copy(b, v); return b }
func writeFrame(w io.Writer, command, sequence uint32, body []byte) error {
	raw := make([]byte, 0, 12+len(body))
	raw = binary.BigEndian.AppendUint32(raw, uint32(12+len(body)))
	raw = binary.BigEndian.AppendUint32(raw, command)
	raw = binary.BigEndian.AppendUint32(raw, sequence)
	raw = append(raw, body...)
	for len(raw) > 0 {
		n, e := w.Write(raw)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		raw = raw[n:]
	}
	return nil
}
func readFrame(r net.Conn, command, sequence uint32) ([]byte, error) {
	var h [12]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return nil, e
	}
	n := binary.BigEndian.Uint32(h[:4])
	if n < 12 || n > 4096 || binary.BigEndian.Uint32(h[4:8]) != command || binary.BigEndian.Uint32(h[8:]) != sequence {
		return nil, ErrConfig
	}
	b := make([]byte, n-12)
	_, e := io.ReadFull(r, b)
	return b, e
}
