package telnetclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type memoryConn struct {
	reader *bytes.Reader
	writes bytes.Buffer
}

func (c *memoryConn) Read(p []byte) (int, error)       { return c.reader.Read(p) }
func (c *memoryConn) Write(p []byte) (int, error)      { return c.writes.Write(p) }
func (c *memoryConn) Close() error                     { return nil }
func (c *memoryConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *memoryConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *memoryConn) SetDeadline(time.Time) error      { return nil }
func (c *memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memoryConn) SetWriteDeadline(time.Time) error { return nil }

func TestOptionsNVTBinaryWindowTerminalTypeAndBounds(t *testing.T) {
	data := []byte{iac, will, 1, iac, will, 1, iac, do, 31, iac, do, 31, iac, do, 24, iac, sb, 24, 1, iac, se, iac, will, 99, iac, do, 99}
	data = append(data, []byte("one\r\x00two\r\n")...)
	data = append(data, iac, iac)
	c := &memoryConn{reader: bytes.NewReader(data)}
	s := &Shell{conn: c, reader: bufio.NewReader(c), cols: 255, rows: 24}
	p := make([]byte, 256)
	n, e := s.readNVT(p)
	require.NoError(t, e)
	assert.Equal(t, append([]byte("one\rtwo\r\n"), iac), p[:n])
	_, e = s.readNVT(p)
	require.ErrorIs(t, e, io.EOF)
	assert.Equal(t, 1, bytes.Count(c.writes.Bytes(), []byte{iac, do, 1}))
	assert.Equal(t, 1, bytes.Count(c.writes.Bytes(), []byte{iac, will, 31}))
	assert.Contains(t, string(c.writes.Bytes()), string([]byte{iac, sb, 31, 0, 255, 255, 0, 24, iac, se}))
	assert.Contains(t, string(c.writes.Bytes()), "xterm-256color")
	assert.Contains(t, string(c.writes.Bytes()), string([]byte{iac, dont, 99}))
	assert.Contains(t, string(c.writes.Bytes()), string([]byte{iac, wont, 99}))
	require.NoError(t, s.Resize(100, 40))
	assert.ErrorIs(t, s.Resize(501, 40), ErrInvalid)
	c.writes.Reset()
	_, e = s.Write([]byte("a\rb\nc\r\n"))
	require.NoError(t, e)
	assert.Equal(t, "a\r\nb\r\nc\r\n", c.writes.String())
	s.local[0] = true
	c.writes.Reset()
	_, e = s.Write([]byte{'\r', 0, 255})
	require.NoError(t, e)
	assert.Equal(t, []byte{'\r', 0, 255, 255}, c.writes.Bytes())
	assert.Error(t, func() error { _, e := s.Write(make([]byte, 65537)); return e }())
	for _, bad := range [][]byte{append([]byte{iac, sb, 24}, bytes.Repeat([]byte{'x'}, 1025)...), bytes.Repeat([]byte{iac, 241}, 1025)} {
		c.reader = bytes.NewReader(bad)
		s.reader = bufio.NewReader(c)
		_, e = s.readNVT(p)
		assert.ErrorIs(t, e, ErrProtocol)
	}
}

func TestSecretFilterAllBoundariesAndPrefixOverlap(t *testing.T) {
	for _, secret := range []string{"synthetic-password-233", "ababac", "aaaa", "密码🔐"} {
		text := "prefix " + secret + " suffix aba " + secret + " done $ "
		for split := 0; split <= len(text); split++ {
			s := newSecretFilter(secret)
			out := append(s.filter([]byte(text[:split]), false), s.filter([]byte(text[split:]), true)...)
			assert.Equal(t, strings.ReplaceAll(text, secret, "[redacted]"), string(out))
		}
	}
}

func TestSettingsRejectInvalidPromptsTransportAndCredentials(t *testing.T) {
	s, e := Normalize(Settings{})
	require.NoError(t, e)
	assert.Equal(t, "verify-full", s.TLSMode)
	for _, bad := range []Settings{{TLSMode: "insecure"}, {SuccessPrompt: ".*"}, {LoginPrompt: "["}, {PasswordPrompt: strings.Repeat("x", 513)}, {ServerName: "bad/name"}, {RootCAPEM: "not a certificate"}, {TLSMode: "disable", ServerName: "name"}} {
		_, e := Normalize(bad)
		assert.ErrorIs(t, e, ErrInvalid)
	}
	for _, bad := range []string{"", "a\nb", "a\rb", "a\x00b", strings.Repeat("x", 4097)} {
		assert.False(t, ValidCredential(bad))
	}
}

func testServer(t *testing.T, secured bool, handler func(net.Conn)) Target {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, e)
	settings := Settings{TLSMode: "disable"}
	if secured {
		h := httptest.NewTLSServer(http.NotFoundHandler())
		config := h.TLS.Clone()
		h.Close()
		cert, e := x509.ParseCertificate(config.Certificates[0].Certificate[0])
		require.NoError(t, e)
		settings = Settings{TLSMode: "verify-full", RootCAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))}
		listener = tls.NewListener(listener, config)
	}
	var mu sync.Mutex
	var conns []net.Conn
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				handler(c)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	n, _ := net.LookupPort("tcp", port)
	return Target{Host: host, Port: n, Settings: settings}
}

// Consume client option replies while reading NVT login lines.
func testLine(r *bufio.Reader) (string, error) {
	var line []byte
	for {
		b, e := r.ReadByte()
		if e != nil {
			return "", e
		}
		if b == iac {
			command, e := r.ReadByte()
			if e != nil {
				return "", e
			}
			if command == do || command == dont || command == will || command == wont {
				if _, e = r.ReadByte(); e != nil {
					return "", e
				}
				continue
			}
			if command == sb {
				for {
					v, e := r.ReadByte()
					if e != nil {
						return "", e
					}
					if v == iac {
						v, e = r.ReadByte()
						if e != nil {
							return "", e
						}
						if v == se {
							break
						}
					}
				}
				continue
			}
			if command != iac {
				continue
			}
		}
		if b == '\r' || b == '\n' {
			if len(line) > 0 {
				return string(line), nil
			}
			continue
		}
		if b != 0 {
			line = append(line, b)
		}
	}
}

func TestVerifiedTLSLoginRedactionAndIndependentLifetime(t *testing.T) {
	const secret = "synthetic-test-telnet-password"
	target := testServer(t, true, func(c net.Conn) {
		r := bufio.NewReader(c)
		_, _ = c.Write([]byte{iac, will, 1, iac, do, 31, iac, do, 24, iac, sb, 24, 1, iac, se})
		_, _ = io.WriteString(c, "login: ")
		if user, _ := testLine(r); user != "qa" {
			return
		}
		_, _ = io.WriteString(c, "Password: ")
		if pass, _ := testLine(r); pass != secret {
			_, _ = io.WriteString(c, "Login incorrect\r\n")
			return
		}
		_, _ = io.WriteString(c, "echoed: "+secret+"\r\n~ $ ")
		if command, _ := testLine(r); command != "echo verified" {
			return
		}
		_, _ = io.WriteString(c, "\r\nverified\r\n~ $ ")
		for i := 0; i < len(secret); i++ {
			_, _ = c.Write([]byte{secret[i]})
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, e := OpenShell(ctx, target, "qa", secret, 100, 30)
	require.NoError(t, e)
	defer s.Close()
	cancel()
	_, e = s.Write([]byte("echo verified\n"))
	require.NoError(t, e)
	out, e := io.ReadAll(s)
	require.NoError(t, e)
	assert.Contains(t, string(out), "verified")
	assert.NotContains(t, string(out), secret)
	assert.Equal(t, 2, strings.Count(string(out), "[redacted]"))
	bad := target
	bad.ServerName = "wrong.invalid"
	_, e = OpenShell(context.Background(), bad, "qa", secret, 80, 24)
	require.ErrorIs(t, e, ErrUnavailable)
	_, e = OpenShell(context.Background(), target, "qa", "wrong-password", 80, 24)
	assert.ErrorIs(t, e, ErrAuthentication)
}

func TestLoginCancellationAndBannerBound(t *testing.T) {
	target := testServer(t, false, func(c net.Conn) { _, _ = io.WriteString(c, "login: "); _, _ = io.Copy(io.Discard, c) })
	ctx, stop := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer stop()
	_, e := OpenShell(ctx, target, "qa", "test-password", 80, 24)
	assert.Error(t, e)
	target = testServer(t, false, func(c net.Conn) { _, _ = c.Write(bytes.Repeat([]byte{'x'}, 65537)) })
	_, e = OpenShell(context.Background(), target, "qa", "test-password", 80, 24)
	assert.ErrorIs(t, e, ErrAuthentication)
}
