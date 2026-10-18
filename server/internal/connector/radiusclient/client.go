// Package radiusclient implements PAP RADIUS and RadSec without an external
// process. Message-Authenticator is mandatory in requests and responses.
package radiusclient

import (
	"context"
	"crypto/hmac"
	"crypto/md5" // Required by RFC 2865/3579; RadSec protects the transport.
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrConfig      = errors.New("invalid RADIUS configuration")
	ErrCredentials = errors.New("RADIUS credentials rejected")
	ErrProtocol    = errors.New("invalid RADIUS response")
	ErrUnavailable = errors.New("RADIUS service unavailable")
)

const (
	AccessRequest   byte = 1
	AccessAccept    byte = 2
	AccessReject    byte = 3
	AccessChallenge byte = 11
	MaxPacket            = 4096
)

type Config struct {
	Host              string `json:"host"`
	Port              int    `json:"port"`
	Transport         string `json:"transport"`
	AllowUDP          bool   `json:"allow_udp"`
	ServerName        string `json:"server_name"`
	CAPEM             string `json:"ca_pem"`
	ClientCertificate string `json:"client_certificate"`
	NASIdentifier     string `json:"nas_identifier"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
	Attempts          int    `json:"attempts"`
}
type Secrets struct{ SharedSecret, ClientKey string }
type Request struct {
	Username, Password string
	State              []byte
}
type Reply struct {
	Code    byte
	State   []byte
	Message string
}
type Client interface {
	Exchange(context.Context, Config, Secrets, Request) (Reply, error)
}
type Native struct{}

func Normalize(c Config) (Config, error) {
	c.Host = strings.TrimSpace(c.Host)
	if c.Transport == "" {
		c.Transport = "tls"
	}
	if c.Port == 0 {
		c.Port = 2083
		if c.Transport == "udp" {
			c.Port = 1812
		}
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 3
	}
	if c.Attempts == 0 {
		c.Attempts = 2
	}
	if c.NASIdentifier == "" {
		c.NASIdentifier = "jumpserver233"
	}
	if len(c.Host) < 1 || len(c.Host) > 253 || strings.ContainsAny(c.Host, "/\\?#@[]") || strings.IndexFunc(c.Host, unicode.IsSpace) >= 0 || strings.IndexFunc(c.Host, unicode.IsControl) >= 0 || c.Port < 1 || c.Port > 65535 || c.Transport != "tls" && c.Transport != "udp" || c.Transport == "udp" && !c.AllowUDP || c.TimeoutSeconds < 1 || c.TimeoutSeconds > 5 || c.Attempts < 1 || c.Attempts > 3 || c.TimeoutSeconds*c.Attempts > 10 {
		return c, ErrConfig
	}
	if net.ParseIP(c.Host) == nil {
		for _, label := range strings.Split(c.Host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return c, ErrConfig
			}
			for _, ch := range label {
				if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
					return c, ErrConfig
				}
			}
		}
	}
	for _, v := range []string{c.ServerName, c.NASIdentifier} {
		if len(v) > 253 || !utf8.ValidString(v) || strings.IndexFunc(v, unicode.IsControl) >= 0 {
			return c, ErrConfig
		}
	}
	if len(c.CAPEM) > 64<<10 || len(c.ClientCertificate) > 32<<10 {
		return c, ErrConfig
	}
	if c.Transport == "udp" && (c.ServerName != "" || c.CAPEM != "" || c.ClientCertificate != "") {
		return c, ErrConfig
	}
	if c.CAPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(c.CAPEM)) {
			return c, ErrConfig
		}
	}
	return c, nil
}
func Validate(c Config, s Secrets) error {
	normalized, e := Normalize(c)
	if e != nil {
		return e
	}
	c = normalized
	if c.Transport == "udp" && (len(s.SharedSecret) < 16 || len(s.SharedSecret) > 256 || strings.IndexFunc(s.SharedSecret, unicode.IsControl) >= 0) {
		return ErrConfig
	}
	if c.Transport == "tls" {
		if c.ClientCertificate == "" || s.ClientKey == "" || len(s.ClientKey) > 32<<10 {
			return ErrConfig
		}
		if _, e = tls.X509KeyPair([]byte(c.ClientCertificate), []byte(s.ClientKey)); e != nil {
			return ErrConfig
		}
	}
	return nil
}
func effectiveSecret(c Config, s Secrets) []byte {
	if c.Transport == "tls" {
		return []byte("radsec")
	}
	return []byte(s.SharedSecret)
}
func (Native) Exchange(ctx context.Context, c Config, secrets Secrets, in Request) (Reply, error) {
	var e error
	c, e = Normalize(c)
	if e != nil || Validate(c, secrets) != nil {
		return Reply{}, ErrConfig
	}
	packet, e := EncodeRequest(in, c.NASIdentifier, effectiveSecret(c, secrets))
	if e != nil {
		return Reply{}, e
	}
	total := time.Duration(c.TimeoutSeconds*c.Attempts) * time.Second
	ctx, cancel := context.WithTimeout(ctx, total)
	defer cancel()
	address := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	dial := net.Dialer{Timeout: time.Duration(c.TimeoutSeconds) * time.Second}
	var conn net.Conn
	if c.Transport == "tls" {
		name := c.ServerName
		if name == "" {
			name = c.Host
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name}
		if c.CAPEM != "" {
			cfg.RootCAs = x509.NewCertPool()
			cfg.RootCAs.AppendCertsFromPEM([]byte(c.CAPEM))
		}
		cert, _ := tls.X509KeyPair([]byte(c.ClientCertificate), []byte(secrets.ClientKey))
		cfg.Certificates = []tls.Certificate{cert}
		conn, e = (&tls.Dialer{NetDialer: &dial, Config: cfg}).DialContext(ctx, "tcp", address)
	} else {
		conn, e = dial.DialContext(ctx, "udp", address)
	}
	if e != nil {
		return Reply{}, ErrUnavailable
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	for attempt := 0; attempt < c.Attempts; attempt++ {
		end := time.Now().Add(time.Duration(c.TimeoutSeconds) * time.Second)
		if d, ok := ctx.Deadline(); ok && d.Before(end) {
			end = d
		}
		_ = conn.SetDeadline(end)
		if _, e = conn.Write(packet); e != nil {
			return Reply{}, ErrUnavailable
		}
		invalid := 0
		for {
			var response []byte
			if c.Transport == "tls" {
				header := make([]byte, 4)
				if _, e = io.ReadFull(conn, header); e == nil {
					length := int(binary.BigEndian.Uint16(header[2:]))
					if length < 20 || length > MaxPacket {
						return Reply{}, ErrProtocol
					}
					response = make([]byte, length)
					copy(response, header)
					_, e = io.ReadFull(conn, response[4:])
				}
			} else {
				buf := make([]byte, MaxPacket+1)
				var n int
				n, e = conn.Read(buf)
				if e == nil {
					if n > MaxPacket {
						return Reply{}, ErrProtocol
					}
					response = buf[:n]
				}
			}
			if e != nil {
				var timeout net.Error
				if c.Transport == "udp" && errors.As(e, &timeout) && timeout.Timeout() && ctx.Err() == nil {
					break
				}
				return Reply{}, ErrUnavailable
			}
			reply, err := DecodeReply(packet, response, effectiveSecret(c, secrets))
			if err == nil {
				return reply, nil
			}
			invalid++
			if c.Transport == "tls" || invalid >= 8 {
				return Reply{}, ErrProtocol
			}
		}
	}
	return Reply{}, ErrUnavailable
}
func attr(packet []byte, t byte, v []byte) ([]byte, error) {
	if len(v) > 253 || len(packet)+2+len(v) > MaxPacket {
		return nil, ErrProtocol
	}
	packet = append(packet, t, byte(2+len(v)))
	return append(packet, v...), nil
}
func validText(s string, max int) bool {
	return len(s) > 0 && len(s) <= max && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}
func EncodeRequest(in Request, nas string, secret []byte) ([]byte, error) {
	if !validText(in.Username, 253) || len(in.Password) > 128 || strings.ContainsRune(in.Password, 0) || !utf8.ValidString(in.Password) || len(in.State) > 253 || !validText(nas, 253) || len(secret) == 0 {
		return nil, ErrCredentials
	}
	packet := make([]byte, 20)
	packet[0] = AccessRequest
	if _, e := rand.Read(packet[1:2]); e != nil {
		return nil, e
	}
	if _, e := rand.Read(packet[4:20]); e != nil {
		return nil, e
	}
	var e error
	packet, e = attr(packet, 1, []byte(in.Username))
	if e != nil {
		return nil, e
	}
	encrypted := obscurePassword([]byte(in.Password), secret, packet[4:20])
	packet, e = attr(packet, 2, encrypted)
	if e != nil {
		return nil, e
	}
	packet, e = attr(packet, 32, []byte(nas))
	if e != nil {
		return nil, e
	}
	packet, e = attr(packet, 6, []byte{0, 0, 0, 8})
	if e != nil {
		return nil, e
	}
	if len(in.State) > 0 {
		packet, e = attr(packet, 24, in.State)
		if e != nil {
			return nil, e
		}
	}
	packet, e = attr(packet, 80, make([]byte, 16))
	if e != nil {
		return nil, e
	}
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	mac := hmac.New(md5.New, secret)
	_, _ = mac.Write(packet)
	copy(packet[len(packet)-16:], mac.Sum(nil))
	return packet, nil
}
func obscurePassword(password, secret, auth []byte) []byte {
	n := (len(password) + 15) / 16 * 16
	if n == 0 {
		n = 16
	}
	out := make([]byte, n)
	copy(out, password)
	prev := auth
	for offset := 0; offset < n; offset += 16 {
		h := md5.New()
		_, _ = h.Write(secret)
		_, _ = h.Write(prev)
		mask := h.Sum(nil)
		for i := 0; i < 16; i++ {
			out[offset+i] ^= mask[i]
		}
		prev = out[offset : offset+16]
	}
	return out
}
func DecodeReply(request, response, secret []byte) (Reply, error) {
	if len(request) < 20 || len(response) < 20 || len(response) > MaxPacket || int(binary.BigEndian.Uint16(response[2:4])) != len(response) || response[1] != request[1] || response[0] != AccessAccept && response[0] != AccessReject && response[0] != AccessChallenge {
		return Reply{}, ErrProtocol
	}
	h := md5.New()
	_, _ = h.Write(response[:4])
	_, _ = h.Write(request[4:20])
	_, _ = h.Write(response[20:])
	_, _ = h.Write(secret)
	if subtle.ConstantTimeCompare(response[4:20], h.Sum(nil)) != 1 {
		return Reply{}, ErrProtocol
	}
	copyPacket := append([]byte(nil), response...)
	copy(copyPacket[4:20], request[4:20])
	ma := -1
	reply := Reply{Code: response[0]}
	stateCount := 0
	count := 0
	for p := 20; p < len(response); {
		if p+2 > len(response) {
			return Reply{}, ErrProtocol
		}
		length := int(response[p+1])
		if length < 2 || p+length > len(response) {
			return Reply{}, ErrProtocol
		}
		v := response[p+2 : p+length]
		count++
		if count > 128 {
			return Reply{}, ErrProtocol
		}
		switch response[p] {
		case 80:
			if ma >= 0 || length != 18 {
				return Reply{}, ErrProtocol
			}
			ma = p + 2
			clear(copyPacket[ma : ma+16])
		case 24:
			stateCount++
			if stateCount > 1 {
				return Reply{}, ErrProtocol
			}
			reply.State = append([]byte(nil), v...)
		case 18:
			if !utf8.Valid(v) || len(reply.Message)+len(v) > 512 {
				return Reply{}, ErrProtocol
			}
			if reply.Message != "" {
				reply.Message += " "
			}
			reply.Message += string(v)
		case 33:
			return Reply{}, ErrProtocol // This client never emits Proxy-State.
		}
		p += length
	}
	if ma < 0 {
		return Reply{}, ErrProtocol
	}
	mac := hmac.New(md5.New, secret)
	_, _ = mac.Write(copyPacket)
	if subtle.ConstantTimeCompare(response[ma:ma+16], mac.Sum(nil)) != 1 {
		return Reply{}, ErrProtocol
	}
	reply.Message = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, reply.Message)
	if reply.Code != AccessChallenge {
		reply.State = nil
	}
	return reply, nil
}
