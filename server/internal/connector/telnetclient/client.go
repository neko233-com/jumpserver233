// Package telnetclient implements authenticated NVT terminals over a fixed TCP
// target, optionally secured by verified direct TLS and pinned SSH gateways.
package telnetclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
)

var (
	ErrInvalid        = errors.New("invalid Telnet configuration")
	ErrUnavailable    = errors.New("Telnet connection unavailable")
	ErrAuthentication = errors.New("Telnet login was not confirmed")
	ErrProtocol       = errors.New("invalid Telnet stream")
)

type Settings struct {
	TLSMode        string `json:"tls_mode"`
	ServerName     string `json:"server_name,omitempty"`
	RootCAPEM      string `json:"root_ca_pem,omitempty"`
	LoginPrompt    string `json:"login_prompt"`
	PasswordPrompt string `json:"password_prompt"`
	SuccessPrompt  string `json:"success_prompt"`
}

type Target struct {
	Host string
	Port int
	Settings
	Gateways []sshclient.Hop
}

func Normalize(s Settings) (Settings, error) {
	if s.TLSMode == "" {
		s.TLSMode = "verify-full"
	}
	if s.LoginPrompt == "" {
		s.LoginPrompt = `(?im)(?:login|username)\s*:\s*$`
	}
	if s.PasswordPrompt == "" {
		s.PasswordPrompt = `(?im)password\s*:\s*$`
	}
	if s.SuccessPrompt == "" {
		s.SuccessPrompt = `(?m)(?:^|[\r\n])[^\r\n]{0,128}[#$>]\s*$`
	}
	if s.TLSMode != "verify-full" && s.TLSMode != "disable" || len(s.RootCAPEM) > 64*1024 || len(s.ServerName) > 253 || strings.ContainsAny(s.ServerName, "\x00\r\n /\\@:*") {
		return Settings{}, ErrInvalid
	}
	if s.TLSMode == "disable" && (s.RootCAPEM != "" || s.ServerName != "") {
		return Settings{}, ErrInvalid
	}
	if s.RootCAPEM != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(s.RootCAPEM)) {
		return Settings{}, ErrInvalid
	}
	for _, pattern := range []string{s.LoginPrompt, s.PasswordPrompt, s.SuccessPrompt} {
		if len(pattern) > 512 || strings.ContainsRune(pattern, 0) {
			return Settings{}, ErrInvalid
		}
		r, e := regexp.Compile(pattern)
		if e != nil || r.MatchString("") {
			return Settings{}, ErrInvalid
		}
	}
	return s, nil
}

func ValidCredential(value string) bool {
	return value != "" && len(value) <= 4096 && !strings.ContainsAny(value, "\x00\r\n")
}

// Shell serializes option negotiation, resize and input writes. Authentication
// preambles never reach callers; exact password echoes are redacted in output.
type Shell struct {
	conn          net.Conn
	reader        *bufio.Reader
	once          sync.Once
	mu            sync.Mutex
	local, remote [256]bool
	cols, rows    int
	lastCR        bool
	readMu        sync.Mutex
	initial       []byte
	redactor      *secretFilter
	readErr       error
}

func OpenShell(ctx context.Context, t Target, username, password string, cols, rows int) (*Shell, error) {
	s, e := Normalize(t.Settings)
	if e != nil || t.Host == "" || t.Port < 1 || t.Port > 65535 || cols < 2 || cols > 500 || rows < 2 || rows > 500 || !ValidCredential(username) || !ValidCredential(password) {
		return nil, ErrInvalid
	}
	conn, e := sshclient.DialTunnel(ctx, t.Gateways, net.JoinHostPort(t.Host, strconv.Itoa(t.Port)), 5*time.Second)
	if e != nil {
		return nil, ErrUnavailable
	}
	baseConn := conn
	stop := context.AfterFunc(ctx, func() { _ = baseConn.Close() })
	ok := false
	defer func() {
		stop()
		if !ok {
			_ = conn.Close()
		}
	}()
	deadline := time.Now().Add(12 * time.Second)
	if d, yes := ctx.Deadline(); yes && d.Before(deadline) {
		deadline = d
	}
	if e = conn.SetDeadline(deadline); e != nil {
		return nil, ErrUnavailable
	}
	if s.TLSMode == "verify-full" {
		name := s.ServerName
		if name == "" {
			name = t.Host
		}
		config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name}
		if s.RootCAPEM != "" {
			pool, err := x509.SystemCertPool()
			if err != nil {
				pool = x509.NewCertPool()
			}
			pool.AppendCertsFromPEM([]byte(s.RootCAPEM))
			config.RootCAs = pool
		}
		secured := tls.Client(conn, config)
		if e = secured.HandshakeContext(ctx); e != nil {
			return nil, ErrUnavailable
		}
		conn = secured
	}
	shell := &Shell{conn: conn, reader: bufio.NewReaderSize(conn, 4096), cols: cols, rows: rows, redactor: newSecretFilter(password)}
	initial, e := shell.authenticate(s, username, password)
	if e != nil {
		return nil, e
	}
	if !stop() || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	if e = conn.SetDeadline(time.Time{}); e != nil {
		return nil, ErrUnavailable
	}
	shell.initial = shell.redactor.filter(initial, false)
	ok = true
	return shell, nil
}

var failedLogin = regexp.MustCompile(`(?i)(authentication (?:failed|failure)|login incorrect|access denied|bad password)`)

func (s *Shell) authenticate(config Settings, username, password string) ([]byte, error) {
	login := regexp.MustCompile(config.LoginPrompt)
	pass := regexp.MustCompile(config.PasswordPrompt)
	success := regexp.MustCompile(config.SuccessPrompt)
	buffer := make([]byte, 0, 4096)
	sentUser, sentPassword := false, false
	total := 0
	for {
		part := make([]byte, 4096)
		n, e := s.readNVT(part)
		if e != nil {
			return nil, ErrAuthentication
		}
		if n > 0 {
			total += n
			if total > 64*1024 {
				return nil, ErrAuthentication
			}
			buffer = append(buffer, part[:n]...)
			visible := bytes.ReplaceAll(buffer, []byte(password), []byte("[redacted]"))
			if failedLogin.Match(visible) {
				return nil, ErrAuthentication
			}
			if sentPassword {
				if login.Match(visible) || pass.Match(visible) {
					return nil, ErrAuthentication
				}
				if success.Match(visible) {
					return buffer, nil
				}
			} else if pass.Match(buffer) {
				if _, err := s.Write([]byte(password + "\r")); err != nil {
					return nil, ErrUnavailable
				}
				sentPassword = true
				buffer = buffer[:0]
			} else if login.Match(buffer) {
				if sentUser {
					return nil, ErrAuthentication
				}
				if _, err := s.Write([]byte(username + "\r")); err != nil {
					return nil, ErrUnavailable
				}
				sentUser = true
				buffer = buffer[:0]
			}
		}
	}
}

const (
	iac  byte = 255
	dont byte = 254
	do   byte = 253
	wont byte = 252
	will byte = 251
	sb   byte = 250
	se   byte = 240
)

func escape(data []byte) []byte {
	out := make([]byte, 0, len(data)+8)
	for _, b := range data {
		out = append(out, b)
		if b == iac {
			out = append(out, iac)
		}
	}
	return out
}

func (s *Shell) writeRaw(data []byte) error {
	for len(data) > 0 {
		n, e := s.conn.Write(data)
		if e != nil {
			return ErrUnavailable
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func (s *Shell) sub(option byte, data []byte) error {
	msg := append([]byte{iac, sb, option}, escape(data)...)
	msg = append(msg, iac, se)
	return s.writeRaw(msg)
}
func (s *Shell) window() error {
	return s.sub(31, []byte{byte(s.cols >> 8), byte(s.cols), byte(s.rows >> 8), byte(s.rows)})
}

func (s *Shell) negotiate(command, option byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch command {
	case do:
		if option != 0 && option != 3 && option != 24 && option != 31 {
			return s.writeRaw([]byte{iac, wont, option})
		}
		if s.local[option] {
			return nil
		}
		s.local[option] = true
		if e := s.writeRaw([]byte{iac, will, option}); e != nil {
			return e
		}
		if option == 31 {
			return s.window()
		}
	case dont:
		if s.local[option] {
			s.local[option] = false
			return s.writeRaw([]byte{iac, wont, option})
		}
	case will:
		if option != 0 && option != 1 && option != 3 {
			return s.writeRaw([]byte{iac, dont, option})
		}
		if s.remote[option] {
			return nil
		}
		s.remote[option] = true
		return s.writeRaw([]byte{iac, do, option})
	case wont:
		if s.remote[option] {
			s.remote[option] = false
			return s.writeRaw([]byte{iac, dont, option})
		}
	}
	return nil
}

func (s *Shell) readNVT(p []byte) (int, error) {
	n, controls := 0, 0
	for n < len(p) {
		if n > 0 && s.reader.Buffered() == 0 {
			return n, nil
		}
		b, e := s.reader.ReadByte()
		if e != nil {
			return n, e
		}
		if b == iac {
			controls++
			if controls > 1024 {
				return n, ErrProtocol
			}
			command, err := s.reader.ReadByte()
			if err != nil {
				return n, err
			}
			switch command {
			case iac:
				b = iac
			case do, dont, will, wont:
				option, err := s.reader.ReadByte()
				if err != nil {
					return n, err
				}
				if err = s.negotiate(command, option); err != nil {
					return n, err
				}
				continue
			case sb:
				data := make([]byte, 0, 64)
				for {
					v, err := s.reader.ReadByte()
					if err != nil {
						return n, err
					}
					if v == iac {
						v, err = s.reader.ReadByte()
						if err != nil {
							return n, err
						}
						if v == se {
							break
						}
						if v != iac {
							return n, ErrProtocol
						}
					}
					data = append(data, v)
					if len(data) > 1024 {
						return n, ErrProtocol
					}
				}
				s.mu.Lock()
				if len(data) == 2 && data[0] == 24 && data[1] == 1 && s.local[24] {
					err = s.sub(24, append([]byte{0}, []byte("xterm-256color")...))
				}
				s.mu.Unlock()
				if err != nil {
					return n, err
				}
				continue
			default:
				continue
			}
		}
		s.mu.Lock()
		binary := s.remote[0]
		s.mu.Unlock()
		if !binary && s.lastCR && b == 0 {
			s.lastCR = false
			continue
		}
		s.lastCR = !binary && b == '\r'
		p[n] = b
		n++
	}
	return n, nil
}

func (s *Shell) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for len(s.initial) == 0 {
		if s.readErr != nil {
			return 0, s.readErr
		}
		buffer := make([]byte, 32*1024)
		n, e := s.readNVT(buffer)
		s.initial = s.redactor.filter(buffer[:n], e != nil)
		if e != nil {
			if errors.Is(e, io.EOF) {
				s.readErr = io.EOF
			} else {
				s.readErr = ErrUnavailable
			}
		}
	}
	n := copy(p, s.initial)
	s.initial = s.initial[n:]
	return n, nil
}

func (s *Shell) Write(p []byte) (int, error) {
	if len(p) > 64*1024 {
		return 0, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data := p
	if !s.local[0] {
		data = make([]byte, 0, len(p)+16)
		for i := 0; i < len(p); i++ {
			b := p[i]
			if b == '\r' {
				data = append(data, '\r', '\n')
				if i+1 < len(p) && p[i+1] == '\n' {
					i++
				}
			} else if b == '\n' {
				data = append(data, '\r', '\n')
			} else {
				data = append(data, b)
			}
		}
	}
	if e := s.writeRaw(escape(data)); e != nil {
		return 0, e
	}
	return len(p), nil
}
func (s *Shell) Resize(cols, rows int) error {
	if cols < 2 || cols > 500 || rows < 2 || rows > 500 {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cols = cols
	s.rows = rows
	if s.local[31] {
		return s.window()
	}
	return nil
}
func (s *Shell) Close() error { s.once.Do(func() { _ = s.conn.Close() }); return nil }

// KMP prefix matching retains only a possible secret prefix, so ordinary prompts
// are displayed immediately and a split credential echo cannot escape redaction.
type secretFilter struct {
	secret  []byte
	prefix  []int
	matched int
}

func newSecretFilter(secret string) *secretFilter {
	s := &secretFilter{secret: []byte(secret), prefix: make([]int, len(secret))}
	for i, j := 1, 0; i < len(s.secret); i++ {
		for j > 0 && s.secret[i] != s.secret[j] {
			j = s.prefix[j-1]
		}
		if s.secret[i] == s.secret[j] {
			j++
		}
		s.prefix[i] = j
	}
	return s
}
func (s *secretFilter) filter(data []byte, final bool) []byte {
	var out bytes.Buffer
	for _, b := range data {
		for s.matched > 0 && b != s.secret[s.matched] {
			next := s.prefix[s.matched-1]
			out.Write(s.secret[:s.matched-next])
			s.matched = next
		}
		if b == s.secret[s.matched] {
			s.matched++
			if s.matched == len(s.secret) {
				out.WriteString("[redacted]")
				s.matched = 0
			}
		} else {
			out.WriteByte(b)
		}
	}
	if final && s.matched > 0 {
		out.WriteString("[redacted]")
		s.matched = 0
	}
	return out.Bytes()
}
