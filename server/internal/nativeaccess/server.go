package nativeaccess

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/maintenance"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
	"golang.org/x/crypto/ssh"
)

// Server is part of the application process, with no system sshd dependency.
// The domain-separated Ed25519 seed follows the backed-up Vault key; no host
// key is regenerated on upgrade, restart or restore with that same Vault key.
type Server struct {
	handler     http.Handler
	signer      ssh.Signer
	gate        *workgate.Gate
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	listener    net.Listener
	closed      bool
	wg          sync.WaitGroup
	slots       chan struct{}
	spoolSlots  chan struct{}
	temp        string
	tempLease   *maintenance.Lock
}

func New(handler http.Handler, vaultKey []byte, gate *workgate.Gate) (*Server, error) {
	if handler == nil || len(vaultKey) != 32 {
		return nil, errors.New("native SSH requires an API handler and Vault key")
	}
	mac := hmac.New(sha256.New, vaultKey)
	_, _ = mac.Write([]byte("jumpserver233/native-ssh/ed25519/v1"))
	signer, e := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(mac.Sum(nil)))
	if e != nil {
		return nil, e
	}
	identity := sha256.Sum256(signer.PublicKey().Marshal())
	temp, lease, e := openSpool(hex.EncodeToString(identity[:8]))
	if e != nil {
		return nil, e
	}
	return &Server{handler: handler, signer: signer, gate: gate, connections: make(map[net.Conn]struct{}), slots: make(chan struct{}, 64), spoolSlots: make(chan struct{}, 2), temp: temp, tempLease: lease}, nil
}
func (s *Server) Fingerprint() string { return ssh.FingerprintSHA256(s.signer.PublicKey()) }
func (s *Server) Serve(listener net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		listener.Close()
		return net.ErrClosed
	}
	s.listener = listener
	s.mu.Unlock()
	for {
		c, e := listener.Accept()
		if e != nil {
			return e
		}
		select {
		case s.slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			<-s.slots
			c.Close()
			return net.ErrClosed
		}
		s.connections[c] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() { <-s.slots; s.mu.Lock(); delete(s.connections, c); s.mu.Unlock(); c.Close() }()
			s.serveConnection(c)
		}()
	}
}
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	if s.listener != nil {
		_ = s.listener.Close()
	}
	for c := range s.connections {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tempLease == nil {
		return nil
	}
	e := removeSpool(s.temp, s.tempLease)
	s.tempLease = nil
	return e
}
func splitUsername(value string) (string, string, error) {
	user, org, found := strings.Cut(value, "%")
	if user == "" || len(user) > 128 || strings.ContainsAny(user, "\r\n\x00") {
		return "", "", os.ErrPermission
	}
	if found {
		if len(org) != 36 || strings.ContainsAny(org, "/%\\\r\n\x00") {
			return "", "", os.ErrPermission
		}
	}
	return user, org, nil
}
func (s *Server) serveConnection(raw net.Conn) {
	_ = raw.SetDeadline(time.Now().Add(30 * time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t := newHandlerTransport(s.handler, raw.RemoteAddr())
	defer t.Close()
	client := &apiClient{transport: t, execSlots: make(chan struct{}, 1)}
	defer client.logout()
	authenticate := func(meta ssh.ConnMetadata, password, otp string) (*ssh.Permissions, error) {
		if s.gate.Closed() {
			return nil, os.ErrPermission
		}
		user, org, e := splitUsername(meta.User())
		if e != nil {
			return nil, e
		}
		client.organization = org
		user, selected, _ := strings.Cut(user, "#")
		if user == "" || len(selected) > 128 || strings.ContainsAny(selected, "/\\%?#\x00") {
			return nil, os.ErrPermission
		}
		if e = client.login(ctx, user, password, otp); e != nil {
			return nil, e
		}
		if selected != "" {
			if e = client.selectTarget(ctx, selected); e != nil {
				client.logout()
				return nil, e
			}
		}
		return &ssh.Permissions{}, nil
	}
	config := &ssh.ServerConfig{ServerVersion: "SSH-2.0-JumpServer233", MaxAuthTries: 4,
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			return authenticate(meta, string(password), "")
		},
		KeyboardInteractiveCallback: func(meta ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, e := challenge(meta.User(), "JumpServer233", []string{"Password / 密码: "}, []bool{false})
			if e != nil || len(answers) != 1 {
				return nil, os.ErrPermission
			}
			permission, e := authenticate(meta, answers[0], "")
			var failure *apiError
			if errors.As(e, &failure) && failure.MFA {
				codes, err := challenge(meta.User(), "MFA", []string{"One-time code / 动态验证码: "}, []bool{false})
				if err != nil || len(codes) != 1 {
					return nil, os.ErrPermission
				}
				return authenticate(meta, answers[0], codes[0])
			}
			return permission, e
		}}
	config.AddHostKey(s.signer)
	conn, channels, requests, e := ssh.NewServerConn(raw, config)
	if e != nil {
		return
	}
	defer conn.Close()
	release, e := s.gate.Acquire("native_ssh_connections")
	if e != nil {
		return
	}
	defer release()
	_ = raw.SetDeadline(time.Time{})
	go func() {
		for r := range requests {
			_ = r.Reply(r.Type == "keepalive@openssh.com", nil)
		}
	}()
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if client.validate(ctx) != nil {
					_ = conn.Close()
					return
				}
			}
		}
	}()
	var channelWG sync.WaitGroup
	defer func() { cancel(); _ = conn.Close(); channelWG.Wait() }()
	capacity := make(chan struct{}, 16)
	for incoming := range channels {
		if incoming.ChannelType() != "session" {
			_ = incoming.Reject(ssh.Prohibited, "only audited terminal and SFTP channels are supported")
			continue
		}
		select {
		case capacity <- struct{}{}:
		default:
			_ = incoming.Reject(ssh.ResourceShortage, "channel limit")
			continue
		}
		ch, reqs, e := incoming.Accept()
		if e != nil {
			<-capacity
			continue
		}
		channelWG.Add(1)
		go func() {
			defer channelWG.Done()
			defer func() { <-capacity; ch.Close() }()
			s.serveChannel(ctx, client, ch, reqs)
		}()
	}
}
func exitStatus(ch ssh.Channel, code uint32) {
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{code}))
}
func (s *Server) serveChannel(parent context.Context, c *apiClient, ch ssh.Channel, requests <-chan *ssh.Request) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	state := &terminalState{cols: 80, rows: 24}
	started := false
	startup := time.NewTimer(10 * time.Second)
	defer startup.Stop()
	var worker sync.WaitGroup
	defer func() { cancel(); _ = ch.Close(); worker.Wait() }()
	for {
		var req *ssh.Request
		select {
		case <-ctx.Done():
			return
		case <-startup.C:
			return
		case r, ok := <-requests:
			if !ok {
				return
			}
			req = r
		}
		switch req.Type {
		case "pty-req":
			var p struct {
				Term                      string
				Cols, Rows, Width, Height uint32
				Modes                     string
			}
			ok := !started && ssh.Unmarshal(req.Payload, &p) == nil && validSize(p.Cols, p.Rows)
			if ok {
				state.cols, state.rows = int(p.Cols), int(p.Rows)
				state.plain = p.Term == "dumb"
			}
			_ = req.Reply(ok, nil)
		case "env":
			var env struct{ Name, Value string }
			ok := !started && ssh.Unmarshal(req.Payload, &env) == nil && (env.Name == "LANG" || env.Name == "LC_ALL") && len(env.Value) < 64
			if ok {
				state.english = strings.HasPrefix(strings.ToLower(env.Value), "en")
			}
			_ = req.Reply(ok, nil)
		case "window-change":
			var size struct{ Cols, Rows, Width, Height uint32 }
			ok := ssh.Unmarshal(req.Payload, &size) == nil && validSize(size.Cols, size.Rows)
			if ok {
				state.resize(ctx, int(size.Cols), int(size.Rows))
			}
			_ = req.Reply(ok, nil)
		case "shell", "exec", "subsystem":
			if started {
				_ = req.Reply(false, nil)
				continue
			}
			var command struct{ Value string }
			ok := req.Type == "shell" && len(req.Payload) == 0 || req.Type != "shell" && ssh.Unmarshal(req.Payload, &command) == nil
			if req.Type == "subsystem" {
				ok = ok && command.Value == "sftp"
			}
			if req.Type == "exec" {
				ok = ok && command.Value != "" && len(command.Value) <= 8192 && !strings.ContainsRune(command.Value, '\x00')
			}
			if !ok {
				_ = req.Reply(false, nil)
				return
			}
			started = true
			startup.Stop()
			_ = req.Reply(true, nil)
			worker.Add(1)
			go func(kind, value string) {
				defer worker.Done()
				defer cancel()
				defer ch.Close()
				var e error
				if kind == "subsystem" {
					e = s.serveSFTP(ctx, c, ch)
				} else {
					input := inputFor(ctx, ch)
					if kind == "exec" && strings.HasPrefix(value, "connect ") && len(strings.Fields(value)) == 2 {
						e = c.selectTarget(ctx, strings.Fields(value)[1])
						if e == nil {
							e = state.relay(ctx, c, ch, strings.Fields(value)[1], input)
						}
					} else if kind == "exec" {
						e = s.exec(ctx, c, ch, value)
					} else {
						e = state.menu(ctx, c, ch, input)
					}
				}
				if e != nil && !errors.Is(e, io.EOF) && !errors.Is(e, context.Canceled) {
					_, _ = io.WriteString(ch.Stderr(), "Access denied, session closed, or review required / 访问拒绝、会话结束或需要审批\r\n")
					exitStatus(ch, 1)
				} else if kind != "exec" || strings.HasPrefix(value, "connect ") {
					exitStatus(ch, 0)
				}
			}(req.Type, command.Value)
		default:
			_ = req.Reply(false, nil)
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
func validSize(cols, rows uint32) bool { return cols >= 2 && cols <= 500 && rows >= 2 && rows <= 500 }
