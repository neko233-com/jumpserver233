// Package sshgateway provides a loopback-only synthetic direct-tcpip fixture.
package sshgateway

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshidentity"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	xssh "golang.org/x/crypto/ssh"
)

const Username = "qa-gateway"
const Password = "synthetic-gateway-password"

type Server struct {
	listener    net.Listener
	config      *xssh.ServerConfig
	allowed     map[string]string
	mu          sync.Mutex
	closing     bool
	connections map[net.Conn]bool
	wg          sync.WaitGroup
	forwards    atomic.Int64
	Fingerprint string
}

func Start(address string, destinations map[string]string) (*Server, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return nil, fmt.Errorf("fixture requires loopback address")
	}
	allowed := map[string]string{}
	for from, to := range destinations {
		host, _, err := net.SplitHostPort(to)
		if err != nil || !net.ParseIP(host).IsLoopback() {
			return nil, fmt.Errorf("fixture destination must be loopback")
		}
		allowed[from] = to
	}
	seed := sha256.Sum256([]byte("jumpserver233 synthetic gateway fixture"))
	signer, err := xssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed[:]))
	if err != nil {
		return nil, err
	}
	config := &xssh.ServerConfig{PasswordCallback: func(meta xssh.ConnMetadata, password []byte) (*xssh.Permissions, error) {
		if meta.User() != Username || string(password) != Password {
			return nil, xssh.ErrNoAuth
		}
		return nil, nil
	}}
	config.PublicKeyCallback = sshidentity.PublicKeyCallback("qa-gateway")
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	s := &Server{listener: listener, config: config, allowed: allowed, connections: map[net.Conn]bool{}, Fingerprint: xssh.FingerprintSHA256(signer.PublicKey())}
	s.wg.Add(1)
	go s.accept()
	return s, nil
}
func (s *Server) Address() string { return s.listener.Addr().String() }
func (s *Server) Forwards() int64 { return s.forwards.Load() }
func (s *Server) Active() int     { s.mu.Lock(); defer s.mu.Unlock(); return len(s.connections) }
func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		_ = c.Close()
		return false
	}
	s.connections[c] = true
	return true
}
func (s *Server) untrack(c net.Conn) {
	_ = c.Close()
	s.mu.Lock()
	delete(s.connections, c)
	s.mu.Unlock()
}
func (s *Server) Close() {
	s.mu.Lock()
	s.closing = true
	_ = s.listener.Close()
	for c := range s.connections {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}
func (s *Server) accept() {
	defer s.wg.Done()
	for {
		raw, e := s.listener.Accept()
		if e != nil {
			return
		}
		if !s.track(raw) {
			return
		}
		s.wg.Add(1)
		go s.serve(raw)
	}
}
func (s *Server) serve(raw net.Conn) {
	defer s.wg.Done()
	defer s.untrack(raw)
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	conn, channels, requests, e := xssh.NewServerConn(raw, s.config)
	if e != nil {
		return
	}
	_ = raw.SetDeadline(time.Time{})
	defer conn.Close()
	go xssh.DiscardRequests(requests)
	for pending := range channels {
		var payload struct {
			Host       string
			Port       uint32
			Origin     string
			OriginPort uint32
		}
		if pending.ChannelType() != "direct-tcpip" || xssh.Unmarshal(pending.ExtraData(), &payload) != nil {
			_ = pending.Reject(xssh.Prohibited, "only synthetic TCP forwarding is allowed")
			continue
		}
		destination, ok := s.allowed[net.JoinHostPort(payload.Host, strconv.Itoa(int(payload.Port)))]
		if !ok {
			_ = pending.Reject(xssh.Prohibited, "destination is not in the fixture allowlist")
			continue
		}
		remote, e := net.DialTimeout("tcp", destination, time.Second)
		if e != nil {
			_ = pending.Reject(xssh.ConnectionFailed, "synthetic destination unavailable")
			continue
		}
		if !s.track(remote) {
			_ = pending.Reject(xssh.Prohibited, "closing")
			return
		}
		channel, requests, e := pending.Accept()
		if e != nil {
			s.untrack(remote)
			continue
		}
		s.forwards.Add(1)
		go xssh.DiscardRequests(requests)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.untrack(remote)
			defer channel.Close()
			done := make(chan struct{})
			go func() { _, _ = io.Copy(channel, remote); _ = channel.Close(); close(done) }()
			_, _ = io.Copy(remote, channel)
			_ = remote.Close()
			<-done
		}()
	}
}
