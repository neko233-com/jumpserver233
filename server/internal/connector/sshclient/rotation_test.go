package sshclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshidentity"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"
)

func TestChangePasswordUsesEncryptedSSHStdinAndVerifiesNewCredential(t *testing.T) {
	for _, tc := range []struct {
		name    string
		uid     string
		command string
	}{
		{name: "root", uid: "0", command: "chpasswd"},
		{name: "sudo", uid: "1000", command: "sudo -n chpasswd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, target := startRotationServer(t, tc.uid, "initial-password")
			defer server.listener.Close()

			const newPassword = "very-strong-generated-password-0001"
			if err := ChangePassword(context.Background(), target, Credentials{Password: "initial-password"}, newPassword, 3*time.Second); err != nil {
				t.Fatalf("ChangePassword() error = %v", err)
			}
			if err := VerifyPassword(context.Background(), target, Credentials{Password: newPassword}, time.Second); err != nil {
				t.Fatalf("VerifyPassword(new) error = %v", err)
			}
			if err := VerifyPassword(context.Background(), target, Credentials{Password: "initial-password"}, time.Second); err == nil {
				t.Fatal("old password remained valid after rotation")
			}
			server.mu.Lock()
			defer server.mu.Unlock()
			if got := server.password; got != newPassword {
				t.Fatalf("server password = %q, want new generated value", got)
			}
			if !containsCommand(server.commands, "id -u") || !containsCommand(server.commands, tc.command) {
				t.Fatalf("SSH commands = %v, want id -u and %q", server.commands, tc.command)
			}
			for _, command := range server.commands {
				if strings.Contains(command, newPassword) {
					t.Fatalf("new password appeared in SSH command: %q", command)
				}
			}
			if got := server.stdin; got != "rotation:"+newPassword+"\n" {
				t.Fatalf("SSH stdin payload = %q, want account and password on stdin", got)
			}
		})
	}
}

func TestChangePasswordRejectsUnsafeAccountAndPassword(t *testing.T) {
	target := Target{Username: "bad:user"}
	if err := ChangePassword(context.Background(), target, Credentials{Password: "old"}, "abcdefghijklmnopqrstuvwxyz012345", time.Second); err != ErrInvalidRotationAccount {
		t.Fatalf("unsafe account error = %v, want ErrInvalidRotationAccount", err)
	}
	target.Username = "safe_user"
	if err := ChangePassword(context.Background(), target, Credentials{Password: "old"}, "too-short", time.Second); err != ErrInvalidGeneratedPassword {
		t.Fatalf("unsafe password error = %v, want ErrInvalidGeneratedPassword", err)
	}
}

type rotationTestServer struct {
	listener    net.Listener
	config      *xssh.ServerConfig
	fingerprint string
	uid         string
	mu          sync.Mutex
	password    string
	commands    []string
	stdin       string
	resetUser   string
}

func startRotationServer(t *testing.T, uid, initialPassword string) (*rotationTestServer, Target) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := xssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	server := &rotationTestServer{uid: uid, password: initialPassword}
	server.config = &xssh.ServerConfig{PasswordCallback: func(conn xssh.ConnMetadata, password []byte) (*xssh.Permissions, error) {
		server.mu.Lock()
		valid := conn.User() == "rotation" && string(password) == server.password
		server.mu.Unlock()
		if !valid {
			return nil, xssh.ErrNoAuth
		}
		return nil, nil
	}}
	server.config.PublicKeyCallback = sshidentity.PublicKeyCallback("rotation")
	server.config.AddHostKey(signer)
	server.listener, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server.fingerprint = xssh.FingerprintSHA256(signer.PublicKey())
	go server.serve()
	host, portText, err := net.SplitHostPort(server.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return server, Target{Host: host, Port: port, Username: "rotation", HostKeyFingerprint: server.fingerprint}
}

func (s *rotationTestServer) serve() {
	for {
		connection, err := s.listener.Accept()
		if err != nil {
			return
		}
		go func() {
			serverConnection, channels, requests, err := xssh.NewServerConn(connection, s.config)
			if err != nil {
				_ = connection.Close()
				return
			}
			go xssh.DiscardRequests(requests)
			defer serverConnection.Close()
			for channelRequest := range channels {
				if channelRequest.ChannelType() != "session" {
					_ = channelRequest.Reject(xssh.UnknownChannelType, "unsupported")
					continue
				}
				channel, requests, acceptErr := channelRequest.Accept()
				if acceptErr != nil {
					continue
				}
				go s.serveSession(channel, requests)
			}
		}()
	}
}

func (s *rotationTestServer) serveSession(channel xssh.Channel, requests <-chan *xssh.Request) {
	defer channel.Close()
	for request := range requests {
		if request.Type != "exec" {
			_ = request.Reply(false, nil)
			continue
		}
		var payload struct{ Command string }
		if err := xssh.Unmarshal(request.Payload, &payload); err != nil {
			_ = request.Reply(false, nil)
			return
		}
		_ = request.Reply(true, nil)
		s.mu.Lock()
		s.commands = append(s.commands, payload.Command)
		s.mu.Unlock()
		if payload.Command == "id -u" {
			_, _ = io.WriteString(channel, s.uid+"\n")
			s.sendExitStatus(channel, 0)
			return
		}
		if payload.Command != "chpasswd" && payload.Command != "sudo -n chpasswd" {
			s.sendExitStatus(channel, 1)
			return
		}
		input, err := io.ReadAll(channel)
		if err != nil {
			s.sendExitStatus(channel, 1)
			return
		}
		parts := strings.SplitN(strings.TrimSuffix(string(input), "\n"), ":", 2)
		s.mu.Lock()
		resetUser := s.resetUser
		s.mu.Unlock()
		if len(parts) != 2 || parts[0] != "rotation" && parts[0] != resetUser {
			s.sendExitStatus(channel, 1)
			return
		}
		s.mu.Lock()
		if parts[0] == "rotation" {
			s.password = parts[1]
		}
		s.stdin = string(input)
		s.mu.Unlock()
		s.sendExitStatus(channel, 0)
		return
	}
}

func (s *rotationTestServer) sendExitStatus(channel xssh.Channel, status uint32) {
	_, _ = channel.SendRequest("exit-status", false, xssh.Marshal(struct{ Status uint32 }{Status: status}))
}

func containsCommand(commands []string, expected string) bool {
	for _, command := range commands {
		if command == expected {
			return true
		}
	}
	return false
}
