package sshclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshidentity"
	"io"
	"net"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"
)

func TestOpenShellStartsPinnedPTYAndResizes(t *testing.T) {
	for _, hops := range []int{0, 2} {
		t.Run(fmt.Sprintf("gateways-%d", hops), func(t *testing.T) { testPinnedShell(t, hops, false) })
	}
	t.Run("private-key-gateway", func(t *testing.T) { testPinnedShell(t, 2, true) })
}
func testPinnedShell(t *testing.T, hops int, key bool) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := xssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	config := &xssh.ServerConfig{PasswordCallback: func(metadata xssh.ConnMetadata, password []byte) (*xssh.Permissions, error) {
		if metadata.User() != "ops" || string(password) != "secret" {
			return nil, xssh.ErrNoAuth
		}
		return nil, nil
	}}
	config.PublicKeyCallback = sshidentity.PublicKeyCallback("ops")
	config.AddHostKey(signer)
	sizeChanges := make(chan [2]uint32, 1)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		serverConnection, channels, requests, err := xssh.NewServerConn(connection, config)
		if err != nil {
			return
		}
		go xssh.DiscardRequests(requests)
		for incoming := range channels {
			if incoming.ChannelType() != "session" {
				_ = incoming.Reject(xssh.UnknownChannelType, "unsupported")
				continue
			}
			channel, channelRequests, err := incoming.Accept()
			if err != nil {
				continue
			}
			go func() {
				for request := range channelRequests {
					switch request.Type {
					case "pty-req":
						request.Reply(true, nil)
					case "shell":
						request.Reply(true, nil)
						_, _ = channel.Write([]byte("ready\r\n"))
						go func() {
							_, _ = io.Copy(channel, channel)
							_, _ = channel.SendRequest("exit-status", false, xssh.Marshal(struct{ Status uint32 }{0}))
							_ = channel.Close()
						}()
					case "window-change":
						var dimensions struct {
							Columns uint32
							Rows    uint32
							Width   uint32
							Height  uint32
						}
						if xssh.Unmarshal(request.Payload, &dimensions) == nil {
							sizeChanges <- [2]uint32{dimensions.Columns, dimensions.Rows}
						}
						request.Reply(true, nil)
					default:
						request.Reply(false, nil)
					}
				}
			}()
		}
		_ = serverConnection.Close()
	}()

	address := listener.Addr().(*net.TCPAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	target := Target{
		Host:               "127.0.0.1",
		Port:               address.Port,
		Username:           "ops",
		HostKeyFingerprint: xssh.FingerprintSHA256(signer.PublicKey()),
	}
	if hops > 0 {
		target, _ = routedTarget(t, target, hops)
	}
	credentials := Credentials{Password: "secret"}
	if key {
		credentials = Credentials{PrivateKey: sshidentity.PEM("")}
	}
	shell, err := OpenShell(ctx, target, credentials, 3*time.Second, 80, 24)
	if err != nil {
		t.Fatalf("OpenShell() error = %v", err)
	}
	defer shell.Close()

	ready := make([]byte, len("ready\r\n"))
	if _, err := io.ReadFull(shell, ready); err != nil {
		t.Fatalf("read shell banner: %v", err)
	}
	if string(ready) != "ready\r\n" {
		t.Fatalf("shell banner = %q", ready)
	}
	if _, err := shell.Write([]byte("hello\n")); err != nil {
		t.Fatalf("write to shell: %v", err)
	}
	echo := make([]byte, len("hello\n"))
	if _, err := io.ReadFull(shell, echo); err != nil {
		t.Fatalf("read shell echo: %v", err)
	}
	if string(echo) != "hello\n" {
		t.Fatalf("shell echo = %q", echo)
	}
	if err := shell.Resize(100, 30); err != nil {
		t.Fatalf("resize shell: %v", err)
	}
	select {
	case got := <-sizeChanges:
		if got != [2]uint32{100, 30} {
			t.Fatalf("PTY size = %v, want [100 30]", got)
		}
	case <-ctx.Done():
		t.Fatal("server did not receive PTY resize")
	}
	_ = shell.Close()
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("SSH test server did not stop")
	}
}
