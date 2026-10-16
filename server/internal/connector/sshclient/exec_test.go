package sshclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xssh "golang.org/x/crypto/ssh"
)

func TestExecCapturesStreamsExitStatusLimitAndCancellation(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := xssh.NewSignerFromKey(private)
	require.NoError(t, err)
	config := &xssh.ServerConfig{PasswordCallback: func(meta xssh.ConnMetadata, password []byte) (*xssh.Permissions, error) {
		if meta.User() != "ops" || string(password) != "test-only" {
			return nil, xssh.ErrNoAuth
		}
		return nil, nil
	}}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				server, channels, requests, err := xssh.NewServerConn(connection, config)
				if err != nil {
					_ = connection.Close()
					return
				}
				defer server.Close()
				go xssh.DiscardRequests(requests)
				for pending := range channels {
					stream, requests, err := pending.Accept()
					if err != nil {
						continue
					}
					go func() {
						defer stream.Close()
						for req := range requests {
							var input struct{ Command string }
							if req.Type != "exec" || xssh.Unmarshal(req.Payload, &input) != nil {
								_ = req.Reply(false, nil)
								continue
							}
							_ = req.Reply(true, nil)
							if input.Command == "stall" {
								for range requests {
								}
								return
							}
							status := uint32(7)
							if input.Command == "large" {
								_, _ = stream.Write([]byte(strings.Repeat("x", MaxExecOutput+100)))
								status = 0
							} else {
								_, _ = stream.Write([]byte("hello\n"))
								_, _ = stream.Stderr().Write([]byte("failure\n"))
							}
							_, _ = stream.SendRequest("exit-status", false, xssh.Marshal(struct{ Status uint32 }{status}))
							return
						}
					}()
				}
			}()
		}
	}()
	host, portText, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portText)
	require.NoError(t, err)
	target := Target{Host: host, Port: port, Username: "ops", HostKeyFingerprint: xssh.FingerprintSHA256(signer.PublicKey())}
	credentials := Credentials{Password: "test-only"}
	result, err := Exec(context.Background(), target, credentials, "exit7")
	require.NoError(t, err)
	assert.Equal(t, "hello\n", result.Stdout)
	assert.Equal(t, "failure\n", result.Stderr)
	assert.Equal(t, 7, result.ExitCode)
	result, err = Exec(context.Background(), target, credentials, "large")
	require.NoError(t, err)
	assert.True(t, result.Truncated)
	assert.Len(t, result.Stdout, MaxExecOutput)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = Exec(ctx, target, credentials, "stall")
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	target.HostKeyFingerprint = "SHA256:wrong"
	_, err = Exec(context.Background(), target, credentials, "exit7")
	require.Error(t, err)
}
