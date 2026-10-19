package sshclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshidentity"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xssh "golang.org/x/crypto/ssh"
)

func TestOpenSFTPUsesPinnedSSHAndSupportsFileOperations(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "existing.txt"), []byte("existing data"), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, target := startSFTPTestServer(t, root)
	defer listener.Close()

	remote, err := OpenSFTP(context.Background(), target, Credentials{Password: "sftp-test-password"}, 2*time.Second)
	if err != nil {
		t.Fatalf("OpenSFTP() error = %v", err)
	}
	defer remote.Close()
	if remote.Root() == "" || remote.Root()[0] != '/' {
		t.Fatalf("SFTP root = %q, want an absolute POSIX path", remote.Root())
	}

	entries, err := remote.ReadDir(context.Background(), remote.Root())
	if err != nil || len(entries) != 1 || entries[0].Name != "existing.txt" {
		t.Fatalf("ReadDir() = %+v, %v", entries, err)
	}
	content, err := remote.OpenRead(context.Background(), path.Join(remote.Root(), "existing.txt"))
	if err != nil {
		t.Fatal(err)
	}
	readBuffer := make([]byte, 32)
	n, readErr := content.Read(readBuffer)
	if readErr != nil && readErr.Error() != "EOF" {
		t.Fatalf("read remote file: %v", readErr)
	}
	if string(readBuffer[:n]) != "existing data" {
		t.Fatalf("remote file content = %q", readBuffer[:n])
	}
	if err := content.Close(); err != nil {
		t.Fatal(err)
	}

	newPath := path.Join(remote.Root(), "created.txt")
	created, err := remote.CreateExclusive(context.Background(), newPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := created.Write([]byte("uploaded data")); err != nil {
		t.Fatal(err)
	}
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := remote.Lstat(context.Background(), newPath)
	if err != nil || info.Size != int64(len("uploaded data")) || !info.IsRegular {
		t.Fatalf("Lstat() = %+v, %v", info, err)
	}
	if err := remote.Mkdir(context.Background(), path.Join(remote.Root(), "folder")); err != nil {
		t.Fatal(err)
	}
	if err := remote.Remove(context.Background(), newPath); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceSFTPExecChannelIsPinnedAndNeverFallsBack(t *testing.T) {
	listener, target := startSFTPTestServer(t, t.TempDir(), "pinned-workspace-helper")
	defer listener.Close()
	remote, e := OpenSFTPCommand(context.Background(), target, Credentials{Password: "sftp-test-password"}, 2*time.Second, "pinned-workspace-helper")
	require.NoError(t, e)
	_, e = remote.ReadDir(context.Background(), remote.Root())
	require.NoError(t, e)
	_ = remote.Close()
	_ = remote.Close()
	_, e = OpenSFTPCommand(context.Background(), target, Credentials{Password: "sftp-test-password"}, 2*time.Second, "wrong-helper")
	require.Error(t, e)
	_, e = OpenSFTPCommand(context.Background(), target, Credentials{Password: "sftp-test-password"}, 2*time.Second, "")
	require.Error(t, e)
	ordinary, normalTarget := startSFTPTestServer(t, t.TempDir())
	defer ordinary.Close()
	_, e = OpenSFTPCommand(context.Background(), normalTarget, Credentials{Password: "sftp-test-password"}, 2*time.Second, "pinned-workspace-helper")
	require.Error(t, e)
	stalled, stallTarget := startSFTPTestServer(t, t.TempDir(), "stall")
	defer stalled.Close()
	start := time.Now()
	_, e = OpenSFTPCommand(context.Background(), stallTarget, Credentials{Password: "sftp-test-password"}, 100*time.Millisecond, "stall")
	require.Error(t, e)
	assert.Less(t, time.Since(start), 2*time.Second)
}

func startSFTPTestServer(t *testing.T, root string, startup ...string) (net.Listener, Target) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := xssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	config := &xssh.ServerConfig{PasswordCallback: func(metadata xssh.ConnMetadata, password []byte) (*xssh.Permissions, error) {
		if metadata.User() != "sftp-test" || string(password) != "sftp-test-password" {
			return nil, xssh.ErrNoAuth
		}
		return nil, nil
	}}
	config.PublicKeyCallback = sshidentity.PublicKeyCallback("sftp-test")
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go serveSFTPTestConnection(connection, config, root, startup...)
		}
	}()
	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return listener, Target{Host: host, Port: port, Username: "sftp-test", HostKeyFingerprint: xssh.FingerprintSHA256(signer.PublicKey())}
}

func serveSFTPTestConnection(connection net.Conn, config *xssh.ServerConfig, root string, startup ...string) {
	serverConnection, channels, requests, err := xssh.NewServerConn(connection, config)
	if err != nil {
		_ = connection.Close()
		return
	}
	go xssh.DiscardRequests(requests)
	defer serverConnection.Close()
	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(xssh.UnknownChannelType, "unsupported channel")
			continue
		}
		channel, channelRequests, acceptErr := newChannel.Accept()
		if acceptErr != nil {
			continue
		}
		go func() {
			defer channel.Close()
			for request := range channelRequests {
				kind, want := "subsystem", "sftp"
				if len(startup) > 0 {
					kind, want = "exec", startup[0]
				}
				if request.Type != kind {
					_ = request.Reply(false, nil)
					continue
				}
				var payload struct{ Name string }
				if err := xssh.Unmarshal(request.Payload, &payload); err != nil || payload.Name != want {
					_ = request.Reply(false, nil)
					return
				}
				if err := request.Reply(true, nil); err != nil {
					return
				}
				if want == "stall" {
					_, _ = io.Copy(io.Discard, channel)
					return
				}
				server, err := sftp.NewServer(channel, sftp.WithServerWorkingDirectory(root))
				if err != nil {
					return
				}
				if err := server.Serve(); err != nil {
					_ = server.Close()
					return
				}
				_ = server.Close()
				return
			}
		}()
	}
}
