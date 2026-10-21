package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/config"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestNativeSSHNodeRestartPreservesDefaultAccountVaultAndFingerprint(t *testing.T) {
	data := t.TempDir()
	httpAddr, sshAddr := freeAddress(t), freeAddress(t)
	cfg := &config.Config{Addr: httpAddr, SSHAddr: sshAddr, DataDir: data, DefaultAdminEnabled: true, MonitorInterval: time.Hour, ShutdownTimeout: time.Second}
	var previousFingerprint string
	var previousKey []byte
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- runNode(ctx, cfg, nil) }()
		waitForHTTPStatus(t, "http://"+httpAddr+"/api/health", 200, 10*time.Second)
		fingerprint := ""
		var client *ssh.Client
		require.Eventually(t, func() bool {
			var e error
			client, e = ssh.Dial("tcp", sshAddr, &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.Password("root")}, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
				fingerprint = ssh.FingerprintSHA256(key)
				return nil
			}, Timeout: time.Second})
			return e == nil
		}, 10*time.Second, 20*time.Millisecond)
		files, e := sftp.NewClient(client)
		require.NoError(t, e)
		rows, e := files.ReadDir("/")
		require.NoError(t, e)
		require.Empty(t, rows)
		_ = files.Close()
		_ = client.Close()
		key, e := os.ReadFile(filepath.Join(data, "vault.key"))
		require.NoError(t, e)
		var response map[string]any
		raw := orgHTTP(t, httpAddr, "POST", "/api/v1/authentication/auth/", "", "", map[string]string{"username": "root", "password": "root"}, 200)
		require.NoError(t, json.Unmarshal(raw, &response))
		if attempt > 0 {
			require.Equal(t, previousFingerprint, fingerprint)
			require.Equal(t, previousKey, key)
		}
		previousFingerprint = fingerprint
		previousKey = key
		cancel()
		select {
		case e := <-done:
			require.NoError(t, e)
		case <-time.After(10 * time.Second):
			t.Fatal("native listener shutdown timed out")
		}
		probe, e := net.Listen("tcp", sshAddr)
		require.NoError(t, e)
		_ = probe.Close()
	}
}
