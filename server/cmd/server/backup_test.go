package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/config"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/maintenance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStandaloneBackupStopsConcurrentWritersRestoresHTTPIdentityAndRealSSH(t *testing.T) {
	parent := t.TempDir()
	data := filepath.Join(parent, "data")
	address := freeAddress(t)
	cfg := &config.Config{Addr: address, PublicURL: "http://" + address, DataDir: data, DefaultAdminEnabled: true, MonitorInterval: time.Hour, ShutdownTimeout: time.Second, Version: "backup-test"}
	var cancel context.CancelFunc
	var done chan error
	start := func() {
		ctx, c := context.WithCancel(context.Background())
		cancel = c
		done = make(chan error, 1)
		go func() { done <- runNode(ctx, cfg, nil) }()
		waitForHTTPStatus(t, "http://"+cfg.Addr+"/api/health", 200, 10*time.Second)
	}
	stop := func() {
		if cancel == nil {
			return
		}
		cancel()
		select {
		case e := <-done:
			require.NoError(t, e)
		case <-time.After(15 * time.Second):
			t.Fatal("backup fixture server did not stop")
		}
		cancel = nil
	}
	t.Cleanup(stop)
	start()
	login := func() auth.LoginSession {
		var l auth.LoginSession
		require.NoError(t, json.Unmarshal(orgHTTP(t, cfg.Addr, "POST", "/api/v1/authentication/auth/", "", "", map[string]string{"username": "root", "password": "root"}, 200), &l))
		return l
	}
	old := login()
	options := maintenance.Options{DataDir: data, File: filepath.Join(parent, "backup.jmsbackup"), Version: "backup-test", Passphrase: []byte("synthetic-server-backup-password")}
	_, e := maintenance.Create(context.Background(), options)
	assert.ErrorIs(t, e, maintenance.ErrBusy)
	duplicate := *cfg
	duplicate.Addr = freeAddress(t)
	assert.ErrorIs(t, runNode(context.Background(), &duplicate, nil), maintenance.ErrBusy)
	var asset assets.Asset
	realSSH := os.Getenv("JMS_TEST_KEY_HOST_ADDR") != ""
	if realSSH {
		require.True(t, strings.HasPrefix(os.Getenv("JMS_TEST_KEY_HOST_NAME"), "jms233-keyhost-"))
		host, portText, e := net.SplitHostPort(os.Getenv("JMS_TEST_KEY_HOST_ADDR"))
		require.NoError(t, e)
		port, e := strconv.Atoi(portText)
		require.NoError(t, e)
		in := assets.Input{Name: "Backup real SSH", Host: host, Port: port, Username: "keyqa", Protocol: "ssh", Password: "synthetic-keyhost-password-233", HostKeyFingerprint: os.Getenv("JMS_TEST_KEY_HOST_FINGERPRINT")}
		require.NoError(t, json.Unmarshal(orgHTTP(t, cfg.Addr, "POST", "/api/v1/assets", old.AccessToken, "", in, 201), &asset))
	}
	execSSH := func(token string) {
		if !realSSH {
			return
		}
		var job jobs.Job
		require.NoError(t, json.Unmarshal(orgHTTP(t, cfg.Addr, "POST", "/api/v1/ops/jobs", token, "", map[string]any{"asset_id": asset.ID, "command": "printf backup-restored-ssh-ok", "timeout_seconds": 10, "request_id": strconv.FormatInt(time.Now().UnixNano(), 10)}, 201), &job))
		require.Eventually(t, func() bool {
			var current jobs.Job
			raw := orgHTTP(t, cfg.Addr, "GET", "/api/v1/ops/jobs/"+job.ID, token, "", nil, 200)
			if json.Unmarshal(raw, &current) != nil {
				return false
			}
			return current.State == "succeeded" && current.Stdout == "backup-restored-ssh-ok"
		}, 15*time.Second, 50*time.Millisecond)
	}
	execSSH(old.AccessToken)
	stop()
	created, e := maintenance.Create(context.Background(), options)
	require.NoError(t, e)
	verified, e := maintenance.Verify(context.Background(), options)
	require.NoError(t, e)
	assert.Equal(t, created, verified)
	options.DataDir = filepath.Join(parent, "restored")
	_, e = maintenance.Restore(context.Background(), options)
	require.NoError(t, e)
	// Existing encrypted bytes and stable IDs survive; no default identity reset.
	original, e := os.ReadFile(filepath.Join(data, "users.json"))
	require.NoError(t, e)
	copy, e := os.ReadFile(filepath.Join(options.DataDir, "users.json"))
	require.NoError(t, e)
	assert.True(t, bytes.Equal(original, copy))
	cfg.DataDir = options.DataDir
	cfg.Addr = freeAddress(t)
	cfg.PublicURL = "http://" + cfg.Addr
	start()
	restored := login()
	assert.Equal(t, old.User.ID, restored.User.ID)
	execSSH(restored.AccessToken)
	if !realSSH {
		t.Log("HTTP/identity recovery verified; real SSH skipped without the disposable OpenSSH fixture")
	}
	stop()
	_, e = maintenance.Restore(context.Background(), options)
	require.NoError(t, e)
}
