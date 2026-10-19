package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/config"
	"github.com/neko233-com/jumpserver233/server/internal/maintenance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGatedStartupServesOnlyHealthAndIndexUntilLocalActivation(t *testing.T) {
	data, web := t.TempDir(), t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(web, "index.html"), []byte("<html>JumpServer233 activation</html>"), 0600))
	cfg := &config.Config{Addr: "127.0.0.1:0", DataDir: data, WebDir: web, CheckData: true, DefaultAdminEnabled: true, Version: "v1.2.3", MonitorInterval: time.Hour}
	require.NoError(t, runNode(context.Background(), cfg, nil))
	cfg.CheckData = false
	lock, e := maintenance.Acquire(data)
	require.NoError(t, e)
	sha, e := maintenance.ExecutableSHA256()
	require.NoError(t, e)
	g := maintenance.UpgradeGuard{Schema: 1, RootID: strings.Repeat("a", 32), ID: strings.Repeat("b", 32), Attempt: strings.Repeat("c", 32), BinarySHA256: sha, Phase: "trial"}
	require.NoError(t, maintenance.SetUpgradeGuard(lock, g))
	require.NoError(t, lock.Close())
	cfg.ActivationID = g.ID
	cfg.ActivationAttempt = g.Attempt
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runNode(ctx, cfg, nil) }()
	t.Cleanup(func() {
		cancel()
		select {
		case e := <-done:
			assert.NoError(t, e)
		case <-time.After(15 * time.Second):
			t.Error("gated node did not stop")
		}
	})
	var record maintenance.ActivationRecord
	require.Eventually(t, func() bool {
		r, e := maintenance.ReadActivation(data)
		if e == nil {
			record = r
		}
		return e == nil
	}, 10*time.Second, 20*time.Millisecond)
	get := func(method, path string) *http.Response {
		t.Helper()
		request, e := http.NewRequest(method, "http://"+record.Address+path, nil)
		require.NoError(t, e)
		response, e := (&http.Client{Timeout: time.Second}).Do(request)
		require.NoError(t, e)
		return response
	}
	for _, path := range []string{"/api/health", "/"} {
		response := get("GET", path)
		assert.Equal(t, 200, response.StatusCode)
		assert.Equal(t, g.Attempt, response.Header.Get("X-JMS-Activation"))
		assert.Equal(t, "trial", response.Header.Get("X-JMS-Activation-Phase"))
		assert.Equal(t, "no-store", response.Header.Get("Cache-Control"))
		response.Body.Close()
	}
	for _, path := range []string{"/api/v1/assets", "/ws", "/login", "/assets/example.js"} {
		response := get("GET", path)
		assert.Equal(t, 503, response.StatusCode)
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		assert.Contains(t, string(body), "upgrade_activation_pending")
	}
	response := get("POST", "/api/v1/authentication/auth/")
	assert.Equal(t, 503, response.StatusCode)
	response.Body.Close()
	require.NoError(t, maintenance.ReleaseActivation(data, record))
	require.Eventually(t, func() bool {
		r, e := maintenance.ReadActivation(data)
		if e != nil || r.Phase != "active" {
			return false
		}
		response := get("GET", "/api/health")
		defer response.Body.Close()
		return response.Header.Get("X-JMS-Activation-Phase") == "active"
	}, 10*time.Second, 20*time.Millisecond)
	response = get("GET", "/api/health")
	assert.Equal(t, "active", response.Header.Get("X-JMS-Activation-Phase"))
	response.Body.Close()
	response = get("GET", "/api/v1/assets")
	assert.Equal(t, 401, response.StatusCode)
	response.Body.Close()
	response = get("GET", "/login")
	assert.Equal(t, 200, response.StatusCode)
	response.Body.Close()
}
