package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/config"
	"github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
	"github.com/neko233-com/jumpserver233/server/internal/maintenance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOfflinePreflightLoadsOrganizationStoresWithoutListeningAndHonorsUpgradeGuard(t *testing.T) {
	data := t.TempDir()
	addr := freeAddress(t)
	cfg := &config.Config{Addr: addr, PublicURL: "http://" + addr, DataDir: data, DefaultAdminEnabled: true, MonitorInterval: time.Hour, ShutdownTimeout: time.Second, Version: "preflight-test"}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runNode(ctx, cfg, nil) }()
	t.Cleanup(func() { cancel() })
	waitForHTTPStatus(t, "http://"+addr+"/api/health", 200, 10*time.Second)
	var login auth.LoginSession
	require.NoError(t, json.Unmarshal(orgHTTP(t, addr, "POST", "/api/v1/authentication/auth/", "", "", map[string]string{"username": "root", "password": "root"}, 200), &login))
	var org organizations.Organization
	require.NoError(t, json.Unmarshal(orgHTTP(t, addr, "POST", "/api/v1/organizations", login.AccessToken, "", organizations.Input{Name: "Offline organization", Enabled: true}, 201), &org))
	cancel()
	require.NoError(t, <-done)
	// A listener occupying the configured port proves that preflight never binds it.
	listener, e := net.Listen("tcp", addr)
	require.NoError(t, e)
	defer listener.Close()
	cfg.CheckData = true
	require.NoError(t, runNode(context.Background(), cfg, nil))
	users, e := os.ReadFile(filepath.Join(data, "users.json"))
	require.NoError(t, e)
	lock, e := maintenance.Acquire(data)
	require.NoError(t, e)
	binary, e := maintenance.ExecutableSHA256()
	require.NoError(t, e)
	g := maintenance.UpgradeGuard{Schema: 1, RootID: strings.Repeat("a", 32), ID: strings.Repeat("b", 32), BinarySHA256: binary, Phase: "pending"}
	require.NoError(t, maintenance.SetUpgradeGuard(lock, g))
	require.NoError(t, lock.Close())
	assert.ErrorIs(t, runNode(context.Background(), cfg, nil), maintenance.ErrUpgradePending)
	cfg.UpgradeID = g.ID
	require.NoError(t, runNode(context.Background(), cfg, nil))
	current, e := os.ReadFile(filepath.Join(data, "users.json"))
	require.NoError(t, e)
	assert.Equal(t, users, current)
	// Active non-default stores are validated too, without starting schedulers.
	require.NoError(t, os.WriteFile(filepath.Join(data, "organizations", org.ID, "operations.json"), []byte("invalid target-format store"), 0600))
	assert.Error(t, runNode(context.Background(), cfg, nil))
	cfg.ClusterMode = true
	assert.ErrorIs(t, runNode(context.Background(), cfg, nil), maintenance.ErrCluster)
}
