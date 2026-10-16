package main

import (
	"context"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/config"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestDefaultAdministratorUsesNormalHTTPAuthentication(t *testing.T) {
	addr := freeAddress(t)
	cfg := &config.Config{Addr: addr, PublicURL: "http://" + addr, DataDir: t.TempDir(), DefaultAdminEnabled: true, MonitorInterval: time.Hour, ShutdownTimeout: time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runNode(ctx, cfg, nil) }()
	t.Cleanup(func() {
		cancel()
		select {
		case e := <-done:
			require.NoError(t, e)
		case <-time.After(10 * time.Second):
			t.Error("default account server did not stop")
		}
	})
	waitForHTTPStatus(t, "http://"+addr+"/api/health", 200, 10*time.Second)
	var login coreauth.LoginSession
	raw := orgHTTP(t, addr, "POST", "/api/v1/authentication/auth/", "", "", map[string]string{"username": "root", "password": "root"}, 200)
	require.NoError(t, json.Unmarshal(raw, &login))
	require.Equal(t, "root", login.User.Username)
	require.Equal(t, coreauth.RoleAdmin, login.User.Role)
	require.Contains(t, string(orgHTTP(t, addr, "GET", "/api/v1/users/me", login.AccessToken, "", nil, 200)), `"username":"root"`)
	orgHTTP(t, addr, "POST", "/api/v1/authentication/bootstrap", "", "", map[string]string{"username": "another", "password": "synthetic-another-password"}, 409)
}
