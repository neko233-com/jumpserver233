package config

import (
	"encoding/base64"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"
)

func TestFromEnvUsesLoopbackStandaloneDefaults(t *testing.T) {
	clearConfigEnv(t)
	cfg, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != "127.0.0.1:8080" {
		t.Errorf("Addr = %q, want 127.0.0.1:8080", cfg.Addr)
	}
	if cfg.MonitorInterval != time.Minute {
		t.Errorf("MonitorInterval = %s, want 1m", cfg.MonitorInterval)
	}
	if cfg.DataDir == "" {
		t.Error("DataDir is empty")
	}
	require.True(t, cfg.DefaultAdminEnabled)
}

func TestDefaultAdministratorCanBeExplicitlyDisabled(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("JMS_DEFAULT_ADMIN_ENABLED", "false")
	cfg, e := FromEnv()
	require.NoError(t, e)
	require.False(t, cfg.DefaultAdminEnabled)
	t.Setenv("JMS_DEFAULT_ADMIN_ENABLED", "invalid")
	_, e = FromEnv()
	require.Error(t, e)
}

func TestTrustedProxyCIDRsRequireExplicitValidConfiguration(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("JMS_TRUSTED_PROXIES", "10.0.0.1/8,2001:db8::/32")
	cfg, e := FromEnv()
	require.NoError(t, e)
	require.Equal(t, []string{"10.0.0.0/8", "2001:db8::/32"}, cfg.TrustedProxies)
	for _, value := range []string{"*", "127.0.0.1", "localhost/32", "::ffff:192.0.2.0/120", "10.0.0.0/8,"} {
		t.Setenv("JMS_TRUSTED_PROXIES", value)
		_, e := FromEnv()
		require.Error(t, e, value)
	}
}

func TestFromEnvRequiresStrongTokenForExposedListener(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("JMS_ADDR", "0.0.0.0:8080")
	if _, err := FromEnv(); err == nil {
		t.Fatal("FromEnv() allowed a remote listener without an admin token")
	}
	t.Setenv("JMS_ADMIN_TOKEN", "too-short")
	if _, err := FromEnv(); err == nil {
		t.Fatal("FromEnv() accepted a short admin token")
	}
	t.Setenv("JMS_ADMIN_TOKEN", "0123456789abcdef0123456789abcdef")
	if _, err := FromEnv(); err != nil {
		t.Fatalf("FromEnv() rejected a 32-byte token: %v", err)
	}
}

func TestFromEnvValidatesMonitorInterval(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("JMS_MONITOR_INTERVAL", "5s")
	if _, err := FromEnv(); err == nil {
		t.Fatal("FromEnv() accepted an interval below 15 seconds")
	}
	t.Setenv("JMS_MONITOR_INTERVAL", "2m")
	cfg, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MonitorInterval != 2*time.Minute {
		t.Errorf("MonitorInterval = %s, want 2m", cfg.MonitorInterval)
	}
}

func TestFromEnvValidatesActiveStandbyClusterRequirements(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("JMS_CLUSTER_MODE", "true")
	t.Setenv("JMS_ADDR", "0.0.0.0:8080")
	t.Setenv("JMS_ADMIN_TOKEN", "0123456789abcdef0123456789abcdef")
	if _, err := FromEnv(); err == nil {
		t.Fatal("FromEnv() allowed cluster mode without a database, shared data directory, and vault key")
	}

	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	t.Setenv("JMS_DATABASE_URL", "postgres://jms:secret@postgres:5432/jms?sslmode=disable")
	t.Setenv("JMS_DATA_DIR", "/srv/jumpserver233/shared")
	t.Setenv("JMS_VAULT_KEY", key)
	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv() rejected valid active/standby settings: %v", err)
	}
	if !cfg.ClusterMode || cfg.ClusterID != "jumpserver233" || cfg.ClusterHealthAddr != "0.0.0.0:8081" {
		t.Fatalf("cluster config = %+v", cfg)
	}
}

func TestFromEnvRejectsInvalidClusterModeAndEmptyClusterID(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("JMS_CLUSTER_MODE", "sometimes")
	if _, err := FromEnv(); err == nil {
		t.Fatal("FromEnv() accepted an invalid JMS_CLUSTER_MODE value")
	}

	clearConfigEnv(t)
	t.Setenv("JMS_CLUSTER_MODE", "true")
	t.Setenv("JMS_ADDR", "0.0.0.0:8080")
	t.Setenv("JMS_ADMIN_TOKEN", "0123456789abcdef0123456789abcdef")
	t.Setenv("JMS_DATABASE_URL", "postgres://postgres@127.0.0.1:5432/jms")
	t.Setenv("JMS_DATA_DIR", "shared")
	t.Setenv("JMS_VAULT_KEY", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	t.Setenv("JMS_CLUSTER_ID", "   ")
	if _, err := FromEnv(); err == nil {
		t.Fatal("FromEnv() accepted a blank JMS_CLUSTER_ID")
	}
}

func clearConfigEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{"JMS_SSH_ADDR", "JMS_ADDR", "JMS_WEB_DIR", "JMS_VERSION", "JMS_DATA_DIR", "JMS_VAULT_KEY", "JMS_ADMIN_TOKEN", "JMS_MONITOR_INTERVAL", "JMS_CLUSTER_MODE", "JMS_DATABASE_URL", "JMS_CLUSTER_ID", "JMS_CLUSTER_HEALTH_ADDR", "JMS_PUBLIC_URL", "JMS_TRUSTED_PROXIES", "JMS_DEFAULT_ADMIN_ENABLED"} {
		value, existed := os.LookupEnv(name)
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if existed {
				_ = os.Setenv(name, value)
			} else {
				_ = os.Unsetenv(name)
			}
		})
	}
}

func TestPublicURLIsExplicitHTTPSOrLocalIPOrigin(t *testing.T) {
	clearConfigEnv(t)
	for _, value := range []string{"https://console.example.invalid", "http://localhost:15178", "http://127.0.0.1:5177", "http://[::1]:5177", "http://10.12.0.5:8180", "http://[fd00::5]:8180"} {
		t.Setenv("JMS_PUBLIC_URL", value)
		c, err := FromEnv()
		require.NoError(t, err)
		require.Equal(t, value, c.PublicURL)
	}
	for _, value := range []string{"http://console.example.invalid", "https://user:secret@console.example.invalid", "https://console.example.invalid/path", "https://console.example.invalid?bad=1", "http://8.8.8.8", "http://0.0.0.0:8180", "http://10.12.0.5:65536", "https://console.example.invalid?"} {
		t.Setenv("JMS_PUBLIC_URL", value)
		_, err := FromEnv()
		require.Error(t, err)
	}
}
