package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config holds process-level settings loaded from the environment.
type Config struct {
	// Addr is the HTTP listen address, e.g. ":8080".
	Addr string
	// Version is reported by the health endpoint.
	Version string
	// ShutdownTimeout bounds graceful shutdown.
	ShutdownTimeout time.Duration
	// DataDir contains the encrypted standalone inventory and vault key.
	DataDir string
	// WebDir optionally serves a production frontend on the API listener.
	WebDir string
	// VaultKey is optional base64-encoded 32-byte key material for shared deployments.
	VaultKey string
	// AdminToken protects inventory APIs when the listener is exposed beyond loopback.
	AdminToken          string
	DefaultAdminEnabled bool
	// MonitorInterval controls how often SSH host metrics are collected.
	MonitorInterval time.Duration
	// ClusterMode enables PostgreSQL-coordinated active/standby operation.
	ClusterMode bool
	// DatabaseURL connects to the shared PostgreSQL database used for leader election.
	DatabaseURL string
	// ClusterID identifies the application cluster's advisory lock.
	ClusterID string
	// ClusterHealthAddr serves liveness and readiness probes on every node.
	ClusterHealthAddr string
	PublicURL         string
	TrustedProxies    []string
}

// FromEnv builds a Config from environment variables with safe defaults.
func FromEnv() (*Config, error) {
	userConfigDir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("resolve user config directory: %w", err)
	}
	cfg := &Config{
		Addr:            getEnv("JMS_ADDR", "127.0.0.1:8080"),
		Version:         getEnv("JMS_VERSION", "dev"),
		ShutdownTimeout: 10 * time.Second,
		DataDir:         getEnv("JMS_DATA_DIR", filepath.Join(userConfigDir, "JumpServer233")),
		WebDir:          strings.TrimSpace(getEnv("JMS_WEB_DIR", "")),
		VaultKey:        getEnv("JMS_VAULT_KEY", ""),
		AdminToken:      getEnv("JMS_ADMIN_TOKEN", ""),
		MonitorInterval: time.Minute,
		ClusterID:       strings.TrimSpace(getEnv("JMS_CLUSTER_ID", "jumpserver233")),
	}
	if cfg.Addr == "" {
		return nil, fmt.Errorf("JMS_ADDR must not be empty")
	}
	cfg.DefaultAdminEnabled, err = parseBoolEnv("JMS_DEFAULT_ADMIN_ENABLED", true)
	if err != nil {
		return nil, err
	}
	if value := strings.TrimSpace(getEnv("JMS_TRUSTED_PROXIES", "")); value != "" {
		for _, raw := range strings.Split(value, ",") {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
			if err != nil || prefix.Addr().Is4In6() || len(cfg.TrustedProxies) >= 32 {
				return nil, fmt.Errorf("JMS_TRUSTED_PROXIES requires up to 32 IPv4/IPv6 CIDRs")
			}
			cfg.TrustedProxies = append(cfg.TrustedProxies, prefix.Masked().String())
		}
	}
	if value := strings.TrimRight(strings.TrimSpace(getEnv("JMS_PUBLIC_URL", "")), "/"); value != "" {
		u, err := url.Parse(value)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || (u.Scheme != "https" && (u.Scheme != "http" || u.Hostname() != "localhost" && (net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback()))) {
			return nil, fmt.Errorf("JMS_PUBLIC_URL must be an HTTPS origin or an HTTP loopback origin")
		}
		cfg.PublicURL = u.String()
	}
	if cfg.DataDir == "" {
		return nil, fmt.Errorf("JMS_DATA_DIR must not be empty")
	}
	if interval := getEnv("JMS_MONITOR_INTERVAL", ""); interval != "" {
		parsed, err := time.ParseDuration(interval)
		if err != nil || parsed < 15*time.Second {
			return nil, fmt.Errorf("JMS_MONITOR_INTERVAL must be at least 15s")
		}
		cfg.MonitorInterval = parsed
	}
	if cfg.AdminToken != "" && len(cfg.AdminToken) < 32 {
		return nil, fmt.Errorf("JMS_ADMIN_TOKEN must contain at least 32 bytes")
	}
	if !isLoopbackAddress(cfg.Addr) && cfg.AdminToken == "" {
		return nil, fmt.Errorf("JMS_ADMIN_TOKEN is required when JMS_ADDR is not loopback")
	}
	clusterMode, err := parseBoolEnv("JMS_CLUSTER_MODE", false)
	if err != nil {
		return nil, err
	}
	cfg.ClusterMode = clusterMode
	cfg.DatabaseURL = strings.TrimSpace(getEnv("JMS_DATABASE_URL", ""))
	cfg.ClusterHealthAddr = getEnv("JMS_CLUSTER_HEALTH_ADDR", "0.0.0.0:8081")
	if cfg.ClusterMode {
		if isLoopbackAddress(cfg.Addr) {
			return nil, fmt.Errorf("JMS_ADDR must be reachable by the cluster load balancer when JMS_CLUSTER_MODE is enabled")
		}
		if cfg.DatabaseURL == "" {
			return nil, fmt.Errorf("JMS_DATABASE_URL is required when JMS_CLUSTER_MODE is enabled")
		}
		if cfg.VaultKey == "" {
			return nil, fmt.Errorf("JMS_VAULT_KEY is required when JMS_CLUSTER_MODE is enabled")
		}
		decodedKey, err := base64.StdEncoding.DecodeString(cfg.VaultKey)
		if err != nil || len(decodedKey) != 32 {
			return nil, fmt.Errorf("JMS_VAULT_KEY must be base64-encoded 32-byte key material in cluster mode")
		}
		if _, explicitlySet := os.LookupEnv("JMS_DATA_DIR"); !explicitlySet {
			return nil, fmt.Errorf("JMS_DATA_DIR must point to shared storage when JMS_CLUSTER_MODE is enabled")
		}
		if cfg.ClusterID == "" || len(cfg.ClusterID) > 128 {
			return nil, fmt.Errorf("JMS_CLUSTER_ID must contain 1 to 128 characters")
		}
		if cfg.ClusterHealthAddr == "" || cfg.ClusterHealthAddr == cfg.Addr {
			return nil, fmt.Errorf("JMS_CLUSTER_HEALTH_ADDR must be set and differ from JMS_ADDR")
		}
		if _, _, err := net.SplitHostPort(cfg.ClusterHealthAddr); err != nil {
			return nil, fmt.Errorf("JMS_CLUSTER_HEALTH_ADDR must be a host:port address")
		}
	}
	return cfg, nil
}

func isLoopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func parseBoolEnv(key string, fallback bool) (bool, error) {
	value, exists := os.LookupEnv(key)
	if !exists {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", key)
	}
	return parsed, nil
}
