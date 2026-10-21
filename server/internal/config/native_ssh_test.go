package config

import (
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestNativeSSHListenerConfiguration(t *testing.T) {
	for _, address := range []string{"0.0.0.0:2222", "[::]:2222", "127.0.0.1:2222"} {
		t.Run(address, func(t *testing.T) {
			clearConfigEnv(t)
			t.Setenv("JMS_SSH_ADDR", address)
			t.Setenv("JMS_ADMIN_TOKEN", strings.Repeat("a", 32))
			cfg, e := FromEnv()
			require.NoError(t, e)
			require.Equal(t, address, cfg.SSHAddr)
		})
	}
	for _, address := range []string{"bad", "host:2222", "127.0.0.1:0", "127.0.0.1:65536", "0.0.0.0:8080"} {
		t.Run(address, func(t *testing.T) {
			clearConfigEnv(t)
			t.Setenv("JMS_SSH_ADDR", address)
			_, e := FromEnv()
			require.Error(t, e)
		})
	}
	clearConfigEnv(t)
	t.Setenv("JMS_SSH_ADDR", "0.0.0.0:2222")
	_, e := FromEnv()
	require.Error(t, e)
}
