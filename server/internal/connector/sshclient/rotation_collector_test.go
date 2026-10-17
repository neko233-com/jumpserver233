package sshclient

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"time"
)

func TestChangePasswordForAuthenticatesCollectorAndResetsOnlySelectedUsername(t *testing.T) {
	for _, uid := range []string{"0", "1000"} {
		t.Run(uid, func(t *testing.T) {
			server, target := startRotationServer(t, uid, "synthetic-collector-password")
			defer server.listener.Close()
			server.mu.Lock()
			server.resetUser = "managed_target"
			server.mu.Unlock()
			next := "synthetic-generated-password-0000000001"
			require.NoError(t, ChangePasswordFor(context.Background(), target, Credentials{Password: "synthetic-collector-password"}, "managed_target", next, 3*time.Second))
			require.NoError(t, VerifyPassword(context.Background(), target, Credentials{Password: "synthetic-collector-password"}, time.Second))
			server.mu.Lock()
			defer server.mu.Unlock()
			assert.Equal(t, "managed_target:"+next+"\n", server.stdin)
			for _, command := range server.commands {
				assert.False(t, strings.Contains(command, next))
				assert.NotContains(t, command, "managed_target")
			}
			if uid == "0" {
				assert.Contains(t, server.commands, "chpasswd")
			} else {
				assert.Contains(t, server.commands, "sudo -n chpasswd")
			}
		})
	}
}
func TestChangePasswordForRejectsTargetShellAndPasswordInjection(t *testing.T) {
	for _, username := range []string{"bad:user", "user\nroot", "$(id)", "-root"} {
		assert.Error(t, ChangePasswordFor(context.Background(), Target{Username: "collector"}, Credentials{}, username, "synthetic-generated-password-0000000001", time.Second))
	}
	assert.Error(t, ChangePasswordFor(context.Background(), Target{Username: "collector"}, Credentials{}, "managed_target", "unsafe\npassword", time.Second))
}
