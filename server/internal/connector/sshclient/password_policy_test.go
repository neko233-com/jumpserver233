package sshclient

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"time"
)

func TestSSHPasswordPolicySymbolsRemainInStdin(t *testing.T) {
	server, target := startRotationServer(t, "1000", "synthetic-collector-password")
	defer server.listener.Close()
	server.mu.Lock()
	server.resetUser = "managed_target"
	server.mu.Unlock()
	next := "Abc42!#%+,-.=?@[]^_{}~"
	require.NoError(t, ChangePasswordFor(context.Background(), target, Credentials{Password: "synthetic-collector-password"}, "managed_target", next, 3*time.Second))
	server.mu.Lock()
	defer server.mu.Unlock()
	assert.Equal(t, "managed_target:"+next+"\n", server.stdin)
	for _, command := range server.commands {
		assert.NotContains(t, command, next)
	}
}
func TestSSHPasswordPolicyTransportRejectsSeparatorsQuotesAndBounds(t *testing.T) {
	for _, p := range []string{strings.Repeat("a", 15), strings.Repeat("a", 129), "Abcdefghijklmnop\nroot", `Abcdefghijklmnop:root`, `Abcdefghijklmnop'`, "Abcdefghijklmnop\x00", `Abcdefghijklmnop$(id)`} {
		assert.False(t, rotationPasswordPattern.MatchString(p))
	}
	assert.True(t, rotationPasswordPattern.MatchString("AbcdEfgh1234!#%+"))
}
