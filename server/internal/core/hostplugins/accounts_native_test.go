package hostplugins_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/agentbundle"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNativeAccountDiscoveryUsesUnprivilegedSSHAndVerifiedEmbeddedHelper(t *testing.T) {
	h := newNativeTools(t, "pluginqa")
	before := h.run(t, "stat -c '%s:%Y:%a:%u' /etc/passwd").Stdout
	checks := 0
	rows, digest, e := h.service.DiscoverAccounts(h.ctx, "fixture", "job-"+strings.Repeat("a", 32), func() error { checks++; return nil })
	require.NoError(t, e)
	require.NotEmpty(t, rows)
	assert.Equal(t, hostagent.AccountDigest(rows), digest)
	assert.GreaterOrEqual(t, checks, 4)
	root, operator := false, false
	for _, a := range rows {
		root = root || a.Username == "root" && a.UID == 0
		operator = operator || a.Username == "pluginqa"
	}
	assert.True(t, root)
	assert.True(t, operator)
	raw, e := json.Marshal(rows)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "synthetic-keyhost-password-233")
	assert.Equal(t, before, h.run(t, "stat -c '%s:%Y:%a:%u' /etc/passwd").Stdout)
	b, e := agentbundle.Get("linux-amd64")
	require.NoError(t, e)
	file := "/home/pluginqa/.jumpserver233/account-discovery/agent-recovery-" + b.SHA256
	require.Zero(t, h.run(t, "cp "+file+" "+file+".qa-valid; printf '\\n# drift\\n' >> "+file).ExitCode)
	t.Cleanup(func() { require.Zero(t, h.run(t, "mv "+file+".qa-valid "+file).ExitCode) })
	_, _, e = h.service.DiscoverAccounts(h.ctx, "fixture", "job-"+strings.Repeat("b", 32), func() error { return nil })
	require.ErrorIs(t, e, hostplugins.ErrIntegrity)
}
