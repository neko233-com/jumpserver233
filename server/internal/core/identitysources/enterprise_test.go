package identitysources

import (
	"path/filepath"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/enterpriselogin"
	"github.com/neko233-com/jumpserver233/server/internal/core/identityscope"
	"github.com/neko233-com/jumpserver233/server/testsupport/enterpriseprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnterpriseLoginSourceRegistryReopenAndIndependentProviderSecrets(t *testing.T) {
	root := t.TempDir()
	key := make([]byte, 32)
	identities, e := auth.OpenServiceWithVaultKey(filepath.Join(root, "users.json"), key)
	require.NoError(t, e)
	_, e = identities.Bootstrap("local.admin", "synthetic-local-admin-password")
	require.NoError(t, e)
	path := filepath.Join(root, "identity-sources.json")
	store, e := Open(path, key, nil, "http://127.0.0.1:5177", identities)
	require.NoError(t, e)
	defer func() { store.Close() }()
	ids := map[string]string{}
	for _, kind := range []string{"wecom", "dingtalk", "feishu"} {
		source, e := store.Save("", "actor", Input{Name: kind, Kind: kind, Enabled: true, RequestID: "native-source-" + kind})
		require.NoError(t, e)
		ids[kind] = source.ID
		_, runtime, ok := store.Get(source.ID)
		require.True(t, ok)
		require.NotNil(t, runtime.Enterprise)
		assert.False(t, runtime.Ready())
		cfg := enterpriseprovider.Config(kind, "http://127.0.0.1:5177"+identityscope.Prefix(source.ID)+"/api/v1/authentication/"+kind+"/callback")
		cfg.AllowLoopbackHTTP = true
		_, e = runtime.Enterprise.Save(enterpriselogin.Input{Config: enterpriselogin.Config{Config: cfg, Enabled: true}, ClientSecret: enterpriseprovider.Secret, RequestID: "native-provider-" + kind}, "actor", "admin")
		require.NoError(t, e)
		assert.True(t, runtime.Ready())
	}
	store.Close()
	store, e = Open(path, key, nil, "http://127.0.0.1:5177", identities)
	require.NoError(t, e)
	for kind, id := range ids {
		_, runtime, ok := store.Get(id)
		require.True(t, ok)
		assert.Equal(t, kind, runtime.Enterprise.Snapshot().Provider)
		assert.True(t, runtime.Enterprise.Snapshot().HasClientSecret)
		assert.True(t, runtime.Ready())
		assert.Contains(t, runtime.Enterprise.ReturnURL("/login?enterprise="+kind+"&continue=1"), "identity_source="+id)
	}
}
