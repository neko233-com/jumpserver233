package identitysources

import (
	"github.com/neko233-com/jumpserver233/server/internal/connector/casclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/ldapclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/caslogin"
	"github.com/neko233-com/jumpserver233/server/internal/core/identityscope"
	"github.com/neko233-com/jumpserver233/server/internal/core/ldaplogin"
	"github.com/neko233-com/jumpserver233/server/internal/core/oidclogin"
	"github.com/neko233-com/jumpserver233/server/testsupport/ldapserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourceRegistryOIDCCASCallbacksBindExactSourceAndPreserveLoginLanding(t *testing.T) {
	root := t.TempDir()
	a, e := auth.OpenServiceWithVaultKey(filepath.Join(root, "users.json"), make([]byte, 32))
	require.NoError(t, e)
	_, e = a.Bootstrap("local.admin", "synthetic-local-admin-password")
	require.NoError(t, e)
	s, e := Open(filepath.Join(root, "identity-sources.json"), make([]byte, 32), nil, "https://console.example.invalid", a)
	require.NoError(t, e)
	defer s.Close()
	for _, kind := range []string{"oidc", "cas"} {
		source, e := s.Save("", "actor", Input{Name: kind, Kind: kind, RequestID: "callback-source-" + kind})
		require.NoError(t, e)
		_, runtime, _ := s.Get(source.ID)
		prefix := identityscope.Prefix(source.ID)
		callback := "https://console.example.invalid" + prefix + "/api/v1/authentication/" + kind + "/callback"
		if kind == "oidc" {
			cfg := oidclogin.Input{Config: oidclogin.Config{Issuer: "https://idp.example.invalid", ClientID: "source-client", RedirectURL: callback, TokenAuthMethod: "none"}}
			_, e = runtime.OIDC.Save(cfg, "actor", "admin")
			require.NoError(t, e)
			assert.Contains(t, runtime.OIDC.ReturnURL("/login?sso=continue"), "identity_source="+source.ID)
			cfg.Revision = 1
			cfg.RedirectURL = "https://console.example.invalid/api/v1/authentication/oidc/callback"
			_, e = runtime.OIDC.Save(cfg, "actor", "admin")
			assert.ErrorIs(t, e, oidclogin.ErrInvalid)
		} else {
			cfg := caslogin.Config{Config: casclient.Config{BaseURL: "https://idp.example.invalid/cas", Protocol: "3"}, CallbackURL: callback}
			_, e = runtime.CAS.Save(cfg, "actor", "admin")
			require.NoError(t, e)
			assert.Contains(t, runtime.CAS.ReturnURL("/login?cas=continue"), "identity_source="+source.ID)
			cfg.Revision = 1
			cfg.CallbackURL = "https://console.example.invalid/api/v1/authentication/cas/callback"
			_, e = runtime.CAS.Save(cfg, "actor", "admin")
			assert.ErrorIs(t, e, caslogin.ErrInvalid)
		}
	}
}
func TestSourceRegistryIdempotenceImmutableKindIndependentKeysAndReopen(t *testing.T) {
	root := t.TempDir()
	key := make([]byte, 32)
	identities, e := auth.OpenServiceWithVaultKey(filepath.Join(root, "users.json"), key)
	require.NoError(t, e)
	_, e = identities.Bootstrap("local.admin", "synthetic-local-admin-password")
	require.NoError(t, e)
	path := filepath.Join(root, "identity-sources.json")
	store, e := Open(path, key, nil, "", identities)
	require.NoError(t, e)
	input := Input{Name: "Directory A", Kind: "ldap", Enabled: true, RequestID: "create-source-001"}
	a, e := store.Save("", "actor", input)
	require.NoError(t, e)
	again, e := store.Save("", "actor", input)
	require.NoError(t, e)
	assert.Equal(t, a, again)
	input.Name = "different"
	_, e = store.Save("", "actor", input)
	assert.ErrorIs(t, e, ErrConflict)
	input.Name = "Directory B"
	input.RequestID = "create-source-002"
	b, e := store.Save("", "actor", input)
	require.NoError(t, e)
	_, ra, _ := store.Get(a.ID)
	_, rb, _ := store.Get(b.ID)
	fixture, e := ldapserver.Start(ldapserver.Options{})
	require.NoError(t, e)
	defer fixture.Close()
	config := ldaplogin.Input{Config: ldaplogin.Config{Config: ldapclient.Config{URL: fixture.URL, BaseDN: ldapserver.BaseDN, BindDN: ldapserver.BindDN, Filter: "(uid={username})", IdentityAttribute: "entryUUID", CAPEM: fixture.CAPEM}, Enabled: true}, BindPassword: ldapserver.BindPassword}
	_, e = ra.LDAP.Save(config, "actor", "admin")
	require.NoError(t, e)
	assert.True(t, ra.Ready())
	assert.False(t, rb.Ready())
	id, e := ra.LDAP.Lookup(t.Context(), ldapserver.Username)
	require.NoError(t, e)
	user, e := identities.EnsureNamedExternalUser("ldap", a.ID, id.Issuer, id.Subject, "", true)
	require.NoError(t, e)
	login, _, e := identities.AuthenticateNamedExternalUser(user.ID, "ldap", a.ID, "")
	require.NoError(t, e)
	protected := ra.SealCookie("flow", "synthetic-opaque-proof", ra.Generation())
	require.NotEmpty(t, protected)
	assert.Equal(t, "synthetic-opaque-proof", ra.OpenCookie("flow", protected))
	assert.Empty(t, ra.OpenCookie("pending", protected))
	off := a.Input
	off.Enabled = false
	off.RequestID = "disable-source-001"
	saved, e := store.Save(a.ID, "actor", off)
	require.NoError(t, e)
	_, valid := identities.ValidateToken(login.AccessToken)
	assert.False(t, valid)
	on := saved.Input
	on.Enabled = true
	on.RequestID = "enable-source-001"
	_, e = store.Save(a.ID, "actor", on)
	require.NoError(t, e)
	assert.Empty(t, ra.OpenCookie("flow", protected))
	forged := strings.Replace(protected, "0.", "1.", 1)
	assert.Empty(t, ra.OpenCookie("flow", forged), "a browser cannot relabel a stale proof with the current generation")
	_, valid = identities.ValidateToken(login.AccessToken)
	assert.False(t, valid)
	wrong := on
	wrong.Kind = "oidc"
	wrong.RequestID = "change-kind-001"
	_, e = store.Save(a.ID, "actor", wrong)
	assert.ErrorIs(t, e, ErrConflict)
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "Directory A")
	child := filepath.Join(root, "identity-sources", a.ID, "ldap.json")
	raw, e = os.ReadFile(child)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), ldapserver.BindPassword)
	store.Close()
	reopened, e := Open(path, key, nil, "", identities)
	require.NoError(t, e)
	defer reopened.Close()
	assert.Len(t, reopened.List(), 2)
	_, loaded, ok := reopened.Get(a.ID)
	require.True(t, ok)
	assert.True(t, loaded.Ready())
	assert.True(t, loaded.LDAP.Snapshot().HasBindPassword)
	target := filepath.Join(root, "identity-sources", b.ID, "ldap.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(target), 0700))
	require.NoError(t, os.WriteFile(target, raw, 0600))
	_, e = Open(path, key, nil, "", identities)
	assert.Error(t, e, "a source's encrypted configuration cannot be transplanted to another source")
	assert.False(t, strings.Contains(a.ID, "/"))
}
