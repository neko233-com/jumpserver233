package directorysync

import (
	"context"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/connector/ldapclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/groups"
	"github.com/neko233-com/jumpserver233/server/internal/core/identitysources"
	"github.com/neko233-com/jumpserver233/server/internal/core/ldaplogin"
	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/neko233-com/jumpserver233/server/testsupport/ldapserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDirectorySyncPostgresReopenPreservesSourceKeysMappingsAndReceipts(t *testing.T) {
	url := os.Getenv("JMS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for directory synchronization PostgreSQL integration")
	}
	docs, e := storage.OpenPostgres(context.Background(), url, fmt.Sprintf("directory-sync-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	defer docs.Close()
	defer func() {
		for _, key := range []string{"identity-sources", "directory-sync", "users", "user-groups", "organizations"} {
			_ = docs.Delete(key)
		}
	}()
	root := t.TempDir()
	key := make([]byte, 32)
	identities, e := auth.OpenServiceWithDocumentsAndVaultKey(filepath.Join(root, "users.json"), docs, key)
	require.NoError(t, e)
	_, e = identities.Bootstrap("local.admin", "synthetic-local-admin-password")
	require.NoError(t, e)
	bank, e := identitysources.Open(filepath.Join(root, "identity-sources.json"), key, docs, "", identities)
	require.NoError(t, e)
	defer bank.Close()
	source, e := bank.Save("", "actor", identitysources.Input{Name: "PG directory", Kind: "ldap", Enabled: true, RequestID: "pg-source-001"})
	require.NoError(t, e)
	scoped, e := docs.Scoped(source.ID)
	require.NoError(t, e)
	defer scoped.Delete("ldap-config")
	fixture, e := ldapserver.Start(ldapserver.Options{DirectorySync: true})
	require.NoError(t, e)
	defer fixture.Close()
	_, runtime, _ := bank.Get(source.ID)
	_, e = runtime.LDAP.Save(ldaplogin.Input{Config: ldaplogin.Config{Config: ldapclient.Config{URL: fixture.URL, BaseDN: ldapserver.BaseDN, BindDN: ldapserver.BindDN, Filter: "(uid={username})", IdentityAttribute: "entryUUID", CAPEM: fixture.CAPEM}, Enabled: true}, BindPassword: ldapserver.BindPassword}, "actor", "admin")
	require.NoError(t, e)
	groupStore, e := groups.OpenStoreWithDocuments(filepath.Join(root, "groups.json"), docs)
	require.NoError(t, e)
	group, e := groupStore.Create("Directory operations", "")
	require.NoError(t, e)
	orgStore, e := organizations.Open(filepath.Join(root, "organizations.json"), docs)
	require.NoError(t, e)
	path := filepath.Join(root, "directory-sync.json")
	store, e := Open(path, key, docs, bank, identities, groupStore, orgStore)
	require.NoError(t, e)
	defer store.Close()
	c := config()
	c.Mappings = []Mapping{{DirectoryGroupDN: ldapserver.GroupDN, GroupIDs: []string{group.ID}}}
	cfg, e := store.SaveConfig(source.ID, "actor", ConfigInput{c, "pg-sync-config-001"})
	require.NoError(t, e)
	p, e := store.Preview(t.Context(), source.ID, "actor", Operation{RequestID: "pg-sync-preview-001", Revision: cfg.Revision})
	require.NoError(t, e)
	op := Operation{RequestID: "pg-sync-apply-001", Revision: cfg.Revision, PreviewID: p.ID}
	run, e := store.Apply(t.Context(), source.ID, "actor", op)
	require.NoError(t, e)
	uid := store.Entries(source.ID)[0].UserID
	store.Close()
	bank.Close()
	reloadedAuth, e := auth.OpenServiceWithDocumentsAndVaultKey(filepath.Join(root, "users.json"), docs, key)
	require.NoError(t, e)
	reloadedBank, e := identitysources.Open(filepath.Join(root, "identity-sources.json"), key, docs, "", reloadedAuth)
	require.NoError(t, e)
	defer reloadedBank.Close()
	reloadedGroups, e := groups.OpenStoreWithDocuments(filepath.Join(root, "groups.json"), docs)
	require.NoError(t, e)
	reloaded, e := Open(path, key, docs, reloadedBank, reloadedAuth, reloadedGroups, orgStore)
	require.NoError(t, e)
	defer reloaded.Close()
	assert.Contains(t, reloadedGroups.GroupIDsForUser(uid), group.ID)
	again, e := reloaded.Apply(t.Context(), source.ID, "actor", op)
	require.NoError(t, e)
	assert.Equal(t, run, again)
	assert.Len(t, reloaded.Entries(source.ID), 1)
}
