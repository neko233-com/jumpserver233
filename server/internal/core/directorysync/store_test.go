package directorysync

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/connector/ldapclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/groups"
	"github.com/neko233-com/jumpserver233/server/internal/core/identitysources"
	"github.com/neko233-com/jumpserver233/server/internal/core/ldaplogin"
	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
	"github.com/neko233-com/jumpserver233/server/testsupport/ldapserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

type environment struct {
	store      *Store
	sources    *identitysources.Store
	identities *auth.Service
	groups     *groups.Store
	orgs       *organizations.Store
	source     identitysources.Source
	runtime    *identitysources.Runtime
	root       string
}

func TestDirectorySyncAdmissionRejectsBeforeAnyDirectoryWork(t *testing.T) {
	e := setup(t)
	gate := workgate.New()
	gate.SetClosed(true)
	ctx := workgate.WithGate(t.Context(), gate)
	_, err := e.store.Preview(ctx, e.source.ID, "actor", Operation{RequestID: "draining-preview-001", Revision: 1})
	assert.ErrorIs(t, err, workgate.ErrDraining)
	assert.Empty(t, gate.Snapshot())
	assert.Empty(t, e.store.Runs(e.source.ID))
}

func setup(t *testing.T) *environment {
	t.Helper()
	root := t.TempDir()
	key := make([]byte, 32)
	a, e := auth.OpenServiceWithVaultKey(filepath.Join(root, "users.json"), key)
	require.NoError(t, e)
	_, e = a.Bootstrap("local.admin", "synthetic-local-admin-password")
	require.NoError(t, e)
	bank, e := identitysources.Open(filepath.Join(root, "identity-sources.json"), key, nil, "", a)
	require.NoError(t, e)
	t.Cleanup(bank.Close)
	source, e := bank.Save("", "actor", identitysources.Input{Name: "Directory", Kind: "ldap", Enabled: true, RequestID: "create-directory-001"})
	require.NoError(t, e)
	_, runtime, _ := bank.Get(source.ID)
	fixture, e := ldapserver.Start(ldapserver.Options{DirectorySync: true})
	require.NoError(t, e)
	t.Cleanup(fixture.Close)
	_, e = runtime.LDAP.Save(ldaplogin.Input{Config: ldaplogin.Config{Config: ldapclient.Config{URL: fixture.URL, BaseDN: ldapserver.BaseDN, BindDN: ldapserver.BindDN, Filter: "(uid={username})", IdentityAttribute: "entryUUID", CAPEM: fixture.CAPEM}, Enabled: true}, BindPassword: ldapserver.BindPassword}, "actor", "admin")
	require.NoError(t, e)
	g, e := groups.OpenStore(filepath.Join(root, "groups.json"))
	require.NoError(t, e)
	o, e := organizations.Open(filepath.Join(root, "organizations.json"), nil)
	require.NoError(t, e)
	store, e := Open(filepath.Join(root, "directory-sync.json"), key, nil, bank, a, g, o)
	require.NoError(t, e)
	t.Cleanup(store.Close)
	return &environment{store, bank, a, g, o, source, runtime, root}
}
func config() Config {
	return Config{ScanOptions: ldapclient.ScanOptions{UserFilter: "(objectClass=person)", UsernameAttribute: "uid", GroupBaseDN: ldapserver.GroupBaseDN, GroupFilter: "(objectClass=groupOfNames)"}, Mappings: []Mapping{}, MissingAction: "keep"}
}
func TestDirectorySyncCompleteApplyIdempotenceOwnedMembershipAndReopen(t *testing.T) {
	e := setup(t)
	group, err := e.groups.Create("Operations", "")
	require.NoError(t, err)
	org, err := e.orgs.Save("", organizations.Input{Name: "Operations", Enabled: true}, "actor")
	require.NoError(t, err)
	cfg := config()
	cfg.Mappings = []Mapping{{DirectoryGroupDN: ldapserver.GroupDN, GroupIDs: []string{group.ID}, OrganizationID: org.ID, OrganizationRole: "auditor"}}
	in := ConfigInput{cfg, "directory-config-001"}
	saved, err := e.store.SaveConfig(e.source.ID, "actor", in)
	require.NoError(t, err)
	again, err := e.store.SaveConfig(e.source.ID, "actor", in)
	require.NoError(t, err)
	assert.Equal(t, saved, again)
	p, err := e.store.Preview(t.Context(), e.source.ID, "actor", Operation{RequestID: "directory-preview-001", Revision: saved.Revision})
	require.NoError(t, err)
	assert.Len(t, p.Result.Users, 1)
	assert.Empty(t, e.store.Entries(e.source.ID))
	op := Operation{RequestID: "directory-apply-001", Revision: saved.Revision, PreviewID: p.ID}
	run, err := e.store.Apply(t.Context(), e.source.ID, "actor", op)
	require.NoError(t, err)
	againRun, err := e.store.Apply(t.Context(), e.source.ID, "actor", op)
	require.NoError(t, err)
	assert.Equal(t, run, againRun)
	entries := e.store.Entries(e.source.ID)
	require.Len(t, entries, 1)
	uid := entries[0].UserID
	assert.Contains(t, e.groups.GroupIDsForUser(uid), group.ID)
	assert.Equal(t, "auditor", e.orgs.Role(org.ID, uid))
	assert.True(t, e.runtime.Ready())
	_, err = e.groups.AddMember(group.ID, uid)
	require.NoError(t, err)
	_, err = e.orgs.SaveMember(org.ID, organizations.MemberInput{UserID: uid, Role: "none"}, "actor")
	require.NoError(t, err)
	assert.Equal(t, "none", e.orgs.Role(org.ID, uid))
	saved.Mappings = []Mapping{}
	saved, err = e.store.SaveConfig(e.source.ID, "actor", ConfigInput{saved, "directory-config-002"})
	require.NoError(t, err)
	p, err = e.store.Preview(t.Context(), e.source.ID, "actor", Operation{RequestID: "directory-preview-002", Revision: saved.Revision})
	require.NoError(t, err)
	_, err = e.store.Apply(t.Context(), e.source.ID, "actor", Operation{RequestID: "directory-apply-002", Revision: saved.Revision, PreviewID: p.ID})
	require.NoError(t, err)
	assert.Contains(t, e.groups.GroupIDsForUser(uid), group.ID, "manual group membership survives removal of source ownership")
	assert.Equal(t, "none", e.orgs.Role(org.ID, uid), "manual exclusion wins over mapping")
	raw, err := os.ReadFile(e.store.path)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), ldapserver.Username)
	assert.NotContains(t, string(raw), ldapserver.GroupDN)
	e.store.Close()
	reopened, err := Open(e.store.path, make([]byte, 32), nil, e.sources, e.identities, e.groups, e.orgs)
	require.NoError(t, err)
	defer reopened.Close()
	assert.Len(t, reopened.Entries(e.source.ID), 1)
	assert.Len(t, reopened.Runs(e.source.ID), 2)
	againRun, err = reopened.Apply(context.Background(), e.source.ID, "actor", op)
	require.NoError(t, err)
	assert.Equal(t, run, againRun)
}
func TestDirectorySyncPendingReopenAbortAndNoPartialMembershipPublication(t *testing.T) {
	e := setup(t)
	cfg, err := e.store.SaveConfig(e.source.ID, "actor", ConfigInput{config(), "pending-config-001"})
	require.NoError(t, err)
	p, err := e.store.Preview(t.Context(), e.source.ID, "actor", Operation{RequestID: "pending-preview-001", Revision: cfg.Revision})
	require.NoError(t, err)
	// The durable identity limit forces a failure after the apply intent commits.
	// A bootstrap-only replacement cannot create source users at this checkpoint.
	original := e.store.identities
	empty, err := auth.OpenServiceWithVaultKey(filepath.Join(e.root, "empty-users.json"), make([]byte, 32))
	require.NoError(t, err)
	e.store.identities = empty
	op := Operation{RequestID: "pending-apply-001", Revision: cfg.Revision, PreviewID: p.ID}
	_, err = e.store.Apply(t.Context(), e.source.ID, "actor", op)
	assert.Error(t, err)
	assert.False(t, e.runtime.Ready())
	assert.Equal(t, "applying", e.store.Runs(e.source.ID)[0].State)
	assert.Empty(t, e.store.Entries(e.source.ID))
	e.store.identities = original
	e.store.Close()
	reopened, err := Open(e.store.path, make([]byte, 32), nil, e.sources, original, e.groups, e.orgs)
	require.NoError(t, err)
	defer reopened.Close()
	assert.False(t, e.runtime.Ready())
	cfg.Revision--
	_, err = reopened.SaveConfig(e.source.ID, "actor", ConfigInput{cfg, "pending-config-002"})
	assert.ErrorIs(t, err, ErrPending)
	result, err := reopened.Apply(t.Context(), e.source.ID, "actor", op)
	require.NoError(t, err)
	assert.Equal(t, "completed", result.State)
	assert.True(t, e.runtime.Ready())
	// A second interrupted transaction may be explicitly aborted by another admin.
	cfg = reopened.Config(e.source.ID)
	p, err = reopened.Preview(t.Context(), e.source.ID, "actor", Operation{RequestID: "pending-preview-002", Revision: cfg.Revision})
	require.NoError(t, err)
	reopened.identities = empty
	_, err = reopened.Apply(t.Context(), e.source.ID, "actor", Operation{RequestID: "pending-apply-002", Revision: cfg.Revision, PreviewID: p.ID})
	require.Error(t, err)
	reopened.identities = original
	aborted, err := reopened.Abort(t.Context(), e.source.ID, "other-admin", Operation{RequestID: "pending-abort-001", Revision: cfg.Revision, PreviewID: p.ID})
	require.NoError(t, err)
	assert.Equal(t, "aborted", aborted.State)
	assert.Empty(t, reopened.Entries(e.source.ID))
	for _, user := range original.NamedDirectoryUsers(e.source.ID) {
		assert.True(t, user.SourceSuspended)
	}
	assert.True(t, e.runtime.Ready())
}
func TestMissingDirectoryUsersRequireTwoCompleteSnapshotsAndPreserveManualState(t *testing.T) {
	c := config()
	c.MissingAction = "disable"
	old := []Entry{{Subject: "subject", UserID: "user", GroupIDs: []string{"group"}, Organizations: map[string]string{"org": "member"}}}
	first, err := mappedEntries(c, ldapclient.DirectorySnapshot{}, nil, old)
	require.NoError(t, err)
	assert.False(t, first[0].Suspended)
	assert.Empty(t, first[0].GroupIDs)
	second, err := mappedEntries(c, ldapclient.DirectorySnapshot{}, nil, first)
	require.NoError(t, err)
	assert.True(t, second[0].Suspended)
	assert.Equal(t, 2, second[0].MissingCount)
	c.MissingAction = "keep"
	kept, err := mappedEntries(c, ldapclient.DirectorySnapshot{}, nil, old)
	require.NoError(t, err)
	assert.Equal(t, []string{"group"}, kept[0].GroupIDs)
}
func TestDirectorySyncScheduleIsExplicitIdempotentAndCloseJoins(t *testing.T) {
	e := setup(t)
	c := config()
	c.IntervalMinutes = 15
	_, err := e.store.SaveConfig(e.source.ID, "actor", ConfigInput{c, "scheduled-config-001"})
	require.NoError(t, err)
	assert.Empty(t, e.store.Runs(e.source.ID))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	require.NoError(t, e.store.Start(ctx))
	require.NoError(t, e.store.Start(ctx))
	e.store.schedule(ctx)
	require.Len(t, e.store.Runs(e.source.ID), 1)
	assert.Equal(t, "directory-scheduler", e.store.Runs(e.source.ID)[0].ActorID)
	e.store.schedule(ctx)
	assert.Len(t, e.store.Runs(e.source.ID), 1)
	cancel()
	e.store.Close()
	e.store.Close()
	_, err = e.store.Preview(t.Context(), e.source.ID, "actor", Operation{RequestID: "closed-preview-001", Revision: 1})
	assert.ErrorIs(t, err, ErrUnavailable)
}
