package ldapclient

import (
	"context"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/neko233-com/jumpserver233/server/testsupport/ldapserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func scanOptions() ScanOptions {
	return ScanOptions{UserFilter: "(objectClass=person)", UsernameAttribute: "uid", GroupBaseDN: ldapserver.GroupBaseDN, GroupFilter: "(objectClass=groupOfNames)"}
}
func TestDirectoryScanUsesRealTLSAndRejectsIncompletePaging(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options ldapserver.Options
		success bool
	}{{"complete", ldapserver.Options{DirectorySync: true}, true}, {"starttls", ldapserver.Options{DirectorySync: true, StartTLS: true}, true}, {"no-control", ldapserver.Options{DirectorySync: true, MissingPaging: true}, false}, {"cookie-loop", ldapserver.Options{DirectorySync: true, RepeatPaging: true}, false}, {"size-limit", ldapserver.Options{DirectorySync: true, TruncatedSearch: true}, false}, {"referral", ldapserver.Options{DirectorySync: true, Referral: true}, false}, {"outside-base", ldapserver.Options{DirectorySync: true, OutsideBase: true}, false}} {
		t.Run(tc.name, func(t *testing.T) {
			server, e := ldapserver.Start(tc.options)
			require.NoError(t, e)
			defer server.Close()
			c := Config{URL: server.URL, BaseDN: ldapserver.BaseDN, BindDN: ldapserver.BindDN, Filter: "(uid={username})", IdentityAttribute: "entryUUID", CAPEM: server.CAPEM}
			result, e := (Client{}).Scan(context.Background(), c, ldapserver.BindPassword, scanOptions())
			if !tc.success {
				assert.Error(t, e)
				assert.Empty(t, result.Users)
				return
			}
			require.NoError(t, e)
			require.Len(t, result.Users, 1)
			assert.Equal(t, []string{ldapserver.GroupDN}, result.Users[0].Groups)
			login, e := (Client{}).Lookup(context.Background(), c, ldapserver.BindPassword, ldapserver.Username)
			require.NoError(t, e)
			assert.Equal(t, login.Subject, result.Users[0].Subject)
		})
	}
}
func TestDirectorySnapshotStableIDsNestedGroupsDuplicatesAndCycles(t *testing.T) {
	c := Config{BaseDN: ldapserver.BaseDN, IdentityAttribute: "entryUUID"}
	o := scanOptions()
	user := ldap.NewEntry(ldapserver.UserDN, map[string][]string{"uid": {"user"}, "entryUUID": {"stable"}})
	child := ldap.NewEntry("cn=child,"+ldapserver.GroupBaseDN, map[string][]string{"cn": {"child"}, "member": {ldapserver.UserDN}})
	parent := ldap.NewEntry(ldapserver.GroupDN, map[string][]string{"cn": {"parent"}, "uniqueMember": {child.DN}})
	result, e := makeSnapshot(c, o, []*ldap.Entry{user}, []*ldap.Entry{parent, child})
	require.NoError(t, e)
	assert.Len(t, result.Users[0].Groups, 2)
	cyclic := ldap.NewEntry(child.DN, map[string][]string{"member": {parent.DN}})
	_, e = makeSnapshot(c, o, []*ldap.Entry{user}, []*ldap.Entry{parent, cyclic})
	assert.ErrorIs(t, e, ErrIncomplete)
	_, e = makeSnapshot(c, o, []*ldap.Entry{user, user}, nil)
	assert.ErrorIs(t, e, ErrIncomplete)
	a, e := DNKey(`CN=ops\,team+UID=x,OU=groups,DC=example,DC=test`)
	require.NoError(t, e)
	b, e := DNKey(`uid=X+cn=OPS\,TEAM,ou=GROUPS,dc=EXAMPLE,dc=TEST`)
	require.NoError(t, e)
	assert.Equal(t, a, b)
	o.UserFilter = "(uid={username})"
	assert.ErrorIs(t, ValidateScan(o), ErrConfig)
}
