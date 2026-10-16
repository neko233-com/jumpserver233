package ldaplogin

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/ldapclient"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/neko233-com/jumpserver233/server/testsupport/ldapserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func input(s *ldapserver.Server) Input {
	return Input{Config: Config{Config: ldapclient.Config{URL: s.URL, BaseDN: ldapserver.BaseDN, BindDN: ldapserver.BindDN, Filter: "(uid={username})", IdentityAttribute: "entryUUID", CAPEM: s.CAPEM}, Enabled: true}, BindPassword: ldapserver.BindPassword}
}
func TestLDAPConfigEncryptionRevisionsIdentityAndTickets(t *testing.T) {
	dir, e := ldapserver.Start(ldapserver.Options{})
	require.NoError(t, e)
	defer dir.Close()
	path := filepath.Join(t.TempDir(), "ldap.json")
	key := make([]byte, 32)
	s, e := Open(path, key, nil, nil)
	require.NoError(t, e)
	in := input(dir)
	saved, e := s.Save(in, "admin-id", "admin")
	require.NoError(t, e)
	assert.True(t, saved.HasBindPassword)
	assert.Equal(t, 1, saved.Revision)
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), ldapserver.BindPassword)
	assert.NotContains(t, string(raw), dir.URL)
	require.NoError(t, s.Check(context.Background()))
	id, e := s.Authenticate(context.Background(), ldapserver.Username, ldapserver.Password)
	require.NoError(t, e)
	assert.False(t, id.Provision)
	assert.True(t, s.IssuerAllowed(id.Issuer))
	token, e := s.NewPending("user", id.Revision)
	require.NoError(t, e)
	_, e = s.Pending(token, false)
	require.NoError(t, e)
	_, e = s.Save(in, "admin-id", "admin")
	assert.ErrorIs(t, e, ErrConflict)
	s2, e := Open(path, key, nil, nil)
	require.NoError(t, e)
	assert.True(t, s2.Snapshot().HasBindPassword)
	assert.True(t, s2.IssuerAllowed(id.Issuer))
	next := s.Snapshot().Config
	next.Enabled = false
	_, e = s.Save(Input{Config: next}, "admin-id", "admin")
	require.NoError(t, e)
	_, e = s.Pending(token, false)
	assert.Error(t, e)
	assert.False(t, s.IssuerAllowed(id.Issuer))
	assert.Len(t, s.Audit(), 2)
	assert.Equal(t, "admin-id", s.Audit()[0].ActorID)
	assert.True(t, s.Snapshot().HasBindPassword)
	_, e = s.Authenticate(context.Background(), ldapserver.Username, ldapserver.Password)
	assert.ErrorIs(t, e, ErrDisabled)
}
func TestLDAPPostgresReload(t *testing.T) {
	url := os.Getenv("JMS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for LDAP PostgreSQL integration")
	}
	docs, e := storage.OpenPostgres(context.Background(), url, "ldap-"+time.Now().Format("150405.000000000"))
	require.NoError(t, e)
	defer docs.Close()
	defer docs.Delete("ldap-config")
	dir, e := ldapserver.Start(ldapserver.Options{})
	require.NoError(t, e)
	defer dir.Close()
	path := filepath.Join(t.TempDir(), "ldap.json")
	s, e := Open(path, make([]byte, 32), docs, nil)
	require.NoError(t, e)
	_, e = s.Save(input(dir), "admin", "admin")
	require.NoError(t, e)
	raw, e := docs.Load("ldap-config")
	require.NoError(t, e)
	assert.NotContains(t, string(raw), ldapserver.BindPassword)
	next, e := Open(path, make([]byte, 32), docs, nil)
	require.NoError(t, e)
	require.NoError(t, next.Check(context.Background()))
	assert.True(t, next.Snapshot().HasBindPassword)
}

func TestDirectoryScopeChangesInvalidateIdentityButPasswordUpdatesDoNot(t *testing.T) {
	dir, e := ldapserver.Start(ldapserver.Options{})
	require.NoError(t, e)
	defer dir.Close()
	path := filepath.Join(t.TempDir(), "ldap.json")
	s, e := Open(path, make([]byte, 32), nil, nil)
	require.NoError(t, e)
	_, e = s.Save(input(dir), "admin", "admin")
	require.NoError(t, e)
	id, e := s.Authenticate(t.Context(), ldapserver.Username, ldapserver.Password)
	require.NoError(t, e)
	cfg := s.Snapshot().Config
	_, e = s.Save(Input{Config: cfg, BindPassword: ldapserver.BindPassword}, "admin", "admin")
	require.NoError(t, e)
	assert.True(t, s.IssuerAllowed(id.Issuer))
	cfg = s.Snapshot().Config
	cfg.Filter = "(sAMAccountName={username})"
	_, e = s.Save(Input{Config: cfg}, "admin", "admin")
	require.NoError(t, e)
	assert.False(t, s.IssuerAllowed(id.Issuer))
	next, e := s.Authenticate(t.Context(), ldapserver.Username, ldapserver.Password)
	require.NoError(t, e)
	assert.Equal(t, id.Subject, next.Subject)
	assert.NotEqual(t, id.Issuer, next.Issuer)
	_, e = Open(path, []byte("different-vault-key-32-bytes-only!"), nil, nil)
	assert.Error(t, e)
	cfg = s.Snapshot().Config
	_, e = s.Save(Input{Config: cfg, ClearPassword: true}, "admin", "admin")
	assert.ErrorIs(t, e, ErrInvalid)
}
