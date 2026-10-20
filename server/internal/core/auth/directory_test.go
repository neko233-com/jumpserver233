package auth

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
)

func TestNamedSourcesDoNotLinkOrCrossAuthenticateAndDisableDoesNotReviveCredentials(t *testing.T) {
	s := externalService(t)
	a := "idp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	b := "idp-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	issuer := "https://issuer.example.invalid"
	for _, id := range []string{a, b} {
		s.SetNamedExternalSourceAllowed("oidc", id, func(i string) bool { return i == issuer })
	}
	one, e := s.EnsureNamedExternalUser("oidc", a, issuer, "subject", "", true)
	require.NoError(t, e)
	two, e := s.EnsureNamedExternalUser("oidc", b, issuer, "subject", "", true)
	require.NoError(t, e)
	legacy, e := s.EnsureExternalUser("oidc", issuer, "subject", "", true)
	require.NoError(t, e)
	assert.NotEqual(t, one.ID, two.ID)
	assert.NotEqual(t, one.ID, legacy.ID)
	_, _, e = s.AuthenticateExternalUser(one.ID, "oidc", "")
	assert.ErrorIs(t, e, ErrInvalidCredentials)
	_, _, e = s.AuthenticateNamedExternalUser(one.ID, "oidc", b, "")
	assert.ErrorIs(t, e, ErrInvalidCredentials)
	login, _, e := s.AuthenticateNamedExternalUser(one.ID, "oidc", a, "")
	require.NoError(t, e)
	require.NoError(t, s.RevokeNamedExternalSource("oidc", a))
	_, valid := s.ValidateToken(login.AccessToken)
	assert.False(t, valid)
	_, valid = s.ActiveUserByID(two.ID)
	assert.True(t, valid)
	_, _, e = s.AuthenticateNamedExternalUser(one.ID, "oidc", a, "", one.AuthGeneration)
	assert.ErrorIs(t, e, ErrInvalidCredentials)
	reopened, e := OpenServiceWithVaultKey(s.path, make([]byte, 32))
	require.NoError(t, e)
	reopened.SetNamedExternalSourceAllowed("oidc", a, func(string) bool { return true })
	_, valid = reopened.ValidateToken(login.AccessToken)
	assert.False(t, valid)
	current, ok := reopened.UserByID(one.ID)
	require.True(t, ok)
	assert.Equal(t, a, current.SourceID)
}
func TestDirectoryBulkReconciliationPreservesManualDisabledAndIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s, e := OpenServiceWithVaultKey(path, make([]byte, 32))
	require.NoError(t, e)
	admin, e := s.Bootstrap("local.admin", "synthetic-local-admin-password")
	require.NoError(t, e)
	id := "idp-cccccccccccccccccccccccccccccccc"
	s.SetNamedExternalSourceAllowed("ldap", id, func(string) bool { return true })
	first, e := s.EnsureNamedDirectoryUsers(id, "ldap:issuer", []string{"stable-1", "stable-2"})
	require.NoError(t, e)
	again, e := s.EnsureNamedDirectoryUsers(id, "ldap:issuer", []string{"stable-2", "stable-1"})
	require.NoError(t, e)
	assert.Equal(t, first, again)
	before := len(s.ListUsers())
	_, e = s.EnsureNamedDirectoryUsers(id, "ldap:issuer", []string{"stable-3", ""})
	require.Error(t, e)
	assert.Len(t, s.ListUsers(), before)
	user := first["stable-1"]
	inactive := false
	_, e = s.ChangeUsers([]UserChange{{ID: user.ID, Action: "update", UserUpdate: UserUpdate{Revision: user.Revision, IsActive: &inactive}}}, UserActor{ID: admin.ID, Name: admin.Username, ManageAdministrators: true})
	require.NoError(t, e)
	require.NoError(t, s.SetNamedDirectorySuspensions(id, map[string]bool{user.ID: true}))
	blocked, _ := s.UserByID(user.ID)
	require.NoError(t, s.SetNamedDirectorySuspensions(id, map[string]bool{user.ID: true}))
	same, _ := s.UserByID(user.ID)
	assert.Equal(t, blocked.AuthGeneration, same.AuthGeneration)
	require.NoError(t, s.SetNamedDirectorySuspensions(id, map[string]bool{user.ID: false}))
	manual, _ := s.UserByID(user.ID)
	assert.True(t, manual.Disabled)
	assert.False(t, manual.SourceSuspended)
	_, ok := s.ActiveUserByID(user.ID)
	assert.False(t, ok)
	e = s.SetNamedDirectorySuspensions("idp-dddddddddddddddddddddddddddddddd", map[string]bool{user.ID: true})
	assert.ErrorIs(t, e, ErrInvalidCredentials)
}
