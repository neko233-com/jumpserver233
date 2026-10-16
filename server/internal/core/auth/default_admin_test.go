package auth

import (
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultAdministratorIsHashedIdempotentAndNeverResetsAccounts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s, e := OpenService(path)
	require.NoError(t, e)
	require.NoError(t, s.InitializeDefaultAdministrator())
	users := s.ListUsers()
	require.Len(t, users, 1)
	require.Equal(t, "root", users[0].Username)
	require.Equal(t, RoleAdmin, users[0].Role)
	require.NoError(t, s.InitializeDefaultAdministrator())
	require.Equal(t, users, s.ListUsers())
	login, e := s.Authenticate("root", "root")
	require.NoError(t, e)
	require.NoError(t, s.ChangePassword(login.User.ID, login.AccessToken, "root", "synthetic-replaced-root-password"))
	require.NoError(t, s.InitializeDefaultAdministrator())
	_, e = s.Authenticate("root", "root")
	require.ErrorIs(t, e, ErrInvalidCredentials)
	s, e = OpenService(path)
	require.NoError(t, e)
	require.NoError(t, s.InitializeDefaultAdministrator())
	_, e = s.Authenticate("root", "synthetic-replaced-root-password")
	require.NoError(t, e)
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	require.NotContains(t, string(raw), "synthetic-replaced-root-password")
	_, e = s.CreateUser("another", "root", RoleAdmin)
	require.ErrorIs(t, e, ErrInvalidPassword)
}

func TestDefaultAdministratorDoesNotAddRootToExistingStore(t *testing.T) {
	s, e := OpenService(filepath.Join(t.TempDir(), "users.json"))
	require.NoError(t, e)
	_, e = s.Bootstrap("existing.admin", "synthetic-existing-admin-password")
	require.NoError(t, e)
	require.NoError(t, s.InitializeDefaultAdministrator())
	require.Len(t, s.ListUsers(), 1)
	require.Equal(t, "existing.admin", s.ListUsers()[0].Username)
	fresh, e := OpenService(filepath.Join(t.TempDir(), "users.json"))
	require.NoError(t, e)
	_, e = fresh.Bootstrap("root", "root")
	require.ErrorIs(t, e, ErrInvalidPassword)
}
