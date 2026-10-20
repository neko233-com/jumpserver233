package rbac

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrganizationRolesCannotAcquireSystemPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roles.json")
	s, e := OpenOrganization(path, nil, func(string, string) Snapshot {
		return Snapshot{RoleIDs: []string{"global"}, Permissions: []string{"security.manage", "assets.view_all"}}
	})
	require.NoError(t, e)
	assert.NotContains(t, s.Catalog(), "security.manage")
	assert.NotContains(t, s.Catalog(), "users.manage")
	assert.NotContains(t, s.Catalog(), "organizations.manage")
	assert.NotContains(t, s.Catalog(), "organizations.overview")
	assert.NotContains(t, s.Catalog(), "reviews.platform_login.manage")
	for _, permission := range []string{"security.manage", "users.manage", "organizations.manage", "organizations.overview", "reviews.platform_login.manage"} {
		_, e = s.SaveRole("", RoleInput{Name: "invalid", Permissions: []string{permission}}, "admin", "admin")
		assert.ErrorIs(t, e, ErrInvalid)
	}
	_, e = s.SaveBinding(BindingInput{SubjectType: "user", SubjectID: "member", RoleIDs: []string{"system-administrator"}}, "admin", "admin")
	require.NoError(t, e)
	snapshot := s.Effective("member", "operator", nil)
	assert.True(t, snapshot.Allows("assets.manage"))
	assert.True(t, snapshot.Allows("roles.manage"))
	assert.False(t, snapshot.Allows("security.manage"))
	assert.False(t, snapshot.Allows("users.manage"))
	assert.False(t, snapshot.Allows("organizations.manage"))
	assert.False(t, snapshot.Allows("reviews.platform_login.manage"))
	assert.Contains(t, snapshot.RoleIDs, "global")
	for _, role := range s.Roles() {
		assert.NotContains(t, role.Permissions, "security.manage")
	}
	reloaded, e := OpenOrganization(path, nil, nil)
	require.NoError(t, e)
	assert.True(t, reloaded.Effective("member", "operator", nil).Allows("assets.manage"))
}
