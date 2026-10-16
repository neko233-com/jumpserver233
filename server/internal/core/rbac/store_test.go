package rbac

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "rbac.json"), nil)
	require.NoError(t, err)
	return s
}
func TestRolesUnionGroupRevocationAndNoImplicitExecution(t *testing.T) {
	s := testStore(t)
	role, err := s.SaveRole("", RoleInput{Name: "read jobs", Permissions: []string{"jobs.view_all"}}, "admin", "admin")
	require.NoError(t, err)
	b, err := s.SaveBinding(BindingInput{SubjectType: "user", SubjectID: "alice", RoleIDs: []string{role.ID}}, "admin", "admin")
	require.NoError(t, err)
	_, err = s.SaveBinding(BindingInput{SubjectType: "group", SubjectID: "audit", RoleIDs: []string{"auditor"}}, "admin", "admin")
	require.NoError(t, err)
	effective := s.Effective("alice", "operator", []string{"audit"})
	assert.True(t, effective.Allows("jobs.view_all"))
	assert.True(t, effective.Allows("audit.replays.view_all"))
	assert.False(t, effective.Allows("assets.connect_all"))
	assert.False(t, effective.Allows("audit.sessions.terminate_all"))
	assert.False(t, s.Effective("foreign", "operator", nil).Allows("jobs.view_all"))
	assert.False(t, s.Effective("alice", "operator", nil).Allows("audit.replays.view_all"))
	b.RoleIDs = []string{}
	_, err = s.SaveBinding(b.BindingInput, "admin", "admin")
	require.NoError(t, err)
	assert.Empty(t, s.Effective("alice", "operator", nil).Permissions)
	assert.Equal(t, Catalog(), s.Effective("admin", "admin", nil).Permissions)
	var absent *Store
	assert.True(t, absent.Effective("a", "admin", nil).Allows("roles.manage"))
	assert.Empty(t, absent.Effective("a", "operator", nil).Permissions)
}
func TestRoleRevisionDeletionValidationAndImmutableBuiltins(t *testing.T) {
	s := testStore(t)
	_, err := s.SaveRole("system-administrator", RoleInput{Name: "change"}, "admin", "admin")
	assert.ErrorIs(t, err, ErrProtected)
	assert.ErrorIs(t, s.DeleteRole("auditor", 1, "a", "a"), ErrProtected)
	for _, in := range []RoleInput{{Name: ""}, {Name: "bad", Permissions: []string{"*"}}, {Name: "bad", Permissions: []string{"jobs.view_all", "jobs.view_all"}}, {Name: "bad\nname"}} {
		_, err = s.SaveRole("", in, "a", "a")
		assert.ErrorIs(t, err, ErrInvalid)
	}
	_, err = s.SaveRole("unknown", RoleInput{Name: "missing"}, "a", "a")
	assert.ErrorIs(t, err, ErrNotFound)
	role, err := s.SaveRole("", RoleInput{Name: "role", Permissions: []string{"assets.view_all"}}, "a", "a")
	require.NoError(t, err)
	_, err = s.SaveRole("", RoleInput{Name: "ROLE"}, "a", "a")
	assert.ErrorIs(t, err, ErrConflict)
	_, err = s.SaveRole(role.ID, RoleInput{Name: "rename", Revision: 0}, "a", "a")
	assert.ErrorIs(t, err, ErrConflict)
	updated, err := s.SaveRole(role.ID, RoleInput{Name: "rename", Revision: role.Revision, Permissions: []string{"jobs.view_all"}}, "a", "a")
	require.NoError(t, err)
	assert.Equal(t, 2, updated.Revision)
	binding, err := s.SaveBinding(BindingInput{SubjectType: "user", SubjectID: "u", RoleIDs: []string{role.ID}}, "a", "a")
	require.NoError(t, err)
	assert.ErrorIs(t, s.DeleteRole(role.ID, 2, "a", "a"), ErrConflict)
	_, err = s.SaveBinding(BindingInput{SubjectType: "user", SubjectID: "u", RoleIDs: []string{}, Revision: 0}, "a", "a")
	assert.ErrorIs(t, err, ErrConflict)
	binding.RoleIDs = []string{}
	_, err = s.SaveBinding(binding.BindingInput, "a", "a")
	require.NoError(t, err)
	require.NoError(t, s.DeleteRole(role.ID, 2, "a", "a"))
	_, err = s.SaveBinding(BindingInput{SubjectType: "user", SubjectID: "u", RoleIDs: []string{role.ID}, Revision: 2}, "a", "a")
	assert.ErrorIs(t, err, ErrInvalid)
}
func TestReturnedRecordsCannotChangePermissionsAndAuditPersists(t *testing.T) {
	s := testStore(t)
	role, err := s.SaveRole("", RoleInput{Name: "read", Permissions: []string{"jobs.view_all"}}, "a", "admin")
	require.NoError(t, err)
	role.Permissions[0] = "roles.manage"
	binding, err := s.SaveBinding(BindingInput{SubjectType: "user", SubjectID: "u", RoleIDs: []string{role.ID}}, "a", "admin")
	require.NoError(t, err)
	binding.RoleIDs[0] = "system-administrator"
	assert.True(t, s.Effective("u", "operator", nil).Allows("jobs.view_all"))
	assert.False(t, s.Effective("u", "operator", nil).Allows("roles.manage"))
	restored, err := Open(s.path, nil)
	require.NoError(t, err)
	assert.Equal(t, s.Effective("u", "operator", nil), restored.Effective("u", "operator", nil))
	records, total := restored.Audit(0, 50)
	assert.Equal(t, 2, total)
	assert.Equal(t, "binding.save", records[0].Action)
	assert.Equal(t, "admin", records[0].Actor)
	assert.Contains(t, string(records[1].After), "jobs.view_all")
	records[0].After[0] = 'x'
	again, _ := restored.Audit(0, 1)
	assert.NotEqual(t, byte('x'), again[0].After[0])
	wrongPath := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(wrongPath, []byte("x"), 0600))
	s.path = filepath.Join(wrongPath, "rbac.json")
	_, err = s.SaveBinding(BindingInput{SubjectType: "user", SubjectID: "u", RoleIDs: []string{"system-administrator"}, Revision: 1}, "a", "a")
	require.Error(t, err)
	assert.False(t, s.Effective("u", "operator", nil).Allows("roles.manage"))
}
func TestConcurrentRoleUpdatesHaveOneWinner(t *testing.T) {
	s := testStore(t)
	r, err := s.SaveRole("", RoleInput{Name: "concurrent"}, "a", "a")
	require.NoError(t, err)
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.SaveRole(r.ID, RoleInput{Name: "changed", Revision: 1}, "a", "a")
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success, conflicts := 0, 0
	for e := range results {
		if e == nil {
			success++
		} else if e == ErrConflict {
			conflicts++
		} else {
			t.Fatal(e)
		}
	}
	assert.Equal(t, 1, success)
	assert.Equal(t, 1, conflicts)
}
func TestRBACPostgresReload(t *testing.T) {
	url := os.Getenv("JMS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for RBAC PostgreSQL integration")
	}
	docs, err := storage.OpenPostgres(context.Background(), url, "rbac-test-"+time.Now().Format("150405.000000000"))
	require.NoError(t, err)
	defer docs.Close()
	defer docs.Delete("rbac")
	s, err := Open(filepath.Join(t.TempDir(), "rbac.json"), docs)
	require.NoError(t, err)
	_, err = s.SaveBinding(BindingInput{SubjectType: "user", SubjectID: "u", RoleIDs: []string{"auditor"}}, "a", "a")
	require.NoError(t, err)
	next, err := Open(filepath.Join(t.TempDir(), "rbac.json"), docs)
	require.NoError(t, err)
	assert.True(t, next.Effective("u", "operator", nil).Allows("audit.commands.view_all"))
	_, total := next.Audit(0, 50)
	assert.Equal(t, 1, total)
}
