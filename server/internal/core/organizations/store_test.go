package organizations

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, e := Open(filepath.Join(t.TempDir(), "organizations.json"), nil)
	require.NoError(t, e)
	return s
}
func TestOrganizationDefaultMembershipRevisionArchiveAndRestart(t *testing.T) {
	s := testStore(t)
	assert.True(t, s.Enabled(DefaultID))
	assert.Equal(t, "member", s.Role(DefaultID, "existing-user"))
	assert.Equal(t, "none", s.Role("missing", "existing-user"))
	_, e := s.Save(DefaultID, Input{Name: "Default", Enabled: false, Revision: 1}, "admin")
	assert.ErrorIs(t, e, ErrProtected)
	assert.ErrorIs(t, s.Archive(DefaultID, 1, false, "admin"), ErrProtected)
	o, e := s.Save("", Input{Name: "Operations", Enabled: true}, "admin")
	require.NoError(t, e)
	assert.True(t, ValidID(o.ID))
	assert.Equal(t, "none", s.Role(o.ID, "operator"))
	m, e := s.SaveMember(o.ID, MemberInput{UserID: "operator", Role: "admin"}, "admin")
	require.NoError(t, e)
	assert.Equal(t, "admin", s.Role(o.ID, "operator"))
	_, e = s.SaveMember(o.ID, MemberInput{UserID: m.UserID, Role: "member", Revision: 0}, "admin")
	assert.ErrorIs(t, e, ErrConflict)
	_, e = s.Save("", Input{Name: "operations", Enabled: true}, "admin")
	assert.ErrorIs(t, e, ErrConflict)
	m, e = s.SaveMember(DefaultID, MemberInput{UserID: "existing-user", Role: "none"}, "admin")
	require.NoError(t, e)
	assert.Equal(t, "none", s.Role(DefaultID, m.UserID))
	m, e = s.SaveMember(DefaultID, MemberInput{UserID: m.UserID, Role: "member", Revision: m.Revision}, "admin")
	require.NoError(t, e)
	assert.Equal(t, "member", s.Role(DefaultID, m.UserID))
	require.NoError(t, s.Archive(o.ID, o.Revision, false, "admin"))
	assert.False(t, s.Enabled(o.ID))
	assert.Equal(t, "none", s.Role(o.ID, "operator"))
	assert.Len(t, s.List(false), 1)
	assert.Len(t, s.List(true), 2)
	archived, e := s.Get(o.ID)
	require.NoError(t, e)
	require.NoError(t, s.Archive(o.ID, archived.Revision, true, "admin"))
	restored, e := s.Get(o.ID)
	require.NoError(t, e)
	assert.False(t, restored.Enabled)
	restored.Input.Enabled = true
	restored, e = s.Save(restored.ID, restored.Input, "admin")
	require.NoError(t, e)
	assert.Equal(t, "admin", s.Role(o.ID, "operator"))
	reloaded, e := Open(s.path, nil)
	require.NoError(t, e)
	assert.Equal(t, "admin", reloaded.Role(o.ID, "operator"))
	rows, total := reloaded.Audit(o.ID, 0, 200)
	assert.Equal(t, 5, total)
	assert.Equal(t, "organization.save", rows[0].Action)
	assert.Equal(t, o.ID, rows[0].OrganizationID)
	copy := reloaded.List(false)
	copy[0].Name = "changed"
	defaultOrg, e := reloaded.Get(DefaultID)
	require.NoError(t, e)
	assert.Equal(t, "Default", defaultOrg.Name)
}
func TestOrganizationValidationAndRollback(t *testing.T) {
	for _, id := range []string{"", "../escape", "00000000-0000-0000-0000-000000000000", "00000000-0000-0000-0000-000000000004", "00000000-0000-0000-0000-00000000000G", "ABCDEF00-0000-0000-0000-000000000002"} {
		assert.False(t, ValidID(id), id)
	}
	s := testStore(t)
	for _, in := range []Input{{}, {Name: "bad\nname", Enabled: true}, {Name: "name", Revision: -1}, {Name: "name", Revision: 1_000_000_001}} {
		_, e := s.Save("", in, "admin")
		assert.Error(t, e)
	}
	o, e := s.Save("", Input{Name: "Rollback", Enabled: true}, "admin")
	require.NoError(t, e)
	for _, in := range []MemberInput{{UserID: "user", Role: "owner"}, {UserID: "", Role: "admin"}, {UserID: "bad\nname", Role: "member"}} {
		_, e = s.SaveMember(o.ID, in, "admin")
		assert.ErrorIs(t, e, ErrInvalid)
	}
	oldPath := s.path
	s.path = filepath.Join(oldPath, "cannot-write")
	_, e = s.SaveMember(o.ID, MemberInput{UserID: "user", Role: "admin"}, "admin")
	assert.Error(t, e)
	assert.Equal(t, "none", s.Role(o.ID, "user"))
	before, _ := s.Get(o.ID)
	before.Input.Enabled = false
	_, e = s.Save(o.ID, before.Input, "admin")
	assert.Error(t, e)
	assert.True(t, s.Enabled(o.ID))
	s.path = oldPath
	require.NoError(t, os.WriteFile(s.path, []byte(`{"organizations":{},"members":{},"audit":[]}`), 0600))
	_, e = Open(s.path, nil)
	assert.ErrorIs(t, e, ErrInvalid)
}
func TestOrganizationConcurrentRevisionIsSingleWinner(t *testing.T) {
	s := testStore(t)
	o, e := s.Save("", Input{Name: "Concurrent", Enabled: true}, "admin")
	require.NoError(t, e)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			in := o.Input
			in.Description = "updated"
			_, e := s.Save(o.ID, in, "admin")
			if e == nil {
				wins.Add(1)
			} else {
				assert.ErrorIs(t, e, ErrConflict)
			}
		})
	}
	wg.Wait()
	assert.EqualValues(t, 1, wins.Load())
}
