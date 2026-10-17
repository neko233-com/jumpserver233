package accessreviews

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountCollectionPermitsAreScopedToOneRunAndNeverAuthorizeSSH(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reviews.json")
	s, e := OpenStore(path)
	require.NoError(t, e)
	normal, e := s.Request("user", "Operator", "asset", "Linux", "ops")
	require.NoError(t, e)
	scope := "plan-00000000000000000000000000000001:1"
	collection, e := s.RequestScopedAction("user", "Operator", "asset", "Linux", "ops", ActionAccountDiscovery, scope)
	require.NoError(t, e)
	assert.NotEqual(t, normal.ID, collection.ID)
	require.NoError(t, s.Resolve(normal.ID, "Reviewer", true))
	ok, e := s.ConsumeApprovedScopedAction("user", "asset", "ops", ActionAccountDiscovery, scope)
	require.NoError(t, e)
	assert.False(t, ok)
	require.NoError(t, s.Resolve(collection.ID, "Reviewer", true))
	ok, e = s.ConsumeApprovedScopedAction("user", "asset", "ops", ActionAccountDiscovery, "plan-00000000000000000000000000000001:2")
	require.NoError(t, e)
	assert.False(t, ok)
	ok, e = s.ConsumeApproved("user", "asset", "ops")
	require.NoError(t, e)
	assert.True(t, ok)
	ok, e = s.ConsumeApproved("user", "asset", "ops")
	require.NoError(t, e)
	assert.False(t, ok)
	ok, e = s.ConsumeApprovedScopedAction("user", "asset", "ops", ActionAccountDiscovery, scope)
	require.NoError(t, e)
	assert.True(t, ok)
	ok, e = s.ConsumeApprovedScopedAction("user", "asset", "ops", ActionAccountDiscovery, scope)
	require.NoError(t, e)
	assert.False(t, ok)
	reopened, e := OpenStore(path)
	require.NoError(t, e)
	record, e := reopened.Get(collection.ID)
	require.NoError(t, e)
	assert.Equal(t, StateConsumed, record.State)
	assert.Equal(t, scope, record.RequestScope)
}

func TestCancelOwnedCollectionApprovalExpiresUnusedPermitAndSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reviews.json")
	s, e := OpenStore(path)
	require.NoError(t, e)
	scope := "plan-00000000000000000000000000000001:1"
	r, e := s.RequestScopedAction("user", "Operator", "asset", "Linux", "ops", ActionAccountDiscovery, scope)
	require.NoError(t, e)
	require.NoError(t, s.Resolve(r.ID, "Reviewer", true))
	assert.ErrorIs(t, s.CancelOwned(r.ID, "other-user"), ErrNotFound)
	require.NoError(t, s.CancelOwned(r.ID, "user"))
	require.NoError(t, s.CancelOwned(r.ID, "user"))
	require.NoError(t, s.CancelOwned("already-pruned", "user"))
	assert.ErrorIs(t, s.Resolve(r.ID, "Reviewer", true), ErrNotPending)
	reopened, e := OpenStore(path)
	require.NoError(t, e)
	record, e := reopened.Get(r.ID)
	require.NoError(t, e)
	assert.Equal(t, StateExpired, record.State)
	ok, e := reopened.ConsumeApprovedScopedAction("user", "asset", "ops", ActionAccountDiscovery, scope)
	require.NoError(t, e)
	assert.False(t, ok)
	_, e = s.RequestAction("user", "Operator", "asset", "Linux", "ops", ActionAccountDiscovery)
	assert.ErrorIs(t, e, ErrInvalid)
	_, e = s.RequestScopedAction("user", "Operator", "asset", "Linux", "ops", ActionSSH, scope)
	assert.ErrorIs(t, e, ErrInvalid)
}
