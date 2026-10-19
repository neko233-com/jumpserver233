package accessreviews

import (
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnectionScopeCanonicalValidation(t *testing.T) {
	for _, directory := range []string{"", "/srv/approved"} {
		identity := ""
		if directory != "" {
			identity = strings.Repeat("b", 64)
		}
		scope, err := ConnectionScope(strings.Repeat("a", 64), directory, identity)
		require.NoError(t, err)
		value, err := ParseConnectionScope(scope)
		require.NoError(t, err)
		assert.Equal(t, directory, value.Workspace)
		assert.Equal(t, identity, value.Identity)
		for _, bad := range []string{"", scope + "=", "cx1-!!!", strings.Repeat("a", 2049)} {
			_, err = ParseConnectionScope(bad)
			assert.ErrorIs(t, err, ErrInvalid)
		}
	}
	for _, value := range []ConnectionContext{{"bad", "", ""}, {strings.Repeat("a", 64), "/etc", strings.Repeat("b", 64)}, {strings.Repeat("a", 64), "/srv/approved", ""}, {strings.Repeat("A", 64), "", ""}, {strings.Repeat("a", 64), "", strings.Repeat("b", 64)}} {
		_, err := ConnectionScope(value.Binding, value.Workspace, value.Identity)
		assert.ErrorIs(t, err, ErrInvalid)
	}
}

func TestConnectionScopedApprovalPersistsAndConsumesExactlyOnce(t *testing.T) {
	for _, action := range []string{ActionSSH, ActionSFTP} {
		t.Run(action, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "reviews.json")
			s, err := OpenStore(file)
			require.NoError(t, err)
			scope, err := ConnectionScope(strings.Repeat("a", 64), "/srv/approved", strings.Repeat("b", 64))
			require.NoError(t, err)
			r, err := s.RequestScopedAction("operator", "Operator", "asset", "Host", "ops", action, scope)
			require.NoError(t, err)
			assert.Equal(t, "/srv/approved", r.Workspace)
			again, err := s.RequestScopedAction("operator", "Operator", "asset", "Host", "ops", action, scope)
			require.NoError(t, err)
			assert.Equal(t, r.ID, again.ID)
			require.NoError(t, s.Resolve(r.ID, "Reviewer", true))
			s, err = OpenStore(file)
			require.NoError(t, err)
			changed, err := ConnectionScope(strings.Repeat("a", 64), "/srv/approved", strings.Repeat("c", 64))
			require.NoError(t, err)
			ok, err := s.ConsumeApprovedScopedAction("operator", "asset", "ops", action, changed)
			require.NoError(t, err)
			assert.False(t, ok)
			ok, err = s.ConsumeApprovedAction("operator", "asset", "ops", action)
			require.NoError(t, err)
			assert.False(t, ok)
			var consumed atomic.Int32
			var group sync.WaitGroup
			for range 8 {
				group.Go(func() {
					ok, err := s.ConsumeApprovedScopedAction("operator", "asset", "ops", action, scope)
					assert.NoError(t, err)
					if ok {
						consumed.Add(1)
					}
				})
			}
			group.Wait()
			assert.EqualValues(t, 1, consumed.Load())
		})
	}
}
