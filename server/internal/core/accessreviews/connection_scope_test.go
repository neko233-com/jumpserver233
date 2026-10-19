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
	for _, value := range []ConnectionContext{{Binding: "bad"}, {Binding: strings.Repeat("a", 64), Workspace: "/etc", Identity: strings.Repeat("b", 64)}, {Binding: strings.Repeat("a", 64), Workspace: "/srv/approved"}, {Binding: strings.Repeat("A", 64)}, {Binding: strings.Repeat("a", 64), Identity: strings.Repeat("b", 64)}} {
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

func TestExecutionDirectoryScopeCanonicalApprovalBindsPathIdentityAndPolicy(t *testing.T) {
	proof := ConnectionContext{Binding: strings.Repeat("a", 64), Workspace: "/srv/work", Identity: strings.Repeat("b", 64), WorkingDirectory: "/srv/work/app", WorkingIdentity: strings.Repeat("c", 64), PolicyKey: strings.Repeat("d", 64)}
	scope, err := ExecutionScope(proof)
	require.NoError(t, err)
	parsed, err := ParseConnectionScope(scope)
	require.NoError(t, err)
	assert.Equal(t, proof, parsed)
	_, err = ParseConnectionScope("cx1-" + strings.TrimPrefix(scope, "cx2-"))
	require.ErrorIs(t, err, ErrInvalid)
	_, err = ParseConnectionScope(scope + "=")
	require.ErrorIs(t, err, ErrInvalid)
	for _, mutate := range []func(*ConnectionContext){func(p *ConnectionContext) { p.WorkingDirectory = "/srv/outside" }, func(p *ConnectionContext) { p.WorkingIdentity = "" }, func(p *ConnectionContext) { p.Workspace = "" }, func(p *ConnectionContext) { p.PolicyKey = "bad" }} {
		bad := proof
		mutate(&bad)
		_, err = ExecutionScope(bad)
		require.ErrorIs(t, err, ErrInvalid)
	}
	file := filepath.Join(t.TempDir(), "reviews")
	s, err := OpenStore(file)
	require.NoError(t, err)
	r, err := s.RequestScopedAction("operator", "Operator", "asset", "Host", "ops", ActionSSH, scope)
	require.NoError(t, err)
	assert.Equal(t, proof.WorkingDirectory, r.WorkingDirectory)
	require.NoError(t, s.Resolve(r.ID, "Reviewer", true))
	s, err = OpenStore(file)
	require.NoError(t, err)
	for _, mutate := range []func(*ConnectionContext){func(p *ConnectionContext) { p.WorkingDirectory = "/srv/work/other" }, func(p *ConnectionContext) { p.WorkingIdentity = strings.Repeat("e", 64) }, func(p *ConnectionContext) { p.PolicyKey = strings.Repeat("e", 64) }} {
		changed := proof
		mutate(&changed)
		changedScope, err := ExecutionScope(changed)
		require.NoError(t, err)
		ok, err := s.ConsumeApprovedScopedAction("operator", "asset", "ops", ActionSSH, changedScope)
		require.NoError(t, err)
		assert.False(t, ok)
	}
	var consumed atomic.Int32
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			ok, err := s.ConsumeApprovedScopedAction("operator", "asset", "ops", ActionSSH, scope)
			assert.NoError(t, err)
			if ok {
				consumed.Add(1)
			}
		})
	}
	group.Wait()
	assert.EqualValues(t, 1, consumed.Load())
}
