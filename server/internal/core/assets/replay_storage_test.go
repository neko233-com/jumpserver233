package assets

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReplayStorageTargetBindsRouteButSurvivesCredentialRotation(t *testing.T) {
	store, e := OpenStore(filepath.Join(t.TempDir(), "assets.json"), make([]byte, 32))
	require.NoError(t, e)
	s := NewService(store, nil)
	in := Input{Name: "storage", Host: "127.0.0.1", Port: 22, Username: "ops", Password: "synthetic-credential-1", HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	asset, e := s.Create(in)
	require.NoError(t, e)
	first, binding, e := s.ReplayStorageTarget(asset.ID)
	require.NoError(t, e)
	assert.Len(t, first, 64)
	in.Password = "synthetic-credential-2"
	_, e = s.Update(asset.ID, in)
	require.NoError(t, e)
	after, next, e := s.ReplayStorageTarget(asset.ID)
	require.NoError(t, e)
	assert.Equal(t, first, after)
	assert.NotEqual(t, binding, next)
	in.Password = ""
	in.Host = "127.0.0.2"
	_, e = s.Update(asset.ID, in)
	require.NoError(t, e)
	changed, _, e := s.ReplayStorageTarget(asset.ID)
	require.NoError(t, e)
	assert.NotEqual(t, first, changed)
	in.Host = "127.0.0.1"
	workspace := "/srv/archive"
	in.SSHWorkspace = &workspace
	_, e = s.Update(asset.ID, in)
	require.NoError(t, e)
	workspaceBinding, _, e := s.ReplayStorageTarget(asset.ID)
	require.NoError(t, e)
	assert.NotEqual(t, first, workspaceBinding)
	_, _, e = s.ReplayStorageTarget("unknown")
	assert.ErrorIs(t, e, ErrNotFound)
}
