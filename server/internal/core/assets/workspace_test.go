package assets

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/core/tickets"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkspacePersistsInheritsAndBlocksUnconfinedChannels(t *testing.T) {
	file := filepath.Join(t.TempDir(), "assets.json")
	store, e := OpenStore(file, make([]byte, 32))
	require.NoError(t, e)
	s := NewService(store, nil)
	directory := "/srv/workspace"
	in := Input{Name: "workspace", Host: "127.0.0.1", Port: 22, Username: "ops", Password: "synthetic-workspace-password", HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", SSHWorkspace: &directory}
	a, e := s.Create(in)
	require.NoError(t, e)
	assert.Equal(t, directory, a.SSHWorkspace)
	_, _, e = s.OpenSFTP(context.Background(), a.ID)
	require.ErrorIs(t, e, hostagent.ErrWorkspaceUnavailable)
	_, _, e = s.PrepareDiscoveryGateway(a.ID)
	require.ErrorIs(t, e, ErrInvalidInput)
	child := inheritAccount(a, Asset{ID: "account-test", Username: "second", ParentAssetID: a.ID})
	assert.Equal(t, directory, child.SSHWorkspace)
	refs := []tickets.Target{{Kind: "asset", ID: a.ID, Account: a.Username, Actions: []string{"connect"}}}
	before, e := s.ResolveAccessTargets(context.Background(), refs, nil)
	require.NoError(t, e)
	// Omission preserves an administrator's existing policy.
	in.SSHWorkspace = nil
	in.Password = ""
	_, e = s.Update(a.ID, in)
	require.NoError(t, e)
	reopened, e := OpenStore(file, make([]byte, 32))
	require.NoError(t, e)
	assert.Equal(t, directory, reopened.List()[0].SSHWorkspace)
	empty := ""
	in.SSHWorkspace = &empty
	_, e = s.Update(a.ID, in)
	require.NoError(t, e)
	after, e := s.ResolveAccessTargets(context.Background(), refs, nil)
	require.NoError(t, e)
	assert.NotEqual(t, before[0].Binding, after[0].Binding)
	directory = "/etc"
	in.SSHWorkspace = &directory
	_, e = s.Update(a.ID, in)
	require.ErrorIs(t, e, ErrInvalidInput)
}

func TestWorkspaceGatewayMutationCannotOpenAnExistingBypass(t *testing.T) {
	store, e := OpenStore(filepath.Join(t.TempDir(), "assets.json"), make([]byte, 32))
	require.NoError(t, e)
	g, e := store.Create(Asset{ID: "gateway", Name: "Gateway", Host: "127.0.0.1", Port: 22, Username: "ops"}, "synthetic")
	require.NoError(t, e)
	_, e = store.Create(Asset{ID: "target", GatewayID: g.ID}, "synthetic")
	require.NoError(t, e)
	g.SSHWorkspace = "/srv/workspace"
	_, e = store.Update(g, "")
	require.ErrorIs(t, e, ErrInvalidInput)
}
