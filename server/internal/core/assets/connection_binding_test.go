package assets

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnectionBindingPinsTargetGatewayAndWorkspaceBeforeCredentials(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "assets.json"), make([]byte, 32))
	require.NoError(t, err)
	s := NewService(store, nil)
	in := Input{Name: "gateway", Host: "127.0.0.1", Port: 22, Username: "ops", Password: "synthetic-only", HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	gate, err := s.Create(in)
	require.NoError(t, err)
	in.Name = "target"
	in.GatewayID = &gate.ID
	a, err := s.Create(in)
	require.NoError(t, err)
	binding, err := s.BindConnection(a)
	require.NoError(t, err)
	assert.Len(t, binding, 64)
	_, _, _, err = store.connectionForProtocolBound(a.ID, true, binding)
	require.NoError(t, err)
	gateInput := Input{Name: gate.Name, Host: "127.0.0.2", Port: 22, Username: gate.Username, HostKeyFingerprint: gate.HostKeyFingerprint}
	_, err = s.Update(gate.ID, gateInput)
	require.NoError(t, err)
	_, _, _, err = store.connectionForProtocolBound(a.ID, true, binding)
	assert.ErrorIs(t, err, ErrConnectionChanged)
	_, _, err = s.OpenSFTP(WithConnectionBinding(context.Background(), binding), a.ID)
	assert.ErrorIs(t, err, ErrConnectionChanged)
	_, _, err = s.OpenShell(WithConnectionBinding(context.Background(), binding), a.ID, 80, 24)
	assert.ErrorIs(t, err, ErrConnectionChanged)
	current, err := s.Get(a.ID)
	require.NoError(t, err)
	next, err := s.BindConnection(current)
	require.NoError(t, err)
	assert.NotEqual(t, binding, next)
	workspace := "/srv/approved"
	in.Password = ""
	in.SSHWorkspace = &workspace
	_, err = s.Update(a.ID, in)
	require.NoError(t, err)
	_, err = s.BindConnection(a)
	assert.ErrorIs(t, err, ErrConnectionChanged)
	_, _, _, err = store.connectionForProtocolBound(a.ID, true, next)
	assert.ErrorIs(t, err, ErrConnectionChanged)
}
