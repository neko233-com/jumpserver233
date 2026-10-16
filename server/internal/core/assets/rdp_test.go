package assets

import (
	"github.com/neko233-com/jumpserver233/server/internal/connector/rdpclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestRDPVaultValidationCloningAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assets.json")
	store, e := OpenStore(path, make([]byte, 32))
	require.NoError(t, e)
	service := NewService(store, nil)
	input := Input{Name: "Desktop", Protocol: ProtocolRDP, Host: "127.0.0.1", Username: "qa", Password: "synthetic-rdp-vault-pass", RDP: &rdpclient.Settings{}}
	a, e := service.Create(input)
	require.NoError(t, e)
	assert.Equal(t, 3389, a.Port)
	assert.Equal(t, "nla", a.RDP.Security)
	assert.Nil(t, service.passwordRotationStatus(a))
	assert.Nil(t, service.sshKeyRotationStatus(a))
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), input.Password)
	copy, e := service.Get(a.ID)
	require.NoError(t, e)
	copy.RDP.Domain = "mutated"
	current, e := service.Get(a.ID)
	require.NoError(t, e)
	assert.Empty(t, current.RDP.Domain)
	updated, e := service.Update(a.ID, Input{Name: "renamed", Host: a.Host, Username: a.Username})
	require.NoError(t, e)
	assert.Equal(t, a.RDP, updated.RDP)
	reopened, e := OpenStore(path, make([]byte, 32))
	require.NoError(t, e)
	assert.Len(t, reopened.List(), 1)
	for _, mutate := range []func(*Input){func(i *Input) { i.RDP.Security = "rdp" }, func(i *Input) { i.RDP.Width = 10000 }, func(i *Input) { i.CredentialType = CredentialSSHKey }, func(i *Input) { i.KeyRotationEnabled = new(true) }, func(i *Input) { i.Protocol = ProtocolSSH }, func(i *Input) { i.Password = "bad\nsecret" }, func(i *Input) { i.PostgreSQL = &PostgreSQLInput{} }} {
		v := input
		copy := *input.RDP
		v.RDP = &copy
		mutate(&v)
		_, e = service.Create(v)
		assert.Error(t, e)
	}
}
