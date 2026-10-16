package assets

import (
	"github.com/neko233-com/jumpserver233/server/internal/connector/telnetclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestTelnetVaultValidationCloningAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assets.json")
	key := make([]byte, 32)
	store, e := OpenStore(path, key)
	require.NoError(t, e)
	s := NewService(store, nil)
	input := Input{Name: "Telnet", Protocol: ProtocolTelnet, Host: "127.0.0.1", Username: "qa", Password: "synthetic-telnet-vault-password", Telnet: &telnetclient.Settings{}}
	a, e := s.Create(input)
	require.NoError(t, e)
	assert.Equal(t, 992, a.Port)
	assert.Equal(t, "verify-full", a.Telnet.TLSMode)
	assert.Nil(t, s.passwordRotationStatus(a))
	assert.Nil(t, s.sshKeyRotationStatus(a))
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), input.Password)
	copy, e := s.Get(a.ID)
	require.NoError(t, e)
	copy.Telnet.SuccessPrompt = "mutated"
	current, e := s.Get(a.ID)
	require.NoError(t, e)
	assert.NotEqual(t, "mutated", current.Telnet.SuccessPrompt)
	updated, e := s.Update(a.ID, Input{Name: "renamed", Host: a.Host, Username: a.Username})
	require.NoError(t, e)
	assert.Equal(t, a.Telnet, updated.Telnet)
	reopened, e := OpenStore(path, key)
	require.NoError(t, e)
	assert.Len(t, reopened.List(), 1)
	input.Telnet = &telnetclient.Settings{TLSMode: "disable"}
	plain, e := s.Create(input)
	require.NoError(t, e)
	assert.Equal(t, 23, plain.Port)
	for _, mutate := range []func(*Input){func(i *Input) { i.Telnet.SuccessPrompt = ".*" }, func(i *Input) { i.Password = "injected\rpassword" }, func(i *Input) { i.CredentialType = CredentialSSHKey }, func(i *Input) { i.KeyRotationEnabled = new(true) }, func(i *Input) { i.PostgreSQL = &PostgreSQLInput{Database: "db"} }, func(i *Input) { i.Protocol = ProtocolSSH }} {
		v := input
		copy := *input.Telnet
		v.Telnet = &copy
		mutate(&v)
		_, e = s.Create(v)
		assert.Error(t, e)
	}
}
