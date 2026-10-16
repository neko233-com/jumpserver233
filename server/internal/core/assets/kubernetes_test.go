package assets

import (
	"github.com/neko233-com/jumpserver233/server/internal/connector/kubeclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestKubernetesAssetsEncryptTokenValidateProtocolAndPreserveConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assets.json")
	key := make([]byte, 32)
	store, e := OpenStore(path, key)
	require.NoError(t, e)
	s := NewService(store, nil)
	input := Input{Name: "cluster", Protocol: ProtocolKubernetes, Host: "127.0.0.1", Username: "scoped-service-account", Password: "synthetic-cluster-token", Kubernetes: &kubeclient.Settings{Namespaces: []string{"qa"}, Shell: []string{"/bin/sh"}}}
	a, e := s.Create(input)
	require.NoError(t, e)
	assert.Equal(t, 6443, a.Port)
	assert.Nil(t, s.passwordRotationStatus(a))
	assert.Nil(t, s.sshKeyRotationStatus(a))
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), input.Password)
	copy, e := s.Get(a.ID)
	require.NoError(t, e)
	copy.Kubernetes.Namespaces[0] = "mutated"
	current, e := s.Get(a.ID)
	require.NoError(t, e)
	assert.Equal(t, "qa", current.Kubernetes.Namespaces[0])
	updated, e := s.Update(a.ID, Input{Name: "renamed", Host: a.Host, Username: a.Username})
	require.NoError(t, e)
	assert.Equal(t, []string{"qa"}, updated.Kubernetes.Namespaces)
	reopened, e := OpenStore(path, key)
	require.NoError(t, e)
	assert.Len(t, reopened.List(), 1)
	for _, mutate := range []func(*Input){func(i *Input) { i.Kubernetes.Namespaces = []string{"../outside"} }, func(i *Input) { i.CredentialType = CredentialSSHKey }, func(i *Input) { i.PostgreSQL = &PostgreSQLInput{Database: "db"} }, func(i *Input) { i.Protocol = ProtocolSSH }} {
		v := input
		settings := *input.Kubernetes
		settings.Namespaces = append([]string(nil), settings.Namespaces...)
		v.Kubernetes = &settings
		mutate(&v)
		_, e = s.Create(v)
		assert.Error(t, e)
	}
}
