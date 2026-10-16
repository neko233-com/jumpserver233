package assets

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRealOpenSSHSharedPasswordRotationAndRestoreAcrossOrganizations(t *testing.T) {
	address := os.Getenv("JMS_TEST_KEY_HOST_ADDR")
	if address == "" {
		t.Skip("set JMS_TEST_KEY_HOST_ADDR for disposable shared password SSH integration")
	}
	require.True(t, strings.HasPrefix(os.Getenv("JMS_TEST_KEY_HOST_NAME"), "jms233-keyhost-"))
	host, portText, e := net.SplitHostPort(address)
	require.NoError(t, e)
	port, e := strconv.Atoi(portText)
	require.NoError(t, e)
	a := Asset{ID: "shared-real-host", Name: "Shared Linux password QA", Host: host, Port: port, Username: "rotationqa", HostKeyFingerprint: os.Getenv("JMS_TEST_KEY_HOST_FINGERPRINT")}
	c, e := OpenPasswordCoordinator(filepath.Join(t.TempDir(), "shared.json"), make([]byte, 32), nil)
	require.NoError(t, e)
	services := []*Service{}
	for i, scope := range []string{"first", "second"} {
		key := make([]byte, 32)
		key[0] = byte(i)
		st, e := OpenStore(filepath.Join(t.TempDir(), "assets.json"), key)
		require.NoError(t, e)
		_, e = st.Create(a, "synthetic-keyhost-password-233")
		require.NoError(t, e)
		s := NewService(st, nil)
		require.NoError(t, s.CoordinatePasswords(c, scope))
		services = append(services, s)
	}
	backup, e := services[0].CreateCredentialBackup(a.ID, "integration.user")
	require.NoError(t, e)
	_, e = services[0].RotatePassword(context.Background(), a.ID)
	require.NoError(t, e)
	defer func() {
		_, e := services[0].RestoreCredentialBackup(context.Background(), a.ID, backup.ID, "integration.cleanup")
		assert.NoError(t, e)
	}()
	for _, s := range services {
		item, e := s.Probe(context.Background(), a.ID)
		require.NoError(t, e)
		assert.Equal(t, "online", item.Monitor.State)
		_, target, creds, e := s.store.connection(a.ID)
		require.NoError(t, e)
		require.NoError(t, sshclient.VerifyPassword(context.Background(), target, creds, 5*time.Second))
		assert.NotEqual(t, "synthetic-keyhost-password-233", creds.Password)
	}
	_, target, _, e := services[0].store.connection(a.ID)
	require.NoError(t, e)
	assert.Error(t, sshclient.VerifyPassword(context.Background(), target, sshclient.Credentials{Password: "synthetic-keyhost-password-233"}, time.Second))
}
