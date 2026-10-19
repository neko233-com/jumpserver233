package sshclient

import (
	"context"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestSSHDrainCountsRouteLifetimeAndPreservesExistingSFTP(t *testing.T) {
	listener, target := startSFTPTestServer(t, t.TempDir())
	defer listener.Close()
	target, _ = routedTarget(t, target, 1)
	g := workgate.New()
	target.Admission = g
	remote, e := OpenSFTP(context.Background(), target, Credentials{Password: "sftp-test-password"}, time.Second*3)
	require.NoError(t, e)
	defer remote.Close()
	assert.Equal(t, 1, g.Snapshot()["ssh_routes"])
	g.SetClosed(true)
	_, e = remote.ReadDir(context.Background(), remote.Root())
	require.NoError(t, e)
	_, _, e = dialRoute(context.Background(), target, Credentials{Password: "sftp-test-password"}, time.Second)
	assert.ErrorIs(t, e, workgate.ErrDraining)
	require.NoError(t, remote.Close())
	require.Eventually(t, func() bool { return len(g.Snapshot()) == 0 }, time.Second, time.Millisecond)
	data, e := json.Marshal(target)
	require.NoError(t, e)
	assert.NotContains(t, string(data), "Admission")
}
func TestFailedSSHHandshakeReleasesAdmission(t *testing.T) {
	listener, target := startSFTPTestServer(t, t.TempDir())
	defer listener.Close()
	g := workgate.New()
	target.Admission = g
	_, _, e := dialRoute(context.Background(), target, Credentials{Password: "wrong"}, time.Second)
	require.Error(t, e)
	assert.Empty(t, g.Snapshot())
	g.SetClosed(true)
	target.Admission = nil
	_, _, e = dialRoute(workgate.WithGate(context.Background(), g), target, Credentials{}, time.Second)
	assert.ErrorIs(t, e, workgate.ErrDraining)
}
