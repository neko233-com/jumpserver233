package assets

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGatewayGraphSnapshotPersistenceAndPendingCredentials(t *testing.T) {
	file := filepath.Join(t.TempDir(), "assets.json")
	key := make([]byte, 32)
	store, e := OpenStore(file, key)
	require.NoError(t, e)
	create := func(id, gateway string) Asset {
		a, e := store.Create(Asset{ID: id, Name: id, Host: id + ".invalid", Port: 22, Username: "ops", HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", GatewayID: gateway}, "synthetic-"+id)
		require.NoError(t, e)
		return a
	}
	root := create("root", "")
	middle := create("middle", root.ID)
	inner := create("inner", middle.ID)
	target := create("target", inner.ID)
	got, route, credentials, e := store.connection(target.ID)
	require.NoError(t, e)
	assert.Equal(t, []string{"root", "middle", "inner"}, got.GatewayIDs)
	assert.Equal(t, "synthetic-target", credentials.Password)
	require.Len(t, route.Gateways, 3)
	assert.Equal(t, "root.invalid", route.Gateways[0].Target.Host)
	assert.Equal(t, "synthetic-inner", route.Gateways[2].Credentials.Password)
	_, e = store.Create(Asset{ID: "too-deep", GatewayID: target.ID}, "synthetic")
	require.ErrorIs(t, e, ErrInvalidInput)
	_, e = store.Create(Asset{ID: "missing", GatewayID: "absent"}, "synthetic")
	require.ErrorIs(t, e, ErrInvalidInput)
	root.GatewayID = target.ID
	_, e = store.Update(root, "")
	require.ErrorIs(t, e, ErrInvalidInput)
	root.GatewayID = ""
	assert.ErrorIs(t, store.Delete(root.ID), ErrGatewayInUse)
	reopened, e := OpenStore(file, key)
	require.NoError(t, e)
	_, route, _, e = reopened.connection(target.ID)
	require.NoError(t, e)
	require.Len(t, route.Gateways, 3)
	raw, e := os.ReadFile(file)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "synthetic-root")
	encoded, e := json.Marshal(got)
	require.NoError(t, e)
	assert.NotContains(t, string(encoded), "gateway_ids")
	require.NoError(t, store.BeginPasswordRotation(inner.ID, "synthetic-replacement", time.Now()))
	_, _, _, e = store.connection(target.ID)
	require.ErrorIs(t, e, ErrRotationPending)
	_, _, _, e = store.connection(inner.ID)
	require.NoError(t, e)
	require.NoError(t, store.AbortPasswordRotation(inner.ID))
	service := NewService(store, func(_ context.Context, target sshclient.Target, c sshclient.Credentials, _ time.Duration) (sshclient.Metrics, error) {
		assert.Len(t, target.Gateways, 3)
		assert.Equal(t, "synthetic-root", target.Gateways[0].Credentials.Password)
		return sshclient.Metrics{CPUPercent: 12}, nil
	})
	item, e := service.Probe(context.Background(), target.ID)
	require.NoError(t, e)
	assert.Equal(t, "online", item.Monitor.State)
	input := Input{Name: "target-updated", Host: target.Host, Port: 22, Username: "ops", HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	updated, e := service.Update(target.ID, input)
	require.NoError(t, e)
	assert.Equal(t, inner.ID, updated.GatewayID)
	empty := ""
	input.GatewayID = &empty
	updated, e = service.Update(target.ID, input)
	require.NoError(t, e)
	assert.Empty(t, updated.GatewayID)
	require.NoError(t, store.Delete(inner.ID))
	require.NoError(t, store.Delete(middle.ID))
	require.NoError(t, store.Delete(root.ID))
}
