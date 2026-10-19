package assets

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/inventoryprobe"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshgateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCloudAddressMigrationUsesRealOpenSSHThroughPinnedGateway(t *testing.T) {
	address := os.Getenv("JMS_TEST_KEY_HOST_ADDR")
	if address == "" {
		t.Skip("requires the disposable OpenSSH fixture")
	}
	require.True(t, strings.HasPrefix(os.Getenv("JMS_TEST_KEY_HOST_NAME"), "jms233-keyhost-"))
	gateway, e := sshgateway.Start("127.0.0.1:0", map[string]string{"192.0.2.7:22": address, "192.0.2.8:22": address})
	require.NoError(t, e)
	t.Cleanup(gateway.Close)
	service, store := discoveryFixture(t)
	host, portText, e := net.SplitHostPort(gateway.Address())
	require.NoError(t, e)
	port, e := strconv.Atoi(portText)
	require.NoError(t, e)
	gatewayAsset, e := service.Create(Input{Name: "Migration gateway", Host: host, Port: port, Protocol: "ssh", Username: sshgateway.Username, Password: sshgateway.Password, HostKeyFingerprint: gateway.Fingerprint})
	require.NoError(t, e)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dial, closeForwarder, current, e := service.DiscoveryGateway(ctx, gatewayAsset.ID)
	require.NoError(t, e)
	defer closeForwarder()
	row := migrationRow("192.0.2.7")
	row.Input.Username = "keyqa"
	row.Input.Password = "synthetic-keyhost-password-233"
	row.Input.GatewayID = &gatewayAsset.ID
	observe := func(host string) string {
		t.Helper()
		probe := inventoryprobe.Probe(ctx, host, 22, "ssh", 5*time.Second, dial)
		require.True(t, probe.Open)
		require.True(t, probe.SSHVerified)
		require.Empty(t, probe.ErrorCode)
		return probe.HostKeyFingerprint
	}
	row.Input.HostKeyFingerprint = observe(row.Input.Host)
	require.Equal(t, os.Getenv("JMS_TEST_KEY_HOST_FINGERPRINT"), row.Input.HostKeyFingerprint)
	a := createMigrationAsset(t, service, row)
	execute := func() {
		t.Helper()
		_, target, key, e := store.connection(a.ID)
		require.NoError(t, e)
		result, e := sshclient.Exec(ctx, target, key, "printf migration-gateway-ok")
		require.NoError(t, e)
		assert.Equal(t, 0, result.ExitCode)
		assert.Equal(t, "migration-gateway-ok", result.Stdout)
	}
	execute()
	oldOpen, _, e := service.PrepareDiscoveryGateway(a.ID)
	require.NoError(t, e)
	row.Input.Host = "192.0.2.8"
	row.Input.HostKeyFingerprint = observe(row.Input.Host)
	row.Input.Password = "synthetic-source-password-must-not-overwrite"
	out, e := service.SyncDiscoveryBatch(ctx, sourceFixture, []DiscoverySyncRow{row}, time.Now().UTC())
	require.NoError(t, e)
	require.NoError(t, out[0].Err)
	assert.Equal(t, "address_updated", out[0].State)
	assert.Equal(t, a.ID, out[0].Asset.ID)
	execute()
	_, _, _, e = oldOpen(ctx)
	assert.ErrorIs(t, e, ErrCredentialChanged)
	assert.True(t, current())
	assert.GreaterOrEqual(t, gateway.Forwards(), int64(4))
}
