package assets

import (
	"context"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sourceFixture = "source-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const policyFixture = "policy-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func discoveryFixture(t *testing.T) (*Service, *Store) {
	t.Helper()
	st, e := OpenStore(filepath.Join(t.TempDir(), "assets.json"), []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, e)
	return NewService(st, nil), st
}
func discoveryInputFixture(host string) Input {
	return Input{Name: "discovered", Host: host, Port: 22, Protocol: "ssh", Username: "deploy", Password: "synthetic-import-password", HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
}
func TestDiscoveryBatchPreservesRotatedCredentialAndExplicitOwnership(t *testing.T) {
	s, st := discoveryFixture(t)
	finding := strings.Repeat("c", 64)
	row := DiscoverySyncRow{FindingID: finding, Input: discoveryInputFixture("192.0.2.1"), Update: true, Options: DiscoverySyncOptions{PolicyID: policyFixture}}
	results, e := s.SyncDiscoveryBatch(context.Background(), sourceFixture, []DiscoverySyncRow{row}, time.Now())
	require.NoError(t, e)
	require.NoError(t, results[0].Err)
	a := results[0].Asset
	assert.Equal(t, "created", results[0].State)
	credential := sshclient.Credentials{Password: "synthetic-rotated-password"}
	_, e = st.UpdateCredentials(a, &credential)
	require.NoError(t, e)
	row.Input.Name = "synced-name"
	results, e = s.SyncDiscoveryBatch(context.Background(), sourceFixture, []DiscoverySyncRow{row}, time.Now())
	require.NoError(t, e)
	require.NoError(t, results[0].Err)
	assert.Equal(t, "updated", results[0].State)
	_, _, saved, e := st.connection(a.ID)
	require.NoError(t, e)
	assert.Equal(t, credential.Password, saved.Password)
	row.Options.PolicyID = "policy-" + strings.Repeat("d", 32)
	results, e = s.SyncDiscoveryBatch(context.Background(), sourceFixture, []DiscoverySyncRow{row}, time.Now())
	require.NoError(t, e)
	assert.ErrorIs(t, results[0].Err, ErrCredentialChanged)
	row.Options.Overwrite = true
	row.Input.Name = "transferred"
	results, e = s.SyncDiscoveryBatch(context.Background(), sourceFixture, []DiscoverySyncRow{row}, time.Now())
	require.NoError(t, e)
	require.NoError(t, results[0].Err)
	assert.Equal(t, row.Options.PolicyID, results[0].Asset.Discovery.PolicyID)
	row.Input.HostKeyFingerprint = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"
	results, e = s.SyncDiscoveryBatch(context.Background(), sourceFixture, []DiscoverySyncRow{row}, time.Now())
	require.NoError(t, e)
	assert.ErrorIs(t, results[0].Err, ErrCredentialChanged)
	_, e = s.SyncDiscoveryBatch(context.Background(), sourceFixture, []DiscoverySyncRow{row, row}, time.Now())
	assert.ErrorIs(t, e, ErrInvalidInput)
	reopened, e := OpenStore(st.path, []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, e)
	assert.Len(t, reopened.List(), 1)
}
func TestDiscoveryBatchCancellationRollbackAndSharedCredentialConflict(t *testing.T) {
	s, st := discoveryFixture(t)
	coordinator, e := OpenPasswordCoordinator(filepath.Join(t.TempDir(), "shared.json"), []byte("0123456789abcdef0123456789abcdef"), nil)
	require.NoError(t, e)
	require.NoError(t, s.CoordinatePasswords(coordinator, "default"))
	rows := []DiscoverySyncRow{}
	for i := range 100 {
		rows = append(rows, DiscoverySyncRow{FindingID: fmt.Sprintf("%064x", i+1), Input: discoveryInputFixture(fmt.Sprintf("192.0.2.%d", i+1)), Options: DiscoverySyncOptions{PolicyID: policyFixture}})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = s.SyncDiscoveryBatch(ctx, sourceFixture, rows, time.Now())
	assert.ErrorIs(t, e, context.Canceled)
	assert.Empty(t, st.List())
	other, otherStore := discoveryFixture(t)
	require.NoError(t, other.CoordinatePasswords(coordinator, "other"))
	aliasInput := rows[0].Input
	aliasInput.Password = "different-synthetic-password"
	alias, e := other.Create(aliasInput)
	require.NoError(t, e)
	_, e = s.SyncDiscoveryBatch(context.Background(), sourceFixture, rows, time.Now())
	assert.ErrorIs(t, e, ErrSharedCredentialConflict)
	assert.Empty(t, st.List())
	replacement := sshclient.Credentials{Password: rows[0].Input.Password}
	_, e = otherStore.UpdateCredentials(alias, &replacement)
	require.NoError(t, e)
	out, e := s.SyncDiscoveryBatch(context.Background(), sourceFixture, rows, time.Now())
	require.NoError(t, e)
	require.Len(t, out, 100)
	for _, r := range out {
		require.NoError(t, r.Err)
	}
	assert.Len(t, st.List(), 100)
}
func TestDiscoveryDoesNotAdoptManualAssetsAndCredentiallessTemplatesAreBounded(t *testing.T) {
	s, _ := discoveryFixture(t)
	input := discoveryInputFixture("192.0.2.1")
	manual, e := s.Create(input)
	require.NoError(t, e)
	out, e := s.SyncDiscoveryBatch(context.Background(), sourceFixture, []DiscoverySyncRow{{FindingID: strings.Repeat("e", 64), Input: input}}, time.Now())
	require.NoError(t, e)
	assert.Equal(t, "existing", out[0].State)
	assert.Equal(t, manual.ID, out[0].Asset.ID)
	assert.Nil(t, out[0].Asset.Discovery)
	for _, protocol := range []string{"ssh", "rdp", "telnet", "postgresql", "mysql", "mariadb", "sqlserver", "clickhouse", "redis", "mongodb", "kubernetes"} {
		_, _, e := NormalizeDiscoveryTemplate(Input{Protocol: protocol}, true)
		assert.NoError(t, e, protocol)
	}
	_, _, e = NormalizeDiscoveryTemplate(Input{Protocol: "invalid"}, true)
	assert.Error(t, e)
}
