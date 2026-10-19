package assets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const migrationResource = "aws:123456789012:us-east-1:i-0123456789abcdef0"

func migrationRow(host string) DiscoverySyncRow {
	hash := sha256.Sum256([]byte(sourceFixture + "\x00ssh\x00" + migrationResource + "\x0022"))
	return DiscoverySyncRow{FindingID: hex.EncodeToString(hash[:]), Input: discoveryInputFixture(host), Update: true, Options: DiscoverySyncOptions{PolicyID: policyFixture, MigrateCloudSSHAddress: true, CloudResourceKey: migrationResource}}
}
func createMigrationAsset(t *testing.T, s *Service, row DiscoverySyncRow) Asset {
	t.Helper()
	out, e := s.SyncDiscoveryBatch(context.Background(), sourceFixture, []DiscoverySyncRow{row}, time.Now().UTC())
	require.NoError(t, e)
	require.NoError(t, out[0].Err)
	require.Equal(t, "created", out[0].State)
	return out[0].Asset
}
func TestCloudAddressMigrationPreservesAccountsVaultHistoryAndTrust(t *testing.T) {
	s, st := discoveryFixture(t)
	row := migrationRow("192.0.2.1")
	a := createMigrationAsset(t, s, row)
	credential := sshclient.Credentials{Password: "synthetic-rotated-migration-password"}
	a, e := st.UpdateCredentials(a, &credential)
	require.NoError(t, e)
	child, e := s.CreateManagedAccount(a.ID, AccountInput{Version: accountVersion(a), Username: "ops", Password: "synthetic-child-migration-password"}, AccountActor{ID: "admin", Name: "Admin"})
	require.NoError(t, e)
	_, e = st.CreateCredentialBackup(a.ID, time.Now())
	require.NoError(t, e)
	before := st.assets[a.ID]
	beforeChild := st.assets[child.ID]
	oldOpen, oldBinding, e := s.PrepareDiscoveryGateway(a.ID)
	require.NoError(t, e)
	row.Input.Host = "2001:db8::88"
	row.Input.Password = "synthetic-source-must-not-replace-rotated-password"
	when := time.Now().UTC()
	out, e := s.SyncDiscoveryBatch(context.Background(), sourceFixture, []DiscoverySyncRow{row}, when)
	require.NoError(t, e)
	require.NoError(t, out[0].Err)
	assert.Equal(t, "address_updated", out[0].State)
	next := out[0].Asset
	assert.Equal(t, a.ID, next.ID)
	assert.Equal(t, row.Input.Host, next.Host)
	assert.Equal(t, a.CredentialRevision, next.CredentialRevision)
	assert.Equal(t, a.PasswordRotatedAt, next.PasswordRotatedAt)
	assert.Equal(t, before.Credential, st.assets[a.ID].Credential)
	assert.Equal(t, before.CredentialBackups, st.assets[a.ID].CredentialBackups)
	assert.Equal(t, beforeChild.Credential, st.assets[child.ID].Credential)
	assert.Equal(t, &DiscoveryAddressChange{PolicyID: policyFixture, From: a.Host, To: row.Input.Host, At: when}, next.Discovery.LastAddressChange)
	for id, password := range map[string]string{a.ID: credential.Password, child.ID: "synthetic-child-migration-password"} {
		asset, target, key, e := st.connection(id)
		require.NoError(t, e)
		assert.Equal(t, row.Input.Host, asset.Host)
		assert.Equal(t, row.Input.Host, target.Host)
		assert.Equal(t, password, key.Password)
	}
	_, _, _, e = oldOpen(context.Background())
	assert.ErrorIs(t, e, ErrCredentialChanged)
	_, binding, e := s.PrepareDiscoveryGateway(a.ID)
	require.NoError(t, e)
	assert.NotEqual(t, oldBinding, binding)
	next.Discovery.LastAddressChange.From = "tampered"
	public, e := s.Get(a.ID)
	require.NoError(t, e)
	assert.Equal(t, a.Host, public.Discovery.LastAddressChange.From)
	out, e = s.SyncDiscoveryBatch(context.Background(), sourceFixture, []DiscoverySyncRow{row}, when.Add(time.Hour))
	require.NoError(t, e)
	require.NoError(t, out[0].Err)
	assert.Equal(t, "unchanged", out[0].State)
	assert.Equal(t, when, out[0].Asset.Discovery.LastAddressChange.At)
	reopened, e := OpenStore(st.path, []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, e)
	assert.Equal(t, st.assets[a.ID].Asset, reopened.assets[a.ID].Asset)
	password, e := reopened.Password(child.ID)
	require.NoError(t, e)
	assert.Equal(t, "synthetic-child-migration-password", password)
}

func TestCloudAddressMigrationRejectsUntrustedOrUnownedChanges(t *testing.T) {
	for _, name := range []string{"off", "wrong_resource", "pin", "port", "protocol", "username", "gateway", "dns", "loopback", "zone", "mapped_ipv4", "missing", "metadata_only", "manual_edit", "policy_transfer", "collision"} {
		t.Run(name, func(t *testing.T) {
			s, st := discoveryFixture(t)
			row := migrationRow("192.0.2.1")
			a := createMigrationAsset(t, s, row)
			before := discoveryMapDigest(st.assets)
			row.Input.Host = "192.0.2.2"
			switch name {
			case "off":
				row.Options.MigrateCloudSSHAddress = false
			case "wrong_resource":
				row.Options.CloudResourceKey = "aws:123456789012:us-east-1:i-fffffffffffffffff"
			case "pin":
				row.Input.HostKeyFingerprint = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"
			case "port":
				row.Input.Port = 2222
			case "protocol":
				row.Input.Protocol = "telnet"
			case "username":
				row.Input.Username = "root"
			case "gateway":
				v := "other-gateway"
				row.Input.GatewayID = &v
			case "dns":
				row.Input.Host = "cloud.invalid"
			case "loopback":
				row.Input.Host = "127.0.0.1"
			case "zone":
				row.Input.Host = "fe80::1%eth0"
			case "mapped_ipv4":
				row.Input.Host = "::ffff:192.0.2.2"
			case "missing":
				row.Missing = true
			case "metadata_only":
				row.Update = false
			case "manual_edit":
				r := st.assets[a.ID]
				r.Name = "Manual name"
				st.assets[a.ID] = r
				row.Options.Overwrite = true
			case "policy_transfer":
				row.Options.PolicyID = "policy-cccccccccccccccccccccccccccccccc"
				row.Options.Overwrite = true
			case "collision":
				_, e := s.Create(discoveryInputFixture(row.Input.Host))
				require.NoError(t, e)
			}
			before = discoveryMapDigest(st.assets)
			out, e := s.SyncDiscoveryBatch(context.Background(), sourceFixture, []DiscoverySyncRow{row}, time.Now())
			require.NoError(t, e)
			require.Error(t, out[0].Err)
			assert.Equal(t, before, discoveryMapDigest(st.assets))
			assert.Equal(t, a.Host, st.assets[a.ID].Host)
		})
	}
}

func TestCloudAddressMigrationBlocksParentAndChildCredentialOperations(t *testing.T) {
	for _, kind := range []string{"parent_rotation", "child_rotation", "child_key", "child_remote", "child_running"} {
		t.Run(kind, func(t *testing.T) {
			s, st := discoveryFixture(t)
			row := migrationRow("192.0.2.1")
			a := createMigrationAsset(t, s, row)
			child, e := s.CreateManagedAccount(a.ID, AccountInput{Version: accountVersion(a), Username: "ops", Password: "synthetic-child-password"}, AccountActor{ID: "admin", Name: "Admin"})
			require.NoError(t, e)
			id := child.ID
			if kind == "parent_rotation" {
				id = a.ID
			}
			record := st.assets[id]
			switch kind {
			case "parent_rotation", "child_rotation":
				record.PendingRotation = &pendingRotation{}
			case "child_key":
				record.PendingKeyChange = &pendingKeyChange{}
			case "child_remote":
				record.RemoteAccount = &RemoteAccountState{State: "pending", OperationID: "synthetic-pending"}
			case "child_running":
				s.rotationRunning[id] = true
			}
			st.assets[id] = record
			row.Input.Host = "192.0.2.2"
			before := discoveryMapDigest(st.assets)
			out, e := s.SyncDiscoveryBatch(context.Background(), sourceFixture, []DiscoverySyncRow{row}, time.Now())
			require.NoError(t, e)
			require.Error(t, out[0].Err)
			assert.Equal(t, before, discoveryMapDigest(st.assets))
		})
	}
}

func TestCloudAddressMigrationSharedCredentialConflictsAndCancellation(t *testing.T) {
	s, st := discoveryFixture(t)
	c, e := OpenPasswordCoordinator(filepath.Join(t.TempDir(), "shared.json"), []byte("0123456789abcdef0123456789abcdef"), nil)
	require.NoError(t, e)
	require.NoError(t, s.CoordinatePasswords(c, "primary"))
	row := migrationRow("192.0.2.1")
	a := createMigrationAsset(t, s, row)
	other, _ := discoveryFixture(t)
	require.NoError(t, other.CoordinatePasswords(c, "other"))
	input := discoveryInputFixture("192.0.2.2")
	input.Password = "different-synthetic-migration-password"
	_, e = other.Create(input)
	require.NoError(t, e)
	row.Input.Host = input.Host
	before := discoveryMapDigest(st.assets)
	_, e = s.SyncDiscoveryBatch(context.Background(), sourceFixture, []DiscoverySyncRow{row}, time.Now())
	assert.ErrorIs(t, e, ErrSharedCredentialConflict)
	assert.Equal(t, before, discoveryMapDigest(st.assets))
	_, _, e = s.SyncDiscovery(sourceFixture, row.FindingID, row.Input, true, false, time.Now(), row.Options)
	assert.ErrorIs(t, e, ErrSharedCredentialConflict)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = s.SyncDiscoveryBatch(ctx, sourceFixture, []DiscoverySyncRow{row}, time.Now())
	assert.ErrorIs(t, e, context.Canceled)
	assert.Equal(t, a.Host, st.assets[a.ID].Host)
}

func TestCloudAddressMigrationPostgresTakeoverKeepsCredentialAndReceipt(t *testing.T) {
	dsn := os.Getenv("JMS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated PostgreSQL")
	}
	docs, e := storage.OpenPostgres(context.Background(), dsn, fmt.Sprintf("migration-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	a, e := docs.Scoped("organization-a")
	require.NoError(t, e)
	b, e := docs.Scoped("organization-b")
	require.NoError(t, e)
	t.Cleanup(func() { _ = a.Delete("assets"); _ = b.Delete("assets"); _ = docs.Close() })
	key := []byte("0123456789abcdef0123456789abcdef")
	st, e := OpenStoreWithDocuments(filepath.Join(t.TempDir(), "assets.json"), key, a)
	require.NoError(t, e)
	service := NewService(st, nil)
	row := migrationRow("192.0.2.1")
	asset := createMigrationAsset(t, service, row)
	row.Input.Host = "192.0.2.2"
	out, e := service.SyncDiscoveryBatch(context.Background(), sourceFixture, []DiscoverySyncRow{row}, time.Now().UTC())
	require.NoError(t, e)
	require.NoError(t, out[0].Err)
	peer, e := OpenStoreWithDocuments(filepath.Join(t.TempDir(), "peer.json"), key, a)
	require.NoError(t, e)
	assert.Equal(t, out[0].Asset, peer.assets[asset.ID].Asset)
	_, e = NewService(peer, nil).SyncDiscoveryBatch(context.Background(), sourceFixture, []DiscoverySyncRow{row}, time.Now())
	require.NoError(t, e)
	assert.Equal(t, out[0].Asset.Discovery.LastAddressChange, peer.assets[asset.ID].Discovery.LastAddressChange)
	password, e := peer.Password(asset.ID)
	require.NoError(t, e)
	assert.Equal(t, row.Input.Password, password)
	other, e := OpenStoreWithDocuments(filepath.Join(t.TempDir(), "other.json"), key, b)
	require.NoError(t, e)
	assert.Empty(t, other.List())
	raw, e := a.Load("assets")
	require.NoError(t, e)
	assert.NotContains(t, string(raw), row.Input.Password)
}
