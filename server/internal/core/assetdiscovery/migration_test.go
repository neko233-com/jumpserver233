package assetdiscovery

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/cloudinventory"
	"github.com/neko233-com/jumpserver233/server/internal/connector/inventoryprobe"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCloudMigrationIsExplicitAndPreservesStableResourceIdentity(t *testing.T) {
	var mu sync.Mutex
	host, pin := "192.0.2.7", fixturePin
	st, s, _, inventory := fixture(t, Hooks{
		CloudList: func(context.Context, string, cloudinventory.Config, cloudinventory.Credential) ([]cloudinventory.Instance, error) {
			mu.Lock()
			defer mu.Unlock()
			return []cloudinventory.Instance{{Provider: "aws", AccountID: "123456789012", Region: "us-east-1", ID: "i-0123456789abcdef0", State: "running", Name: "Migrating instance", PrivateIP: host}}, nil
		},
		Probe: func(context.Context, string, int, string, time.Duration, inventoryprobe.DialFunc) inventoryprobe.Result {
			mu.Lock()
			defer mu.Unlock()
			return inventoryprobe.Result{Open: true, SSHVerified: true, HostKeyFingerprint: pin}
		},
	})
	source, e := st.SaveSource("", cloudSourceInput(), actor(), time.Now())
	require.NoError(t, e)
	p := policyFor(t, st, source, true)
	r := runScan(t, s, source, &p, "migration-first-run")
	require.Equal(t, 1, r.Imported)
	a := inventory.List()[0].Asset
	mu.Lock()
	host = "192.0.2.8"
	mu.Unlock()
	r = runScan(t, s, source, &p, "migration-default-off")
	assert.Equal(t, 1, r.Conflicts)
	assert.Equal(t, a.Host, inventory.List()[0].Host)
	input := p.PolicyInput
	input.MigrateCloudSSHAddress = true
	p, e = st.SavePolicy(p.ID, input, actor(), time.Now())
	require.NoError(t, e)
	r = runScan(t, s, source, &p, "migration-enabled")
	require.Equal(t, "completed", r.State)
	assert.Equal(t, 1, r.Updated)
	rows, _, e := st.Findings(source.ID, 0, 100)
	require.NoError(t, e)
	require.Len(t, rows, 1)
	assert.Equal(t, "address_updated", rows[0].SyncState)
	assert.Equal(t, a.ID, rows[0].AssetID)
	next := inventory.List()[0].Asset
	assert.Equal(t, host, next.Host)
	assert.Equal(t, a.ID, next.ID)
	assert.Equal(t, a.CredentialRevision, next.CredentialRevision)
	change := next.Discovery.LastAddressChange
	r = runScan(t, s, source, &p, "migration-exact-repeat")
	assert.Zero(t, r.Updated)
	assert.Equal(t, change, inventory.List()[0].Discovery.LastAddressChange)
	mu.Lock()
	host = "192.0.2.9"
	pin = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"
	mu.Unlock()
	r = runScan(t, s, source, &p, "migration-wrong-key")
	assert.Equal(t, 1, r.Conflicts)
	assert.Equal(t, next.Host, inventory.List()[0].Host)
	reopened, e := Open(st.path, fixtureKey, nil)
	require.NoError(t, e)
	restored, e := reopened.Policy(p.ID)
	require.NoError(t, e)
	assert.True(t, restored.MigrateCloudSSHAddress)
	input = p.PolicyInput
	input.UpdateExisting = false
	_, e = st.SavePolicy(p.ID, input, actor(), time.Now())
	assert.ErrorIs(t, e, ErrInvalid)
}

func TestCloudMigrationRejectsLANAndOtherProtocolsAndNeverAdoptsManualAssets(t *testing.T) {
	var mu sync.Mutex
	host := "192.0.2.7"
	st, s, lan, inventory := fixture(t, Hooks{CloudList: func(context.Context, string, cloudinventory.Config, cloudinventory.Credential) ([]cloudinventory.Instance, error) {
		mu.Lock()
		defer mu.Unlock()
		return []cloudinventory.Instance{{Provider: "aws", AccountID: "123456789012", Region: "us-east-1", ID: "i-0123456789abcdef0", State: "running", PrivateIP: host}}, nil
	}})
	_, e := st.SavePolicy("", PolicyInput{RequestID: "lan-invalid-migration", SourceID: lan.ID, SourceRevision: lan.Revision, Name: "LAN", Enabled: true, UpdateExisting: true, MigrateCloudSSHAddress: true}, actor(), time.Now())
	assert.ErrorIs(t, e, ErrInvalid)
	other := cloudSourceInput()
	other.RequestID = "other-cloud-protocol"
	other.Template.Protocol = "telnet"
	other.Credential = nil
	otherSource, e := st.SaveSource("", other, actor(), time.Now())
	require.NoError(t, e)
	_, e = st.SavePolicy("", PolicyInput{RequestID: "db-invalid-migration", SourceID: otherSource.ID, SourceRevision: otherSource.Revision, Name: "Other", Enabled: true, UpdateExisting: true, MigrateCloudSSHAddress: true}, actor(), time.Now())
	assert.ErrorIs(t, e, ErrInvalid)
	source, e := st.SaveSource("", cloudSourceInput(), actor(), time.Now())
	require.NoError(t, e)
	manual, e := inventory.Create(assets.Input{Name: "Manual", Host: host, Port: 22, Protocol: "ssh", Username: "deploy", Password: "synthetic-manual-password", HostKeyFingerprint: fixturePin})
	require.NoError(t, e)
	p := policyFor(t, st, source, true)
	r := runScan(t, s, source, &p, "manual-existing-run")
	assert.Zero(t, r.Imported)
	input := p.PolicyInput
	input.AutoImport = false
	input.MigrateCloudSSHAddress = true
	p, e = st.SavePolicy(p.ID, input, actor(), time.Now())
	require.NoError(t, e)
	mu.Lock()
	host = "192.0.2.8"
	mu.Unlock()
	r = runScan(t, s, source, &p, "manual-not-source-owned")
	assert.Zero(t, r.Imported)
	assert.Zero(t, r.Updated)
	require.Len(t, inventory.List(), 1)
	assert.Equal(t, manual.ID, inventory.List()[0].ID)
	assert.Equal(t, manual.Host, inventory.List()[0].Host)
}

func TestMigrationRequiresCurrentSuccessfulSSHObservation(t *testing.T) {
	for _, mode := range []string{"valid", "off", "metadata_only", "stopped", "missing", "unreachable", "unverified", "other_protocol", "lan"} {
		t.Run(mode, func(t *testing.T) {
			source := Source{Provider: "aws", Template: json.RawMessage(`{"protocol":"ssh"}`)}
			policy := Policy{PolicyInput: PolicyInput{UpdateExisting: true, MigrateCloudSSHAddress: true}}
			finding := Finding{Cloud: &cloudinventory.Instance{Provider: "aws", State: "running"}, Protocol: "ssh", Result: inventoryprobe.Result{Open: true, SSHVerified: true}}
			switch mode {
			case "off":
				policy.MigrateCloudSSHAddress = false
			case "metadata_only":
				policy.UpdateExisting = false
			case "stopped":
				finding.Cloud.State = "stopped"
			case "missing":
				finding.Cloud.Missing = true
			case "unreachable":
				finding.Open = false
			case "unverified":
				finding.SSHVerified = false
			case "other_protocol":
				source.Template = json.RawMessage(`{"protocol":"rdp"}`)
			case "lan":
				source.Provider = "lan"
			}
			option := AssetSyncOptions(source, policy, finding)
			assert.Equal(t, mode == "valid", option.MigrateCloudSSHAddress)
		})
	}
}
