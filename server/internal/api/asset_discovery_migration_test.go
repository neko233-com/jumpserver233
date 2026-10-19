package api

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/cloudinventory"
	"github.com/neko233-com/jumpserver233/server/internal/core/assetdiscovery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCloudAddressMigrationAPIKeepsStableIdentityCurrentBindingsAndExactRetries(t *testing.T) {
	var address atomic.Value
	address.Store("192.0.2.88")
	e := discoveryEnv(t, func(context.Context, string, cloudinventory.Config, cloudinventory.Credential) ([]cloudinventory.Instance, error) {
		return []cloudinventory.Instance{{Provider: "aws", AccountID: "123456789012", Region: "us-east-1", ID: "i-0123456789abcdef0", Name: "Migration API", State: "running", PrivateIP: address.Load().(string)}}, nil
	})
	input := discoverySourceInput()
	input.Provider = "aws"
	input.Targets = nil
	input.Cloud = &cloudinventory.Config{AccountID: "123456789012", Regions: []string{"us-east-1"}, AddressMode: "private"}
	input.CloudCredential = &cloudinventory.Credential{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "synthetic-migration-cloud-key"}
	created := e.send(t, "POST", "/api/v1/asset-discovery/sources", input, e.adminToken, "192.0.2.1:1")
	require.Equal(t, 201, created.Code)
	var source assetdiscovery.Source
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &source))
	policyInput := assetdiscovery.PolicyInput{RequestID: "migration-api-policy", Name: "Migration API", SourceID: source.ID, SourceRevision: source.Revision, Enabled: true, AutoImport: true, TrustNewSSHKeys: true, UpdateExisting: true, MigrateCloudSSHAddress: true}
	assert.Equal(t, 403, e.send(t, "POST", "/api/v1/asset-discovery/policies", policyInput, e.token, "192.0.2.1:1").Code)
	created = e.send(t, "POST", "/api/v1/asset-discovery/policies", policyInput, e.adminToken, "192.0.2.1:1")
	require.Equal(t, 201, created.Code)
	var policy assetdiscovery.Policy
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &policy))
	assert.True(t, policy.MigrateCloudSSHAddress)
	repeated := e.send(t, "POST", "/api/v1/asset-discovery/policies", policyInput, e.adminToken, "192.0.2.1:1")
	assert.JSONEq(t, created.Body.String(), repeated.Body.String())
	run := func(requestID string) assetdiscovery.Run {
		in := assetdiscovery.RunInput{RequestID: requestID, SourceID: source.ID, SourceRevision: source.Revision, PolicyID: policy.ID, PolicyRevision: policy.Revision}
		response := e.send(t, "POST", "/api/v1/asset-discovery/runs", in, e.adminToken, "192.0.2.1:1")
		require.Equal(t, 202, response.Code)
		var started, finished assetdiscovery.Run
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &started))
		require.Eventually(t, func() bool {
			finished, _ = e.d.AssetDiscovery.Run(started.ID)
			return finished.State == "completed" || finished.State == "failed"
		}, 4*time.Second, 5*time.Millisecond)
		require.Equal(t, "completed", finished.State)
		return finished
	}
	first := run("migration-api-first")
	require.Equal(t, 1, first.Imported)
	findings, _, err := e.d.AssetDiscovery.Store().Findings(source.ID, 0, 100)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	id := findings[0].AssetID
	old, err := e.d.Assets.Get(id)
	require.NoError(t, err)
	oldBinding := databaseRouteBinding(e.d, old)
	address.Store("192.0.2.99")
	second := run("migration-api-address")
	assert.Equal(t, 1, second.Updated)
	assert.Zero(t, second.Conflicts)
	current, err := e.d.Assets.Get(id)
	require.NoError(t, err)
	assert.Equal(t, address.Load(), current.Host)
	assert.Equal(t, old.CredentialRevision, current.CredentialRevision)
	assert.Equal(t, old.HostKeyFingerprint, current.HostKeyFingerprint)
	assert.NotEqual(t, oldBinding, databaseRouteBinding(e.d, current))
	assert.Equal(t, old.Host, current.Discovery.LastAddressChange.From)
	assert.Equal(t, policy.ID, current.Discovery.LastAddressChange.PolicyID)
	findings, _, err = e.d.AssetDiscovery.Store().Findings(source.ID, 0, 100)
	require.NoError(t, err)
	assert.Equal(t, id, findings[0].AssetID)
	assert.Equal(t, "address_updated", findings[0].SyncState)
	response := e.send(t, "GET", "/api/v1/assets", nil, e.adminToken, "192.0.2.1:1")
	require.Equal(t, 200, response.Code)
	assert.NotContains(t, response.Body.String(), input.Credential.Password)
	assert.NotContains(t, response.Body.String(), input.CloudCredential.SecretAccessKey)
	assert.Equal(t, second.ID, run("migration-api-address").ID)
	third := run("migration-api-noop")
	assert.Zero(t, third.Updated)
	assert.Zero(t, third.Imported)
	policyInput = policy.PolicyInput
	policyInput.Revision = 0
	policyInput.Name = "Stale change"
	assert.Equal(t, 409, e.send(t, "PUT", "/api/v1/asset-discovery/policies/"+policy.ID, policyInput, e.adminToken, "192.0.2.1:1").Code)
}
