package api

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/cloudinventory"
	"github.com/neko233-com/jumpserver233/server/internal/core/assetdiscovery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCloudDiscoveryAPIReadOnlyCredentialAndCompleteInventory(t *testing.T) {
	e := discoveryEnv(t, func(_ context.Context, provider string, c cloudinventory.Config, key cloudinventory.Credential) ([]cloudinventory.Instance, error) {
		assert.Equal(t, "aws_cn", provider)
		assert.Equal(t, "synthetic-cloud-api-secret", key.SecretAccessKey)
		return []cloudinventory.Instance{{Provider: provider, AccountID: c.AccountID, Region: "cn-north-1", ID: "i-0123456789abcdef0", Name: "API cloud node", State: "running", PrivateIP: "192.0.2.88"}}, nil
	})
	in := discoverySourceInput()
	in.Provider = "aws_cn"
	in.Targets = nil
	in.Cloud = &cloudinventory.Config{AccountID: "123456789012", Regions: []string{"cn-north-1"}, AddressMode: "private"}
	in.CloudCredential = &cloudinventory.Credential{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "synthetic-cloud-api-secret"}
	post := e.send(t, "POST", "/api/v1/asset-discovery/sources", in, e.adminToken, "192.0.2.1:1")
	require.Equal(t, 201, post.Code, post.Body.String())
	assert.NotContains(t, post.Body.String(), in.CloudCredential.AccessKeyID)
	assert.NotContains(t, post.Body.String(), in.CloudCredential.SecretAccessKey)
	var source assetdiscovery.Source
	require.NoError(t, json.Unmarshal(post.Body.Bytes(), &source))
	assert.True(t, source.CloudCredentialConfigured)
	input := assetdiscovery.RunInput{RequestID: "cloud-api-run-request", SourceID: source.ID, SourceRevision: source.Revision}
	post = e.send(t, "POST", "/api/v1/asset-discovery/runs", input, e.adminToken, "192.0.2.1:1")
	require.Equal(t, 202, post.Code, post.Body.String())
	var run assetdiscovery.Run
	require.NoError(t, json.Unmarshal(post.Body.Bytes(), &run))
	require.Eventually(t, func() bool { current, _ := e.d.AssetDiscovery.Run(run.ID); return current.State == "completed" }, 3*time.Second, 5*time.Millisecond)
	rows, _, err := e.d.AssetDiscovery.Store().Findings(source.ID, 0, 100)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "i-0123456789abcdef0", rows[0].Cloud.ID)
	for _, path := range []string{"sources/" + source.ID, "audit", "findings.csv?source_id=" + source.ID} {
		get := e.send(t, "GET", "/api/v1/asset-discovery/"+path, nil, e.adminToken, "192.0.2.1:1")
		require.Equal(t, 200, get.Code)
		assert.NotContains(t, get.Body.String(), in.CloudCredential.AccessKeyID)
		assert.NotContains(t, get.Body.String(), in.CloudCredential.SecretAccessKey)
	}
}
