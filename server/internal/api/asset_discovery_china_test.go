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

func TestChinaCloudAPIKeepsAccountIdentifiersAndCredentialBoundaries(t *testing.T) {
	for _, provider := range []string{"aliyun", "tencentcloud"} {
		t.Run(provider, func(t *testing.T) {
			account, region, id := "19681320001234567", "cn-hangzhou", "i-aliyun0001"
			if provider == "tencentcloud" {
				account, region, id = "1000262009", "ap-guangzhou", "ins-cvm00001"
			}
			e := discoveryEnv(t, func(_ context.Context, p string, c cloudinventory.Config, key cloudinventory.Credential) ([]cloudinventory.Instance, error) {
				assert.Equal(t, provider, p)
				assert.Equal(t, account, c.AccountID)
				assert.Equal(t, "synthetic-china-api-secret", key.SecretAccessKey)
				return []cloudinventory.Instance{{Provider: p, AccountID: account, Region: region, ID: id, Name: "China API host", State: "running", ProviderState: "Running", PrivateIP: "192.0.2.88"}}, nil
			})
			input := discoverySourceInput()
			input.Provider = provider
			input.Targets = nil
			input.Cloud = &cloudinventory.Config{AccountID: account, Regions: []string{region}, AddressMode: "private"}
			input.CloudCredential = &cloudinventory.Credential{AccessKeyID: "STS.synthetic_cloud_key001", SecretAccessKey: "synthetic-china-api-secret"}
			assert.Equal(t, 403, e.send(t, "POST", "/api/v1/asset-discovery/sources", input, e.token, "192.0.2.1:1").Code)
			created := e.send(t, "POST", "/api/v1/asset-discovery/sources", input, e.adminToken, "192.0.2.1:1")
			require.Equal(t, 201, created.Code, created.Body.String())
			assert.NotContains(t, created.Body.String(), input.CloudCredential.AccessKeyID)
			assert.NotContains(t, created.Body.String(), input.CloudCredential.SecretAccessKey)
			var source assetdiscovery.Source
			require.NoError(t, json.Unmarshal(created.Body.Bytes(), &source))
			assert.Equal(t, account, source.Cloud.AccountID)
			repeated := e.send(t, "POST", "/api/v1/asset-discovery/sources", input, e.adminToken, "192.0.2.1:1")
			require.Equal(t, 201, repeated.Code)
			assert.JSONEq(t, created.Body.String(), repeated.Body.String())
			request := assetdiscovery.RunInput{RequestID: "china-api-run-001", SourceID: source.ID, SourceRevision: source.Revision}
			started := e.send(t, "POST", "/api/v1/asset-discovery/runs", request, e.adminToken, "192.0.2.1:1")
			require.Equal(t, 202, started.Code)
			var run assetdiscovery.Run
			require.NoError(t, json.Unmarshal(started.Body.Bytes(), &run))
			require.Eventually(t, func() bool { current, _ := e.d.AssetDiscovery.Run(run.ID); return current.State == "completed" }, 3*time.Second, 5*time.Millisecond)
			found := e.send(t, "GET", "/api/v1/asset-discovery/findings?source_id="+source.ID, nil, e.adminToken, "192.0.2.1:1")
			require.Equal(t, 200, found.Code)
			assert.Contains(t, found.Body.String(), id)
			assert.Contains(t, found.Body.String(), `"provider_state":"Running"`)
		})
	}
}
