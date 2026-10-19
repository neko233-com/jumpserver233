package assetdiscovery

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/cloudinventory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChinaSourcesPreserveIdentityCredentialsAndMissesAcrossCloudDenial(t *testing.T) {
	for _, provider := range []string{"aliyun", "tencentcloud"} {
		t.Run(provider, func(t *testing.T) {
			account, region, id := "19681320001234567", "cn-hangzhou", "i-aliyun0001"
			if provider == "tencentcloud" {
				account, region, id = "1000262009", "ap-guangzhou", "ins-cvm00001"
			}
			var denied atomic.Bool
			st, s, _, inventory := fixture(t, Hooks{CloudList: func(_ context.Context, p string, config cloudinventory.Config, key cloudinventory.Credential) ([]cloudinventory.Instance, error) {
				assert.Equal(t, provider, p)
				assert.Equal(t, account, config.AccountID)
				assert.NotEmpty(t, key.SecretAccessKey)
				if denied.Load() {
					return nil, cloudinventory.ErrPermission
				}
				return []cloudinventory.Instance{{Provider: provider, AccountID: account, Region: region, ID: id, Name: "China inventory host", State: "running", ProviderState: "Running", PrivateIP: "192.0.2.41"}}, nil
			}})
			input := cloudSourceInput()
			input.Provider = provider
			input.Cloud.AccountID = account
			input.Cloud.Regions = []string{region}
			source, e := st.SaveSource("", input, actor(), time.Now())
			require.NoError(t, e)
			public, e := json.Marshal(source)
			require.NoError(t, e)
			assert.NotContains(t, string(public), input.CloudCredential.AccessKeyID)
			assert.NotContains(t, string(public), input.CloudCredential.SecretAccessKey)
			retry, e := st.SaveSource("", input, actor(), time.Now())
			require.NoError(t, e)
			assert.Equal(t, source, retry)
			policy := policyFor(t, st, source, true)
			first := runScan(t, s, source, &policy, "china-source-run-001")
			assert.Equal(t, "completed", first.State)
			assert.Equal(t, 1, first.Imported)
			second := runScan(t, s, source, &policy, "china-source-run-002")
			assert.Zero(t, second.Imported)
			require.Len(t, inventory.List(), 1)
			for _, request := range []string{"china-source-denied-001", "china-source-denied-002", "china-source-denied-003"} {
				denied.Store(true)
				run := runScan(t, s, source, &policy, request)
				assert.Equal(t, "failed", run.State)
				assert.Equal(t, "scan_cloud_permission_denied", run.ErrorCode)
			}
			findings, total, e := st.Findings(source.ID, 0, 100)
			require.NoError(t, e)
			require.Equal(t, 1, total)
			assert.Zero(t, findings[0].ConsecutiveMisses)
			assert.False(t, inventory.List()[0].AccountDisabled)
			reopened, e := Open(st.path, fixtureKey, nil)
			require.NoError(t, e)
			restored, e := reopened.Source(source.ID)
			require.NoError(t, e)
			assert.Equal(t, source, restored)
			private, e := reopened.source(source.ID)
			require.NoError(t, e)
			assert.Equal(t, input.CloudCredential, private.Input.CloudCredential)
			edit := sourceEdit(source)
			edit.Cloud = copyJSON(source.Cloud)
			edit.Cloud.AccountID = "99999999999999999"
			_, e = st.SaveSource(source.ID, edit, actor(), time.Now())
			assert.ErrorIs(t, e, ErrInvalid)
		})
	}
}
