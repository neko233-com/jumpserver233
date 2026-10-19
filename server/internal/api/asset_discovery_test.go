package api

import (
	"context"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/connector/cloudinventory"
	"github.com/neko233-com/jumpserver233/server/internal/connector/inventoryprobe"
	"github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	"github.com/neko233-com/jumpserver233/server/internal/core/assetdiscovery"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func discoveryEnv(t *testing.T, cloud ...func(context.Context, string, cloudinventory.Config, cloudinventory.Credential) ([]cloudinventory.Instance, error)) *policyTestEnv {
	t.Helper()
	e := newPolicyEnv(t)
	e.d.AccessMu = &sync.RWMutex{}
	st, err := assetdiscovery.Open(filepath.Join(t.TempDir(), "discovery.json"), make([]byte, 32), nil)
	require.NoError(t, err)
	hooks := assetdiscovery.Hooks{Probe: func(context.Context, string, int, string, time.Duration, inventoryprobe.DialFunc) inventoryprobe.Result {
		return inventoryprobe.Result{Open: true, SSHVerified: true, HostKeyFingerprint: validTestFingerprint()}
	}}
	if len(cloud) > 0 {
		hooks.CloudList = cloud[0]
	}
	e.d.AssetDiscovery = assetdiscovery.NewService(st, hooks)
	e.router = NewRouter("test", e.d)
	require.NoError(t, e.d.AssetDiscovery.Start(context.Background()))
	t.Cleanup(e.d.AssetDiscovery.Close)
	return e
}
func discoverySourceInput() assetdiscovery.SourceInput {
	return assetdiscovery.SourceInput{RequestID: "api-source-create", Name: "API LAN", Enabled: true, Targets: []string{"192.0.2.88"}, Ports: []int{22}, Template: assets.Input{Protocol: "ssh", Username: "discovery"}, Credential: &assetdiscovery.Credential{Password: "synthetic-discovery-api-password"}}
}
func TestAssetDiscoveryAPICompleteImportRetryExportAndCurrentPermission(t *testing.T) {
	e := discoveryEnv(t)
	for _, token := range []string{"", e.token} {
		for _, path := range []string{"sources", "policies", "runs", "audit"} {
			assert.Contains(t, []int{401, 403}, e.send(t, "GET", "/api/v1/asset-discovery/"+path, nil, token, "192.0.2.1:1").Code)
		}
	}
	response := e.send(t, "POST", "/api/v1/asset-discovery/sources", discoverySourceInput(), e.adminToken, "192.0.2.1:1")
	require.Equal(t, 201, response.Code, response.Body.String())
	assert.Contains(t, response.Header().Get("Cache-Control"), "no-store")
	assert.NotContains(t, response.Body.String(), "synthetic-discovery-api-password")
	var source assetdiscovery.Source
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &source))
	pinput := assetdiscovery.PolicyInput{RequestID: "api-policy-create", SourceID: source.ID, SourceRevision: source.Revision, Name: "API policy", Enabled: true, UpdateExisting: true}
	response = e.send(t, "POST", "/api/v1/asset-discovery/policies", pinput, e.adminToken, "192.0.2.1:1")
	require.Equal(t, 201, response.Code, response.Body.String())
	var policy assetdiscovery.Policy
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &policy))
	runInput := assetdiscovery.RunInput{RequestID: "api-scan-create", SourceID: source.ID, SourceRevision: source.Revision}
	response = e.send(t, "POST", "/api/v1/asset-discovery/runs", runInput, e.adminToken, "192.0.2.1:1")
	require.Equal(t, 202, response.Code, response.Body.String())
	var run assetdiscovery.Run
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &run))
	require.Eventually(t, func() bool { r, _ := e.d.AssetDiscovery.Run(run.ID); return r.State == "completed" }, 3*time.Second, 5*time.Millisecond)
	rows, _, err := e.d.AssetDiscovery.Store().Findings(source.ID, 0, 100)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	previewInput := assetdiscovery.PreviewInput{SourceID: source.ID, SourceRevision: source.Revision, PolicyID: policy.ID, PolicyRevision: policy.Revision, Findings: []assetdiscovery.Selection{{ID: rows[0].ID, Revision: rows[0].Revision, HostKeyFingerprint: rows[0].HostKeyFingerprint}}}
	response = e.send(t, "POST", "/api/v1/asset-discovery/import-preview", previewInput, e.adminToken, "192.0.2.1:1")
	require.Equal(t, 200, response.Code, response.Body.String())
	var preview assetdiscovery.Preview
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &preview))
	input := assetdiscovery.ImportInput{Token: preview.Token, RequestID: "api-import-create"}
	first := e.send(t, "POST", "/api/v1/asset-discovery/import", input, e.adminToken, "192.0.2.1:1")
	require.Equal(t, 200, first.Code, first.Body.String())
	second := e.send(t, "POST", "/api/v1/asset-discovery/import", input, e.adminToken, "192.0.2.1:1")
	require.Equal(t, 200, second.Code, second.Body.String())
	assert.JSONEq(t, first.Body.String(), second.Body.String())
	assert.NotContains(t, first.Body.String(), "synthetic-discovery-api-password")
	input.RequestID = "api-import-replayed"
	response = e.send(t, "POST", "/api/v1/asset-discovery/import", input, e.adminToken, "192.0.2.1:1")
	assert.Equal(t, 409, response.Code)
	response = e.send(t, "GET", "/api/v1/asset-discovery/findings.csv?source_id="+source.ID, nil, e.adminToken, "192.0.2.1:1")
	assert.Equal(t, 200, response.Code)
	assert.Contains(t, response.Body.String(), "192.0.2.88")
	assert.NotContains(t, response.Body.String(), "discovery-api-password")
	assert.Contains(t, response.Header().Get("Content-Type"), "text/csv")
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "Discovery reader", Permissions: []string{"assets.view_all", "assets.discovery.view"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	binding, err := e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	response = e.send(t, "GET", "/api/v1/asset-discovery/sources", nil, e.token, "192.0.2.1:1")
	assert.Equal(t, 200, response.Code)
	assert.NotContains(t, response.Body.String(), "synthetic-discovery-api-password")
	assert.Equal(t, 403, e.send(t, "POST", "/api/v1/asset-discovery/runs", runInput, e.token, "192.0.2.1:1").Code)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, Revision: binding.Revision, RoleIDs: []string{}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 403, e.send(t, "GET", "/api/v1/asset-discovery/sources", nil, e.token, "192.0.2.1:1").Code)
}
func TestDiscoveryGatewayRequestsDedicatedReviewBeforeNetwork(t *testing.T) {
	e := discoveryEnv(t)
	var err error
	e.d.AccessReviews, err = accessreviews.OpenStore(filepath.Join(t.TempDir(), "reviews.json"))
	require.NoError(t, err)
	// Configure the runtime before it starts; the first fixture is closed and
	// replaced with the same durable store, without any in-flight workers.
	e.d.AssetDiscovery.Close()
	e.d.AssetDiscovery = assetdiscovery.NewService(e.d.AssetDiscovery.Store(), assetdiscovery.Hooks{})
	e.router = NewRouter("test", e.d)
	require.NoError(t, e.d.AssetDiscovery.Start(context.Background()))
	t.Cleanup(e.d.AssetDiscovery.Close)
	yes := true
	_, err = e.d.Assets.Update(e.asset.ID, assets.Input{Name: e.asset.Name, Host: e.asset.Host, Port: e.asset.Port, Username: e.asset.Username, HostKeyFingerprint: e.asset.HostKeyFingerprint, LoginReviewRequired: &yes})
	require.NoError(t, err)
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "Discovery executor", Permissions: []string{"assets.view_all", "assets.discovery.view", "assets.discovery.execute"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	in := discoverySourceInput()
	in.GatewayID = e.asset.ID
	response := e.send(t, "POST", "/api/v1/asset-discovery/sources", in, e.adminToken, "192.0.2.1:1")
	require.Equal(t, 201, response.Code, response.Body.String())
	var source assetdiscovery.Source
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &source))
	response = e.send(t, "POST", "/api/v1/asset-discovery/runs", assetdiscovery.RunInput{RequestID: "review-required-scan", SourceID: source.ID, SourceRevision: 1}, e.token, "192.0.2.1:1")
	require.Equal(t, 202, response.Code, response.Body.String())
	var run assetdiscovery.Run
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &run))
	require.Eventually(t, func() bool { r, _ := e.d.AssetDiscovery.Run(run.ID); return r.State == "waiting_review" }, 3*time.Second, 5*time.Millisecond)
	reviews, err := e.d.AccessReviews.ListPending()
	require.NoError(t, err)
	require.Len(t, reviews, 1)
	assert.Equal(t, accessreviews.ActionAssetDiscovery, reviews[0].Action)
	_, err = e.d.AssetDiscovery.Cancel(context.Background(), run.ID, assetdiscovery.Actor{ID: e.operator.ID, Name: e.operator.Username})
	require.NoError(t, err)
	require.Eventually(t, func() bool { r, _ := e.d.AssetDiscovery.Run(run.ID); return r.State == "cancelled" }, 3*time.Second, 5*time.Millisecond)
}
func TestDiscoveryRuntimeLockAcquisitionCancelsDuringTenantShutdown(t *testing.T) {
	e := discoveryEnv(t)
	e.d.AccessMu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := lockDiscoveryRuntime(ctx, e.d, true)
	e.d.AccessMu.Unlock()
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	for _, path := range []string{"audit?limit=0", "runs?offset=-1"} {
		response := e.send(t, "GET", "/api/v1/asset-discovery/"+path, nil, e.adminToken, "192.0.2.1:1")
		assert.Equal(t, 400, response.Code)
	}
	assert.Equal(t, 400, e.send(t, "POST", "/api/v1/asset-discovery/sources", map[string]any{"unknown": true}, e.adminToken, "192.0.2.1:1").Code)
}
