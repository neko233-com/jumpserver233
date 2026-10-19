package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/core/assetdiscovery"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshgateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestAssetDiscoveryPersistsReceiptsAndInventoryAcrossPostgresTakeover(t *testing.T) {
	dbURL := os.Getenv("JMS_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for real discovery leader takeover")
	}
	namespace := fmt.Sprintf("discovery-ha-%d", time.Now().UnixNano())
	dir := t.TempDir()
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	first := integrationNodeConfig(t, namespace, dir, key, freeAddress(t), freeAddress(t))
	second := integrationNodeConfig(t, namespace, dir, key, freeAddress(t), freeAddress(t))
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	done1, done2 := make(chan error, 1), make(chan error, 1)
	started2, finished1 := false, false
	t.Cleanup(func() {
		cancel1()
		cancel2()
		if !finished1 {
			select {
			case e := <-done1:
				assert.NoError(t, e)
			case <-time.After(15 * time.Second):
				t.Error("first discovery node did not stop")
			}
		}
		if started2 {
			select {
			case e := <-done2:
				assert.NoError(t, e)
			case <-time.After(15 * time.Second):
				t.Error("second discovery node did not stop")
			}
		}
		pool, e := sql.Open("pgx", dbURL)
		if !assert.NoError(t, e) {
			return
		}
		defer pool.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, e = pool.ExecContext(ctx, `DELETE FROM jms233_state_documents WHERE namespace=$1`, namespace)
		assert.NoError(t, e)
	})
	fixture, e := sshgateway.Start("127.0.0.1:0", nil)
	require.NoError(t, e)
	defer fixture.Close()
	host, port, _ := net.SplitHostPort(fixture.Address())
	p, _ := strconv.Atoi(port)
	go func() { done1 <- runActiveStandby(ctx1, first) }()
	waitForHTTPStatus(t, "http://"+first.ClusterHealthAddr+"/readyz", 200, 20*time.Second)
	input := assetdiscovery.SourceInput{RequestID: "ha-source-create", Name: "HA LAN", Enabled: true, Targets: []string{host}, Ports: []int{p}, Template: assets.Input{Protocol: "ssh", Username: sshgateway.Username}, Credential: &assetdiscovery.Credential{Password: sshgateway.Password}}
	var source assetdiscovery.Source
	require.NoError(t, json.Unmarshal(orgHTTP(t, first.Addr, "POST", "/api/v1/asset-discovery/sources", first.AdminToken, "", input, 201), &source))
	var policy assetdiscovery.Policy
	require.NoError(t, json.Unmarshal(orgHTTP(t, first.Addr, "POST", "/api/v1/asset-discovery/policies", first.AdminToken, "", assetdiscovery.PolicyInput{RequestID: "ha-policy-create", SourceID: source.ID, SourceRevision: 1, Name: "HA policy", Enabled: true}, 201), &policy))
	var run assetdiscovery.Run
	require.NoError(t, json.Unmarshal(orgHTTP(t, first.Addr, "POST", "/api/v1/asset-discovery/runs", first.AdminToken, "", assetdiscovery.RunInput{SourceID: source.ID, SourceRevision: 1, RequestID: "ha-scan-create"}, 202), &run))
	require.Eventually(t, func() bool {
		var r assetdiscovery.Run
		_ = json.Unmarshal(orgHTTP(t, first.Addr, "GET", "/api/v1/asset-discovery/runs/"+run.ID, first.AdminToken, "", nil, 200), &r)
		return r.State == "completed"
	}, 5*time.Second, 20*time.Millisecond)
	var findings struct {
		Results []assetdiscovery.Finding `json:"results"`
	}
	require.NoError(t, json.Unmarshal(orgHTTP(t, first.Addr, "GET", "/api/v1/asset-discovery/findings?source_id="+source.ID, first.AdminToken, "", nil, 200), &findings))
	require.Len(t, findings.Results, 1)
	f := findings.Results[0]
	assert.Equal(t, fixture.Fingerprint, f.HostKeyFingerprint)
	var preview assetdiscovery.Preview
	require.NoError(t, json.Unmarshal(orgHTTP(t, first.Addr, "POST", "/api/v1/asset-discovery/import-preview", first.AdminToken, "", assetdiscovery.PreviewInput{SourceID: source.ID, SourceRevision: 1, PolicyID: policy.ID, PolicyRevision: 1, Findings: []assetdiscovery.Selection{{ID: f.ID, Revision: f.Revision, HostKeyFingerprint: f.HostKeyFingerprint}}}, 200), &preview))
	commit := assetdiscovery.ImportInput{Token: preview.Token, RequestID: "ha-import-create"}
	var receipt assetdiscovery.ImportResult
	require.NoError(t, json.Unmarshal(orgHTTP(t, first.Addr, "POST", "/api/v1/asset-discovery/import", first.AdminToken, "", commit, 200), &receipt))
	assert.Equal(t, 1, receipt.Imported)
	started2 = true
	go func() { done2 <- runActiveStandby(ctx2, second) }()
	waitForHTTPStatus(t, "http://"+second.ClusterHealthAddr+"/readyz", 503, 20*time.Second)
	cancel1()
	select {
	case e = <-done1:
		finished1 = true
		require.NoError(t, e)
	case <-time.After(15 * time.Second):
		t.Fatal("discovery leader did not stop")
	}
	waitForHTTPStatus(t, "http://"+second.ClusterHealthAddr+"/readyz", 200, 20*time.Second)
	var recovered assetdiscovery.Source
	require.NoError(t, json.Unmarshal(orgHTTP(t, second.Addr, "GET", "/api/v1/asset-discovery/sources/"+source.ID, second.AdminToken, "", nil, 200), &recovered))
	assert.Equal(t, source, recovered)
	var retry assetdiscovery.ImportResult
	require.NoError(t, json.Unmarshal(orgHTTP(t, second.Addr, "POST", "/api/v1/asset-discovery/import", second.AdminToken, "", commit, 200), &retry))
	assert.Equal(t, receipt, retry)
	var inventory []assets.ListItem
	require.NoError(t, json.Unmarshal(orgHTTP(t, second.Addr, "GET", "/api/v1/assets", second.AdminToken, "", nil, 200), &inventory))
	count := 0
	for _, a := range inventory {
		if a.Discovery != nil && a.Discovery.SourceID == source.ID {
			count++
			assert.Equal(t, receipt.Results[0].AssetID, a.ID)
		}
	}
	assert.Equal(t, 1, count)
	_, e = os.Stat(filepath.Join(dir, "asset-discovery.json"))
	assert.True(t, os.IsNotExist(e), "HA discovery state must use shared storage")
}
