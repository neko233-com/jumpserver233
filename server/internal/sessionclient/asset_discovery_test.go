package sessionclient

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/core/assetdiscovery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoveryClientTypedPrivateResponsesAsync202AndOrganization(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "Bearer fixture-token", r.Header.Get("Authorization"))
		assert.Equal(t, "00000000-0000-0000-0000-000000000002", r.Header.Get("X-JMS-ORG"))
		if r.URL.Path == "/api/v1/asset-discovery/findings.csv" {
			w.Header().Set("Content-Type", "text/csv")
			_, _ = w.Write([]byte("host,port\n192.0.2.1,22\n"))
			return
		}
		if r.Method == "DELETE" {
			w.WriteHeader(204)
			return
		}
		if r.URL.Path == "/api/v1/asset-discovery/runs" && r.Method == "POST" {
			w.WriteHeader(202)
			_, _ = w.Write([]byte(`{"id":"run-fixture","state":"scanning","password":"should-be-discarded"}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"public-resource","revision":1,"results":[],"total":0,"password":"should-be-discarded"}`))
	}))
	defer srv.Close()
	c, e := New(srv.URL, "fixture-token")
	require.NoError(t, e)
	c, e = c.WithOrganization("00000000-0000-0000-0000-000000000002")
	require.NoError(t, e)
	ctx := context.Background()
	run, e := c.StartDiscoveryRun(ctx, assetdiscovery.RunInput{})
	require.NoError(t, e)
	assert.Equal(t, "run-fixture", run.ID)
	raw, _ := json.Marshal(run)
	assert.NotContains(t, string(raw), "should-be-discarded")
	source, e := c.SaveDiscoverySource(ctx, "", assetdiscovery.SourceInput{})
	require.NoError(t, e)
	assert.Equal(t, 1, source.Revision)
	raw, _ = json.Marshal(source)
	assert.NotContains(t, string(raw), "password")
	_, e = c.DiscoverySources(ctx)
	require.NoError(t, e)
	_, e = c.DiscoveryPolicies(ctx)
	require.NoError(t, e)
	_, e = c.DiscoveryRuns(ctx, "source-1", 0, 100)
	require.NoError(t, e)
	_, e = c.DiscoveryFindings(ctx, "source-1", 0, 100)
	require.NoError(t, e)
	_, e = c.DiscoveryAudit(ctx, 0, 100)
	require.NoError(t, e)
	_, e = c.PreviewDiscoveryImport(ctx, assetdiscovery.PreviewInput{})
	require.NoError(t, e)
	_, e = c.ImportDiscoveryAssets(ctx, assetdiscovery.ImportInput{})
	require.NoError(t, e)
	require.NoError(t, c.DeleteDiscoverySource(ctx, "source-1", 1))
	require.NoError(t, c.DeleteDiscoveryPolicy(ctx, "policy-1", 1))
	var out bytes.Buffer
	require.NoError(t, c.ExportDiscoveryFindings(ctx, "source-1", &out))
	assert.Contains(t, out.String(), "192.0.2.1")
	before := calls
	_, e = c.DiscoveryFindings(ctx, "source-1", -1, 100)
	require.Error(t, e)
	assert.Equal(t, before, calls)
}
