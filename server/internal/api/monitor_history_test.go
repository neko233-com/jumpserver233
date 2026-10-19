package api

import (
	"context"
	"encoding/json"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/neko233-com/jumpserver233/server/internal/core/monitorhistory"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMonitoringHistoryRequiresCurrentAssetViewAndNeverReturnsSecrets(t *testing.T) {
	e := monitoringEnv(t)
	h, err := monitorhistory.Open(filepath.Join(t.TempDir(), "history"), make([]byte, 32), nil)
	require.NoError(t, err)
	t.Cleanup(h.Close)
	e.d.Assets.SetMonitorHistory(h)
	_, err = e.d.Assets.Probe(context.Background(), e.asset.ID)
	require.NoError(t, err)
	now := time.Now().UTC()
	q := url.Values{"from": {now.Add(-5 * time.Minute).Format(time.RFC3339Nano)}, "to": {now.Format(time.RFC3339Nano)}, "step": {"60"}}
	path := "/api/v1/assets/" + e.asset.ID + "/monitor-history?" + q.Encode()
	assert.Equal(t, 404, e.send(t, "GET", path, nil, e.token, "192.0.2.1:4000").Code)
	g, err := e.d.Grants.Create(grants.Input{UserID: e.operator.ID, AssetID: e.asset.ID, Account: "ops", Actions: []string{"view"}}, e.admin.Username)
	require.NoError(t, err)
	r := e.send(t, "GET", path, nil, e.token, "192.0.2.1:4000")
	require.Equal(t, 200, r.Code, r.Body.String())
	assert.Contains(t, r.Header().Get("Cache-Control"), "no-store")
	for _, private := range []string{"synthetic-private-password", "192.0.2.1", "SHA256", "binding", "credential"} {
		assert.NotContains(t, r.Body.String(), private)
	}
	var page monitorhistory.Page
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &page))
	total := 0
	for _, p := range page.Results {
		total += p.Samples
	}
	assert.Equal(t, 1, total)
	assert.Equal(t, 400, e.send(t, "GET", path+"&step=1", nil, e.adminToken, "192.0.2.1:4000").Code)
	assert.Equal(t, 400, e.send(t, "GET", "/api/v1/assets/"+e.asset.ID+"/monitor-history?from=bad", nil, e.adminToken, "192.0.2.1:4000").Code)
	require.NoError(t, e.d.Grants.Delete(g.ID))
	assert.Equal(t, 404, e.send(t, "GET", path, nil, e.token, "192.0.2.1:4000").Code)
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "Global connector", Permissions: []string{"assets.connect_all"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 200, e.send(t, "GET", path, nil, e.token, "192.0.2.1:4000").Code)
	require.NoError(t, e.d.Assets.Delete(e.asset.ID))
	assert.Equal(t, 404, e.send(t, "GET", path, nil, e.adminToken, "192.0.2.1:4000").Code)
}

func TestMonitoringHistoryFollowsCurrentBindingAndWriteFailuresAreVisible(t *testing.T) {
	e := monitoringEnv(t)
	dir := filepath.Join(t.TempDir(), "history")
	h, err := monitorhistory.Open(dir, make([]byte, 32), nil)
	require.NoError(t, err)
	t.Cleanup(h.Close)
	e.d.Assets.SetMonitorHistory(h)
	_, err = e.d.Assets.Probe(context.Background(), e.asset.ID)
	require.NoError(t, err)
	from, to := time.Now().Add(-5*time.Minute), time.Now().Add(time.Second)
	p, err := e.d.Assets.MonitorHistory(e.asset.ID, from, to, 60)
	require.NoError(t, err)
	count := func(p monitorhistory.Page) int {
		n := 0
		for _, v := range p.Results {
			n += v.Samples
		}
		return n
	}
	assert.Equal(t, 1, count(p))
	_, err = e.d.Assets.Update(e.asset.ID, coreassets.Input{Name: e.asset.Name, Host: "192.0.2.2", Port: 22, Username: "ops", Password: "synthetic-private-password", HostKeyFingerprint: validTestFingerprint()})
	require.NoError(t, err)
	p, err = e.d.Assets.MonitorHistory(e.asset.ID, from, to, 60)
	require.NoError(t, err)
	assert.Zero(t, count(p))
	_, err = e.d.Assets.Probe(context.Background(), e.asset.ID)
	require.NoError(t, err)
	p, err = e.d.Assets.MonitorHistory(e.asset.ID, from, to, 60)
	require.NoError(t, err)
	assert.Equal(t, 1, count(p))
	// Closing history must not turn a successful SSH probe into fake downtime.
	h.Close()
	item, err := e.d.Assets.Probe(context.Background(), e.asset.ID)
	require.NoError(t, err)
	assert.Equal(t, "online", item.Monitor.State)
	q := url.Values{"from": {from.UTC().Format(time.RFC3339Nano)}, "to": {to.UTC().Format(time.RFC3339Nano)}}
	r := e.send(t, "GET", "/api/v1/assets/"+e.asset.ID+"/monitor-history?"+q.Encode(), nil, e.adminToken, "192.0.2.1:4000")
	assert.Equal(t, 503, r.Code)
	assert.Contains(t, r.Body.String(), "history_unavailable")
}
