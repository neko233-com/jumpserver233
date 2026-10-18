package api

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/neko233-com/jumpserver233/server/internal/core/monitoralerts"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func monitoringEnv(t *testing.T) *policyTestEnv {
	t.Helper()
	e := securityNotificationEnv(t)
	store, err := coreassets.OpenStore(filepath.Join(t.TempDir(), "assets"), make([]byte, 32))
	require.NoError(t, err)
	e.d.Assets = coreassets.NewService(store, func(context.Context, sshclient.Target, sshclient.Credentials, time.Duration) (sshclient.Metrics, error) {
		return sshclient.Metrics{CPUPercent: 95, MemoryTotalBytes: 1024, MemoryPercent: 40, LatencyMillis: 1}, nil
	})
	e.asset, err = e.d.Assets.Create(coreassets.Input{Name: "Synthetic monitored host", Host: "192.0.2.1", Port: 22, Username: "ops", Password: "synthetic-private-password", HostKeyFingerprint: validTestFingerprint()})
	require.NoError(t, err)
	e.d.MonitorAlerts, err = monitoralerts.Open(filepath.Join(t.TempDir(), "monitor"), make([]byte, 32), nil)
	require.NoError(t, err)
	t.Cleanup(func() { e.d.Notifications.Close(); e.d.MonitorAlerts.Close() })
	e.router = NewRouter("test", e.d)
	return e
}
func monitorInput() monitoralerts.Input {
	return monitoralerts.Input{Name: "Synthetic CPU", Enabled: true, Metric: "cpu_percent", Scope: monitoralerts.Scope{All: true}, Threshold: 90, RecoveryThreshold: 70, ForSamples: 1, RecoverySamples: 1, MaxAgeSeconds: 60}
}
func monitoringFire(t *testing.T, e *policyTestEnv) monitoralerts.Alert {
	t.Helper()
	r := e.send(t, "POST", "/api/v1/monitoring/rules", monitorInput(), e.adminToken, "192.0.2.1:4000")
	require.Equal(t, 201, r.Code, r.Body.String())
	_, err := e.d.Assets.Probe(context.Background(), e.asset.ID)
	require.NoError(t, err)
	require.NoError(t, e.d.MonitorAlerts.Tick())
	p, err := e.d.MonitorAlerts.Alerts(0, 25, "", nil)
	require.NoError(t, err)
	require.Len(t, p.Results, 1)
	return p.Results[0]
}
func TestMonitoringAPIPermissionsCASAndPrivateMetadata(t *testing.T) {
	e := monitoringEnv(t)
	a := monitoringFire(t, e)
	get := func(path, token string) int {
		return e.send(t, "GET", "/api/v1/monitoring/"+path, nil, token, "192.0.2.1:4000").Code
	}
	assert.Equal(t, 403, get("alerts", e.token))
	assert.Equal(t, 403, get("rules", e.token))
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "Monitor viewer", Permissions: []string{"monitoring.view", "notifications.audit"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 404, get("alerts/"+a.ID, e.token))
	// RBAC visibility alone does not confer an asset grant.
	g, err := e.d.Grants.Create(grants.Input{UserID: e.operator.ID, AssetID: e.asset.ID, Account: "ops", Actions: []string{"view"}}, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 200, get("alerts/"+a.ID, e.token))
	detail := e.send(t, "GET", "/api/v1/monitoring/alerts/"+a.ID, nil, e.token, "192.0.2.1:4000")
	assert.Contains(t, detail.Header().Get("Cache-Control"), "no-store")
	assert.NotContains(t, detail.Body.String(), "synthetic-private-password")
	assert.NotContains(t, detail.Body.String(), "192.0.2.1")
	assert.Equal(t, 403, e.send(t, "POST", "/api/v1/monitoring/alerts/"+a.ID+"/acknowledge", map[string]any{"revision": a.Revision}, e.token, "192.0.2.1:4000").Code)
	role, err = e.d.RBAC.SaveRole(role.ID, rbac.RoleInput{Name: role.Name, Revision: role.Revision, Permissions: []string{"monitoring.view", "monitoring.ack"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	out := e.send(t, "POST", "/api/v1/monitoring/alerts/"+a.ID+"/acknowledge", map[string]any{"revision": a.Revision, "comment": "Synthetic investigation"}, e.token, "192.0.2.1:4000")
	require.Equal(t, 200, out.Code, out.Body.String())
	assert.Equal(t, 409, e.send(t, "POST", "/api/v1/monitoring/alerts/"+a.ID+"/acknowledge", map[string]any{"revision": a.Revision}, e.token, "192.0.2.1:4000").Code)
	require.NoError(t, e.d.Grants.Delete(g.ID))
	assert.Equal(t, 404, get("alerts/"+a.ID, e.token))
	r := e.send(t, "GET", "/api/v1/monitoring/alerts", nil, e.token, "192.0.2.1:4000")
	var page monitoralerts.Page[monitoralerts.Alert]
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &page))
	assert.Zero(t, page.Total)
	for _, p := range []string{"alerts?limit=201", "alerts?offset=-1", "alerts?state=unknown", "audit?limit=0"} {
		assert.Equal(t, 400, get(p, e.adminToken))
	}
}
func TestMonitoringNotificationsRecheckAcknowledgementMuteAndOwnerAuthority(t *testing.T) {
	e := monitoringEnv(t)
	a := monitoringFire(t, e)
	e.d.Notifications.Tick()
	inbox := func() string {
		return e.send(t, "GET", "/api/v1/notifications/inbox?limit=100", nil, e.adminToken, "192.0.2.1:4000").Body.String()
	}
	assert.Contains(t, inbox(), a.ID)
	assert.True(t, monitorNotificationAllowed(context.Background(), e.d, e.admin.ID, a, "monitoring_firing"))
	rule, ok := e.d.MonitorAlerts.Rule(a.RuleID)
	require.True(t, ok)
	rule, err := e.d.MonitorAlerts.MuteRule(rule.ID, rule.Revision, time.Now().Add(time.Minute), "Synthetic maintenance", monitoralerts.Actor{ID: e.admin.ID, Name: e.admin.Username})
	require.NoError(t, err)
	assert.NotContains(t, inbox(), a.ID)
	assert.False(t, monitorNotificationAllowed(context.Background(), e.d, e.admin.ID, a, "monitoring_firing"))
	_, err = e.d.MonitorAlerts.MuteRule(rule.ID, rule.Revision, time.Time{}, "", monitoralerts.Actor{ID: e.admin.ID, Name: e.admin.Username})
	require.NoError(t, err)
	ack, err := e.d.MonitorAlerts.Acknowledge(a.ID, a.Revision, "Private synthetic investigation", monitoralerts.Actor{ID: e.admin.ID, Name: e.admin.Username})
	require.NoError(t, err)
	assert.False(t, monitorNotificationAllowed(context.Background(), e.d, e.admin.ID, ack, "monitoring_firing"))
	assert.NotContains(t, inbox(), a.ID)
}
