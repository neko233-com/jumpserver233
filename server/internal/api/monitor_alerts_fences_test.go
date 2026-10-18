package api

import (
	"context"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestMonitoringOrganizationWithdrawalRetiresAndPrunedFeedAdvances(t *testing.T) {
	e := monitoringEnv(t)
	a := monitoringFire(t, e)
	found := false
	for _, f := range securityNotificationFeeds(e.d) {
		if f.Name == "monitor-alerts" {
			found = true
			recipients, err := f.Recipients(context.Background(), eventfeed.Event{ResourceID: "removed-history"})
			require.NoError(t, err)
			assert.Empty(t, recipients)
		}
	}
	require.True(t, found)
	e.d.OrganizationAllowed = func(coreauth.User) bool { return false }
	e.router = NewRouter("test", e.d)
	require.NoError(t, e.d.MonitorAlerts.Tick())
	retired, err := e.d.MonitorAlerts.Alert(a.ID)
	require.NoError(t, err)
	assert.Equal(t, "retired", retired.State)
	assert.Equal(t, "authority_revoked", retired.Reason)
	assert.False(t, monitorNotificationAllowed(context.Background(), e.d, e.admin.ID, retired, "monitoring_firing"))
	assert.Equal(t, 403, e.send(t, "GET", "/api/v1/monitoring/alerts", nil, e.adminToken, "192.0.2.1:4000").Code)
}
