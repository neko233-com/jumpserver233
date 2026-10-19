package api

import (
	"net/http"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/core/servicemaintenance"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
	"github.com/stretchr/testify/require"
)

func TestInstallationScheduleGlobalPermissionsAndUnconfiguredState(t *testing.T) {
	e := monitoringEnv(t)
	e.router = NewOrganizationRouter("test", e.d, func(string) (http.Handler, error) { t.Fatal("installation selected tenant runtime"); return nil, nil })
	for _, path := range []string{installationSchedulePath, installationSchedulePath + "/candidates", installationSchedulePath + "/automatic"} {
		require.Equal(t, 401, e.send(t, "GET", path, nil, "", "192.0.2.1:12").Code)
		require.Equal(t, 403, e.send(t, "GET", path, nil, e.token, "192.0.2.1:12").Code)
	}
	require.Equal(t, 403, e.send(t, "PUT", installationSchedulePath+"/automatic", map[string]any{}, e.token, "192.0.2.1:12").Code)
	require.Equal(t, 409, e.send(t, "PUT", installationSchedulePath+"/automatic", map[string]any{}, e.adminToken, "192.0.2.1:12").Code)
	r := e.send(t, "GET", installationSchedulePath, nil, e.adminToken, "192.0.2.1:12")
	require.Equal(t, 200, r.Code)
	require.Contains(t, r.Body.String(), `"configured":false`)
	require.Contains(t, r.Header().Get("Cache-Control"), "no-store")
	for _, path := range []string{installationSchedulePath, installationSchedulePath + "/cancel"} {
		require.Equal(t, 403, e.send(t, "POST", path, map[string]any{}, e.token, "192.0.2.1:12").Code)
		require.Equal(t, 409, e.send(t, "POST", path, map[string]any{}, e.adminToken, "192.0.2.1:12").Code)
	}
}
func TestDrainStopEndpointAuthorizesReadyAndExactInstance(t *testing.T) {
	e := monitoringEnv(t)
	var err error
	e.d.Maintenance, err = servicemaintenance.New(workgate.New(), true, func(servicemaintenance.Event) error { return nil })
	require.NoError(t, err)
	stops := 0
	e.d.Maintenance.SetStop(func() { stops++ })
	e.router = NewRouter("test", e.d)
	s := e.d.Maintenance.Snapshot()
	in := servicemaintenance.Input{Instance: s.Instance, Revision: 1, RequestID: "api-stop-request", Draining: true}
	require.Equal(t, 403, e.send(t, "POST", maintenancePath+"/stop", in, e.token, "192.0.2.1:12").Code)
	require.Equal(t, 409, e.send(t, "POST", maintenancePath+"/stop", in, e.adminToken, "192.0.2.1:12").Code)
	start := in
	start.RequestID = "api-start-request"
	require.Equal(t, 200, e.send(t, "PUT", maintenancePath, start, e.adminToken, "192.0.2.1:12").Code)
	in.Revision = 2
	r := e.send(t, "POST", maintenancePath+"/stop", in, e.adminToken, "192.0.2.1:12")
	require.Equal(t, 200, r.Code)
	require.Contains(t, r.Body.String(), `"stopping":true`)
	require.Equal(t, 1, stops)
	require.Equal(t, 200, e.send(t, "POST", maintenancePath+"/stop", in, e.adminToken, "192.0.2.1:12").Code)
	require.Equal(t, 1, stops)
}
