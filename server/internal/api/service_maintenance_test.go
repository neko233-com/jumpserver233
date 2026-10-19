package api

import (
	"context"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/core/servicemaintenance"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMaintenanceSystemPermissionsReplayAndGlobalRouting(t *testing.T) {
	e := monitoringEnv(t)
	g := workgate.New()
	var err error
	e.d.Maintenance, err = servicemaintenance.New(g, true, func(servicemaintenance.Event) error { return nil })
	require.NoError(t, err)
	e.router = NewOrganizationRouter("test", e.d, func(string) (http.Handler, error) { t.Fatal("maintenance selected an organization"); return nil, nil })
	for _, token := range []string{"", e.token} {
		status := 401
		if token != "" {
			status = 403
		}
		assert.Equal(t, status, e.send(t, "GET", maintenancePath, nil, token, "192.0.2.1:1234").Code)
		assert.Equal(t, status, e.send(t, "PUT", maintenancePath, map[string]any{}, token, "192.0.2.1:1234").Code)
	}
	release, err := g.Acquire("existing")
	require.NoError(t, err)
	in := servicemaintenance.Input{Instance: e.d.Maintenance.Snapshot().Instance, Revision: 1, RequestID: "api-drain-request", Draining: true}
	r := e.send(t, "PUT", maintenancePath, in, e.adminToken, "192.0.2.1:1234")
	require.Equal(t, 200, r.Code)
	assert.Contains(t, r.Header().Get("Cache-Control"), "no-store")
	var out servicemaintenance.Status
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &out))
	assert.False(t, out.Ready)
	release()
	assert.True(t, e.d.Maintenance.Snapshot().Ready)
	r = e.send(t, "PUT", maintenancePath, in, e.adminToken, "192.0.2.1:1234")
	require.Equal(t, 200, r.Code)
	assert.Contains(t, r.Body.String(), `"replayed":true`)
	in.RequestID = "api-drain-other"
	assert.Equal(t, 409, e.send(t, "PUT", maintenancePath, in, e.adminToken, "192.0.2.1:1234").Code)
	in.Revision = 2
	in.Draining = false
	assert.Equal(t, 200, e.send(t, "PUT", maintenancePath, in, e.adminToken, "192.0.2.1:1234").Code)
}
func TestMaintenanceMiddlewareBlocksNewWorkCountsOnceAndAllowsCancellation(t *testing.T) {
	g := workgate.New()
	c, e := servicemaintenance.New(g, true, func(servicemaintenance.Event) error { return nil })
	require.NoError(t, e)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/work" {
			assert.Equal(t, 1, g.Snapshot()["http_requests"])
		}
		w.WriteHeader(204)
	})
	h := withMaintenance(withMaintenance(inner, c), c)
	call := func(method, path string) int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		return w.Code
	}
	assert.Equal(t, 204, call("POST", "/api/work"))
	assert.Empty(t, g.Snapshot())
	g.SetClosed(true)
	for _, route := range [][2]string{{"POST", "/api/v1/sessions"}, {"PUT", "/api/v1/assets/a"}, {"PUT", "/api/v1/assets/cancel"}, {"GET", "/ws/terminal"}} {
		assert.Equal(t, 503, call(route[0], route[1]))
	}
	for _, route := range [][2]string{{"GET", maintenancePath}, {"PUT", maintenancePath}, {"GET", "/api/health"}, {"DELETE", "/api/v1/sessions/a"}, {"POST", "/api/v1/ops/runs/a/cancel"}, {"DELETE", "/api/v1/database-sessions"}, {"POST", "/api/v1/authentication/auth/"}} {
		assert.Equal(t, 204, call(route[0], route[1]))
	}
	_, _, e = g.Enter(context.Background(), "replay")
	assert.ErrorIs(t, e, workgate.ErrDraining)
}
