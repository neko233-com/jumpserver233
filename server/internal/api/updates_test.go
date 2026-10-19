package api

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/core/updates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type updateTransport func(*http.Request) (*http.Response, error)

func (t updateTransport) Do(r *http.Request) (*http.Response, error) { return t(r) }
func TestUpdateAPIUsesSystemPermissionsGlobalRoutingRevisionsAndReplayReceipts(t *testing.T) {
	e := monitoringEnv(t)
	var calls atomic.Int32
	feed := updates.NewFeed("v1.0.0", "linux", "amd64", updateTransport(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		assert.Equal(t, "api.github.com", r.URL.Host)
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader(""))}, nil
	}))
	var err error
	e.d.Updates, err = updates.Open(filepath.Join(t.TempDir(), "updates.json"), nil, feed)
	require.NoError(t, err)
	e.router = NewOrganizationRouter("v1.0.0", e.d, func(string) (http.Handler, error) {
		t.Fatal("system updates must not select an organization runtime")
		return nil, nil
	})
	const path = "/api/v1/settings/security/updates"
	for _, route := range []struct{ method, path string }{{"GET", path}, {"GET", path + "/audit"}, {"PUT", path}, {"POST", path + "/check"}} {
		r := e.send(t, route.method, route.path, map[string]any{}, e.token, "192.0.2.1:4000")
		assert.Equal(t, 403, r.Code)
		r = e.send(t, route.method, route.path, map[string]any{}, "", "192.0.2.1:4000")
		assert.Equal(t, 401, r.Code)
	}
	get := e.send(t, "GET", path, nil, e.adminToken, "192.0.2.1:4000")
	require.Equal(t, 200, get.Code)
	assert.Contains(t, get.Header().Get("Cache-Control"), "no-store")
	assert.Zero(t, calls.Load())
	settings := updates.Settings{Automatic: false, IntervalHours: 48, Revision: 1}
	saved := e.send(t, "PUT", path, settings, e.adminToken, "192.0.2.1:4000")
	require.Equal(t, 200, saved.Code)
	assert.Equal(t, 409, e.send(t, "PUT", path, settings, e.adminToken, "192.0.2.1:4000").Code)
	in := map[string]any{"revision": 2, "request_id": "request-update-0001"}
	for i := 0; i < 2; i++ {
		r := e.send(t, "POST", path+"/check", in, e.adminToken, "192.0.2.1:4000")
		require.Equal(t, 200, r.Code)
		var out updates.Status
		require.NoError(t, json.Unmarshal(r.Body.Bytes(), &out))
		assert.Equal(t, "no_release", out.Result.Status)
	}
	assert.EqualValues(t, 1, calls.Load())
	in["request_id"] = "request-update-0002"
	assert.Equal(t, 429, e.send(t, "POST", path+"/check", in, e.adminToken, "192.0.2.1:4000").Code)
	history := e.send(t, "GET", path+"/audit", nil, e.adminToken, "192.0.2.1:4000")
	require.Equal(t, 200, history.Code)
	assert.Contains(t, history.Body.String(), `"action":"settings"`)
	assert.Contains(t, history.Body.String(), `"action":"check"`)
	assert.Equal(t, 400, e.send(t, "PUT", path, map[string]any{"revision": 2, "automatic": true, "interval_hours": 0}, e.adminToken, "192.0.2.1:4000").Code)
}
