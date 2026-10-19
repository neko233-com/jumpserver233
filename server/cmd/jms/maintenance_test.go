package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/core/servicemaintenance"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDrainCLIUsesExplicitInstanceRevisionAndIdempotentRequest(t *testing.T) {
	c, e := servicemaintenance.New(workgate.New(), true, func(servicemaintenance.Event) error { return nil })
	require.NoError(t, e)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/settings/security/maintenance", r.URL.Path)
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(c.Snapshot())
			return
		}
		var in servicemaintenance.Input
		require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
		out, e := c.Change(in, "admin", "admin")
		if e != nil {
			w.WriteHeader(409)
			return
		}
		json.NewEncoder(w).Encode(out)
	}))
	defer server.Close()
	client, e := sessionclient.New(server.URL, "")
	require.NoError(t, e)
	var out bytes.Buffer
	require.NoError(t, executeDrain(context.Background(), client, []string{"drain-status"}, &out))
	assert.Contains(t, out.String(), `"draining":false`)
	args := []string{"drain-start", "--instance", c.Snapshot().Instance, "--revision", "1", "--request-id", "cli-drain-request", "--wait", "1s"}
	for i := 0; i < 2; i++ {
		out.Reset()
		require.NoError(t, executeDrain(context.Background(), client, args, &out))
		assert.Contains(t, out.String(), `"ready":true`)
	}
	for _, bad := range [][]string{{}, {"drain-status", "--revision", "1"}, {"drain-start"}, {"drain-cancel", "--instance", "x", "--revision", "1", "--request-id", "request-01", "--wait", "1s"}} {
		assert.Error(t, executeDrain(context.Background(), client, bad, &out))
	}
}
