package api

import (
	"encoding/json"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

func TestGatewayAPIPreservesRouteAndRejectsCycleOrReferencedDelete(t *testing.T) {
	router := NewRouter("test", Dependencies{Assets: testAssetService(t)})
	send := func(method, path string, input any, status int) []byte {
		raw, e := json.Marshal(input)
		require.NoError(t, e)
		w := doJSONRequest(t, router, method, path, string(raw), "", "127.0.0.1:43210")
		require.Equal(t, status, w.Code, w.Body.String())
		assert.NotContains(t, w.Body.String(), "synthetic-gateway-password")
		return w.Body.Bytes()
	}
	input := coreassets.Input{Name: "gateway", Host: "127.0.0.1", Port: 22, Username: "ops", Password: "synthetic-gateway-password", HostKeyFingerprint: validTestFingerprint()}
	var gateway, target coreassets.Asset
	require.NoError(t, json.Unmarshal(send("POST", "/api/v1/assets", input, 201), &gateway))
	input.Name = "private"
	input.Host = "private.synthetic.invalid"
	input.GatewayID = &gateway.ID
	require.NoError(t, json.Unmarshal(send("POST", "/api/v1/assets", input, 201), &target))
	assert.Equal(t, gateway.ID, target.GatewayID)
	send(http.MethodDelete, "/api/v1/assets/"+gateway.ID, nil, 409)
	input.Name = "cycle"
	input.GatewayID = &target.ID
	send("PUT", "/api/v1/assets/"+gateway.ID, input, 400)
	input.Name = "private"
	input.GatewayID = nil
	require.NoError(t, json.Unmarshal(send("PUT", "/api/v1/assets/"+target.ID, input, 200), &target))
	assert.Equal(t, gateway.ID, target.GatewayID)
	empty := ""
	input.GatewayID = &empty
	send("PUT", "/api/v1/assets/"+target.ID, input, 200)
	send("DELETE", "/api/v1/assets/"+gateway.ID, nil, 204)
}
