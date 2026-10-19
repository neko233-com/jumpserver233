package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkspacePolicyIsAdminOnlyAndSFTPKeepsExistingAuthorization(t *testing.T) {
	e := newPolicyEnv(t)
	payload := map[string]any{"name": e.asset.Name, "host": e.asset.Host, "port": e.asset.Port, "username": e.asset.Username, "host_key_fingerprint": e.asset.HostKeyFingerprint, "ssh_workspace": "/srv/workspace"}
	denied := e.send(t, "PUT", "/api/v1/assets/"+e.asset.ID, payload, e.token, "192.0.2.1:4000")
	assert.Equal(t, http.StatusForbidden, denied.Code)
	updated := e.send(t, "PUT", "/api/v1/assets/"+e.asset.ID, payload, e.adminToken, "192.0.2.1:4000")
	require.Equal(t, http.StatusOK, updated.Code, updated.Body.String())
	// The existing file opener is now reached for granted users; it must not
	// silently use an ordinary SFTP channel in the asset service implementation.
	response := e.send(t, "GET", "/api/v1/assets/"+e.asset.ID+"/files", nil, e.adminToken, "192.0.2.1:4000")
	assert.Equal(t, http.StatusBadGateway, response.Code)
	a, e2 := e.d.Assets.Get(e.asset.ID)
	require.NoError(t, e2)
	assert.NotEqual(t, databaseBinding(e.asset), databaseBinding(a))
}
