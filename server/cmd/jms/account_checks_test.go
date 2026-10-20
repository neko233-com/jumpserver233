package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountCheckCLIUsesPlatformIdentityWithoutRotationOrSecrets(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "/api/v1/accounts/rotation-plans/check-plan/checks", r.URL.Path)
		var in map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
		assert.Equal(t, "check-cli-request", in["request_id"])
		w.WriteHeader(202)
		_ = json.NewEncoder(w).Encode(sessionclient.RotationRun{ID: "check-run", Operation: "check", State: "failed"})
	}))
	defer server.Close()
	c, e := sessionclient.New(server.URL, "synthetic-platform-token")
	require.NoError(t, e)
	var out bytes.Buffer
	assert.Error(t, executeRotationPlans(context.Background(), c, []string{"check", "check-plan", "--fixed-password-file", "-"}, &out))
	assert.Zero(t, calls)
	e = executeRotationPlans(context.Background(), c, []string{"check", "check-plan", "--request-id", "check-cli-request", "--wait"}, &out)
	require.ErrorContains(t, e, "connectivity check requires attention")
	assert.Contains(t, out.String(), `"operation":"check"`)
	assert.NotContains(t, out.String(), "synthetic-platform-token")
	assert.Equal(t, 1, calls)
}
