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

func TestAccountsCLIUsesPlatformIdentityAndNeverTargetCredentials(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "Bearer synthetic-platform-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /api/v1/assets/asset/account-discovery/jobs":
			var in sessionclient.AccountDiscoveryRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
			assert.Equal(t, "request-stable", in.RequestID)
			_, _ = w.Write([]byte(`{"id":"job-native","state":"succeeded","stdout":"{\"observed\":2}"}`))
		case "GET /api/v1/assets/asset/discovered-accounts":
			_, _ = w.Write([]byte(`{"results":[],"total":0,"revision":1}`))
		case "PUT /api/v1/assets/asset/discovered-accounts/finding":
			_, _ = w.Write([]byte(`{"id":"finding","username":"ops","review":"acknowledged"}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	c, e := sessionclient.New(server.URL, "synthetic-platform-token")
	require.NoError(t, e)
	for _, args := range [][]string{{"discover", "asset", "--request-id", "request-stable"}, {"list", "asset"}, {"review", "asset", "finding", "--state", "acknowledged", "--revision", "1"}} {
		var out bytes.Buffer
		require.NoError(t, executeAccounts(context.Background(), c, args, &out))
		assert.NotContains(t, out.String(), "synthetic-platform-token")
		assert.Contains(t, out.String(), "\n")
	}
	assert.Equal(t, 3, calls)
	for _, args := range [][]string{{"discover", "asset", "--timeout", "0"}, {"review", "asset", "finding", "--state", "ignored"}, {"list", "asset", "--limit", "101"}} {
		require.Error(t, executeAccounts(context.Background(), c, args, &bytes.Buffer{}))
	}
	assert.Equal(t, 3, calls)
}
