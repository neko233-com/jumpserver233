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

func TestAccountCollectionCLISafeDTOsBoundsAndExplicitRevision(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "Bearer synthetic-platform-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/assets/asset/account-discovery/plans":
			_, _ = w.Write([]byte(`[{"id":"plan","config_revision":1,"password":"synthetic-should-drop"}]`))
		case "POST /api/v1/assets/asset/account-discovery/plans":
			var v sessionclient.AccountCollectionPlanInput
			require.NoError(t, json.NewDecoder(r.Body).Decode(&v))
			assert.Equal(t, 60, v.Interval)
			assert.NotEmpty(t, v.RequestID)
			_, _ = w.Write([]byte(`{"id":"plan","config_revision":1}`))
		case "PUT /api/v1/assets/asset/account-discovery/plans/plan":
			var v sessionclient.AccountCollectionPlanUpdate
			require.NoError(t, json.NewDecoder(r.Body).Decode(&v))
			assert.False(t, v.Enabled)
			assert.Equal(t, 3, v.Revision)
			_, _ = w.Write([]byte(`{"id":"plan","config_revision":4}`))
		case "GET /api/v1/assets/asset/account-discovery/collections":
			assert.Equal(t, "42", r.URL.Query().Get("before"))
			assert.Equal(t, "10", r.URL.Query().Get("limit"))
			_, _ = w.Write([]byte(`{"results":[{"receipt":{"run":{"password":"synthetic-should-drop"},"job":{"password":"synthetic-should-drop","state":"succeeded"}}}],"next_before":0}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer s.Close()
	c, err := sessionclient.New(s.URL, "synthetic-platform-token")
	require.NoError(t, err)
	for _, args := range [][]string{{"plans", "asset"}, {"schedule", "asset", "--interval", "60"}, {"plan", "asset", "plan", "--enabled=false", "--revision", "3"}, {"collections", "asset", "--before", "42", "--limit", "10"}} {
		var out bytes.Buffer
		require.NoError(t, executeAccounts(context.Background(), c, args, &out))
		assert.NotContains(t, out.String(), "synthetic-")
	}
	assert.Equal(t, 4, calls)
	for _, args := range [][]string{{"plans", ""}, {"plans", "asset", "extra"}, {"schedule", "asset", "--interval", "59"}, {"schedule", "asset", "--interval", "86401"}, {"plan", "asset", "plan", "--revision", "3"}, {"plan", "asset", "plan", "--enabled=false"}, {"plan", "asset", "plan", "--enabled=false", "--revision", "0"}, {"collections", "asset", "--before", "-1"}, {"collections", "asset", "--limit", "101"}} {
		require.Error(t, executeAccounts(context.Background(), c, args, &bytes.Buffer{}))
	}
	assert.Equal(t, 4, calls)
}
