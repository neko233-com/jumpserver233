package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSharingManagementCLIValidatesFlagsAndUsesPlatformClient(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		assert.Equal(t, "Bearer synthetic-platform-token", r.Header.Get("Authorization"))
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"shares":[],"members":[]}`))
		case http.MethodPost:
			_, _ = w.Write([]byte(`{"id":"abcdefghijklmnop","code":"synthetic-invitation-code"}`))
		default:
			w.WriteHeader(204)
		}
	}))
	defer server.Close()
	c, e := sessionclient.New(server.URL, "synthetic-platform-token")
	require.NoError(t, e)
	ctx := context.Background()
	for _, args := range [][]string{{}, {"create", "id"}, {"create", "id", "--users", "guest", "--mode", "admin"}, {"create", "id", "--users", "guest", "--minutes", "0"}, {"kick", "id", "extra"}, {"state", "id", "extra"}, {"events", "id", "--limit", "101"}} {
		var out bytes.Buffer
		assert.Error(t, executeShare(ctx, c, args, &out))
	}
	assert.Zero(t, requests.Load())
	var out bytes.Buffer
	require.NoError(t, executeShare(ctx, c, []string{"create", "abcdefghijklmnop", "--users", "guest,other", "--mode", "read_write", "--minutes", "5"}, &out))
	assert.Contains(t, out.String(), "synthetic-invitation-code")
	for _, args := range [][]string{{"state", "id"}, {"reclaim", "id"}, {"revoke", "id"}, {"kick", "id"}} {
		out.Reset()
		require.NoError(t, executeShare(ctx, c, args, &out))
	}
	assert.EqualValues(t, 5, requests.Load())
}
