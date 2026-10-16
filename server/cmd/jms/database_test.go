package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/core/databasequery"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDatabaseCLIUsesPlatformIdentityBoundParametersAndClosesSession(t *testing.T) {
	closed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer platform-token", r.Header.Get("Authorization"))
		assert.Equal(t, "00000000-0000-0000-0000-000000000002", r.Header.Get("X-JMS-ORG"))
		switch r.URL.Path {
		case "/api/v1/assets/db/database-sessions":
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"session_token":"opaque-db-session","read_only":true}`))
		case "/api/v1/assets/db/database-queries":
			assert.Equal(t, "opaque-db-session", r.Header.Get("X-JMS-DB-SESSION"))
			var in databasequery.Input
			require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
			assert.Equal(t, "SELECT $1::text", in.SQL)
			assert.True(t, in.ReadOnly)
			assert.Equal(t, `"hello"`, string(in.Parameters[0]))
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"id":"dbq-1","state":"queued"}`))
		case "/api/v1/database-queries/dbq-1":
			_, _ = w.Write([]byte(`{"id":"dbq-1","state":"completed","summary":{"transaction":"rolled_back"},"result":{"rows":[["hello"]]}}`))
		case "/api/v1/database-sessions":
			assert.Equal(t, "DELETE", r.Method)
			closed = true
			w.WriteHeader(204)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	client, e := sessionclient.New(server.URL, "platform-token")
	require.NoError(t, e)
	client, e = client.WithOrganization("00000000-0000-0000-0000-000000000002")
	require.NoError(t, e)
	var stdout, stderr bytes.Buffer
	require.NoError(t, executeDatabase(context.Background(), client, []string{"db", "--params", `["hello"]`}, strings.NewReader("SELECT $1::text"), &stdout, &stderr))
	assert.Contains(t, stdout.String(), "hello")
	assert.True(t, closed)
}
func TestDatabaseCLIRejectsInvalidInputBeforeAPI(t *testing.T) {
	client, e := sessionclient.New("http://127.0.0.1:1", "unused")
	require.NoError(t, e)
	for _, args := range [][]string{{}, {"db", "--timeout", "bad"}, {"db", "--params", "{}"}, {"db", "--rows", "0"}} {
		var out bytes.Buffer
		require.Error(t, executeDatabase(context.Background(), client, args, strings.NewReader("SELECT 1"), &out, &out))
	}
}
