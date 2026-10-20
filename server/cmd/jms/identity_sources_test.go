package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIdentitySourceCLIPathsStrictInputAndNoProviderRuntimeDependency(t *testing.T) {
	calls := 0
	id := "idp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "Bearer synthetic-token", r.Header.Get("Authorization"))
		switch {
		case r.URL.Path == "/api/v1/identity-sources" && r.Method == "GET":
			json.NewEncoder(w).Encode([]any{})
		case r.Method == "POST" || r.Method == "PUT":
			var body map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			json.NewEncoder(w).Encode(body)
		default:
			json.NewEncoder(w).Encode(map[string]any{"items": []any{}, "total": 0})
		}
	}))
	defer server.Close()
	c, e := sessionclient.New(server.URL, "synthetic-token")
	require.NoError(t, e)
	for _, args := range [][]string{{}, {"bad"}, {"get", "../bad"}, {"sync", id, "unknown"}, {"save", "--file", "-"}} {
		var out bytes.Buffer
		require.Error(t, executeIdentitySources(context.Background(), c, args, strings.NewReader(`{}`), &out))
	}
	assert.Zero(t, calls)
	for _, tc := range []struct {
		args []string
		body string
	}{{[]string{"list"}, ""}, {[]string{"get", id}, ""}, {[]string{"audit"}, ""}, {[]string{"save", "--file", "-"}, `{"name":"Directory","kind":"ldap","revision":0,"request_id":"cli-source-001"}`}, {[]string{"sync", id, "settings"}, ""}, {[]string{"sync", id, "entries"}, ""}, {[]string{"sync", id, "preview", "--file", "-"}, `{"revision":1,"request_id":"cli-preview-001"}`}, {[]string{"sync", id, "apply", "--file", "-"}, `{"revision":1,"request_id":"cli-apply-001","preview_id":"preview-owned"}`}} {
		var out bytes.Buffer
		require.NoError(t, executeIdentitySources(context.Background(), c, tc.args, strings.NewReader(tc.body), &out))
		assert.NotEmpty(t, out.String())
	}
	assert.Equal(t, 8, calls)
}
