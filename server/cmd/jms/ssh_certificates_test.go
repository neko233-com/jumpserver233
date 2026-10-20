package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSHCertificateCLIValidatesIDsStrictJSONAndCompleteSurface(t *testing.T) {
	id := "sshca-" + strings.Repeat("a", 32)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "Bearer synthetic-token", r.Header.Get("Authorization"))
		if r.Method == "DELETE" {
			w.WriteHeader(204)
			return
		}
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/issuers") {
			_ = json.NewEncoder(w).Encode([]any{})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "results": []any{}, "total": 0, "revision": 1})
	}))
	defer server.Close()
	c, e := sessionclient.New(server.URL, "synthetic-token")
	require.NoError(t, e)
	for _, args := range [][]string{{}, {"unknown"}, {"binding", "../escape"}, {"audit", "--limit", "101"}, {"rotate", id, "--revision", "1"}, {"activate", "../escape", "--revision", "1", "--request-id", "activate-cli-001"}, {"save", "--file", "-"}, {"bind", "host", "--file", "-"}} {
		var out bytes.Buffer
		require.Error(t, executeSSHCertificates(context.Background(), c, args, strings.NewReader(`{"unknown":true}`), &out))
		assert.Empty(t, out.String())
	}
	assert.Zero(t, calls)
	for _, tc := range []struct {
		args []string
		body string
	}{{[]string{"list"}, ""}, {[]string{"audit"}, ""}, {[]string{"save", "--file", "-"}, `{"name":"Builtin","provider":"builtin","enabled":true,"request_id":"cli-ca-001"}`}, {[]string{"save", id, "--file", "-"}, `{"name":"Builtin","provider":"builtin","enabled":true,"revision":1,"request_id":"cli-ca-002"}`}, {[]string{"binding", "asset-host"}, ""}, {[]string{"bind", "asset-host", "--file", "-"}, `{"issuer_id":"","revision":1,"request_id":"cli-bind-ca-001"}`}, {[]string{"rotate", id, "--revision", "1", "--request-id", "cli-rotate-ca-001"}, ""}, {[]string{"activate", id, "--revision", "2", "--request-id", "cli-activate-ca-001"}, ""}, {[]string{"delete", id, "--revision", "3", "--request-id", "cli-delete-ca-001"}, ""}} {
		var out bytes.Buffer
		require.NoError(t, executeSSHCertificates(context.Background(), c, tc.args, strings.NewReader(tc.body), &out))
		assert.NotEmpty(t, out.String())
	}
	assert.Equal(t, 9, calls)
}
