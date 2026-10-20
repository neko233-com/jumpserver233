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

func TestEnterpriseLoginCLIStrictInputPathsAndSecretRedaction(t *testing.T) {
	calls := 0
	id := "idp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "Bearer synthetic-token", r.Header.Get("Authorization"))
		assert.Contains(t, r.URL.Path, "/"+id+"/api/v1/settings/security/")
		if strings.HasSuffix(r.URL.Path, "/audit") {
			_ = json.NewEncoder(w).Encode([]any{})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"provider": "wecom", "client_secret": "synthetic-secret-must-not-echo", "access_token": "synthetic-vendor-token", "has_client_secret": true, "application_credentials_available": true, "username": "native.operator"})
	}))
	defer server.Close()
	client, e := sessionclient.New(server.URL, "synthetic-token")
	require.NoError(t, e)
	for _, args := range [][]string{{"provider", "../escape", "wecom", "settings"}, {"provider", id, "unknown", "settings"}, {"provider", id, "wecom", "unknown"}, {"provider", id, "wecom", "save", "--file", "-"}} {
		var out bytes.Buffer
		require.Error(t, executeIdentitySources(t.Context(), client, args, strings.NewReader(`{}`), &out))
	}
	assert.Zero(t, calls)
	for _, action := range []string{"settings", "check", "audit", "save", "prepare"} {
		args := []string{"provider", id, "wecom", action}
		body := ""
		if action == "save" {
			args = append(args, "--file", "-")
			body = `{"provider":"wecom","revision":0,"request_id":"cli-provider-001","client_secret":"synthetic-write-only"}`
		} else if action == "prepare" {
			args = append(args, "--file", "-")
			body = `{"subject":"stable-subject","username":"native.operator"}`
		}
		var out bytes.Buffer
		require.NoError(t, executeIdentitySources(context.Background(), client, args, strings.NewReader(body), &out))
		assert.NotContains(t, out.String(), "synthetic-secret-must-not-echo")
		assert.NotContains(t, out.String(), "synthetic-vendor-token")
	}
	assert.Equal(t, 5, calls)
}
