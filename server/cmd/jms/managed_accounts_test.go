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

func TestManagedAccountCLIReadsSecretsFromStdinAndReturnsSafeMetadata(t *testing.T) {
	var submitted sessionclient.ManagedAccountInput
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		assert.Equal(t, "Bearer synthetic-token", r.Header.Get("Authorization"))
		if r.Method == "GET" {
			_ = json.NewEncoder(w).Encode(sessionclient.ManagedAccountPage{Version: "parent-version", Results: []sessionclient.ManagedAccount{}, Total: 0})
			return
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&submitted))
		assert.Equal(t, "synthetic-cli-password", submitted.Password)
		assert.Equal(t, "parent-version", submitted.Version)
		assert.Equal(t, "operator", submitted.Username)
		require.NotNil(t, submitted.DiscoveryID)
		assert.Equal(t, strings.Repeat("a", 32), *submitted.DiscoveryID)
		_ = json.NewEncoder(w).Encode(sessionclient.ManagedAccount{ID: "endpoint", AssetID: "asset", Username: submitted.Username, Active: true})
	}))
	defer server.Close()
	c, e := sessionclient.New(server.URL, "synthetic-token")
	require.NoError(t, e)
	var output bytes.Buffer
	e = executeManagedAccount(context.Background(), c, []string{"create", "asset", "--username", "operator", "--name", "运维账号", "--discovery-id", strings.Repeat("a", 32), "--password-stdin"}, strings.NewReader("synthetic-cli-password\r\n"), &output)
	require.NoError(t, e)
	require.NotNil(t, submitted.Name)
	assert.Equal(t, "运维账号", *submitted.Name)
	assert.NotContains(t, output.String(), "synthetic-cli-password")
	assert.NotContains(t, output.String(), "synthetic-token")
	assert.Equal(t, 2, requests)
	for _, args := range [][]string{{"create", "asset", "--username", "operator", "--password", "forbidden-argv-secret"}, {"delete", "asset", "endpoint"}, {"list", "asset", "--limit", "101"}, {"create", "asset", "--username", "operator", "--password-stdin", "--private-key-file", "unknown"}} {
		e = executeManagedAccount(context.Background(), c, args, strings.NewReader("unused"), &output)
		require.Error(t, e)
		assert.NotContains(t, e.Error(), "forbidden-argv-secret")
	}
	assert.Equal(t, 2, requests)
}

func TestManagedCredentialInputAndGlobalAccountFlagRejectAmbiguity(t *testing.T) {
	for _, value := range []string{"", "one\ntwo", "one\x00two", strings.Repeat("s", 4097), string([]byte{0xff})} {
		_, e := readManagedSecret(strings.NewReader(value))
		require.Error(t, e)
	}
	assert.Error(t, run([]string{"--account", "operator"}))
	assert.Error(t, run([]string{"--account", "operator", "rdp", "asset"}))
}
