package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCLIAuthenticationStateKeepsCapabilitiesOffStdout(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var payload map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		switch calls {
		case 1:
			assert.Equal(t, "/api/v1/authentication/auth/", r.URL.Path)
			w.WriteHeader(202)
			w.Write([]byte(`{"radius_factor_required":true,"factor_token":"private-factor","expires_at":"2099-01-01T00:00:00Z"}`))
		case 2:
			assert.Equal(t, "/api/v1/authentication/factor/complete", r.URL.Path)
			assert.Equal(t, map[string]string{"factor_token": "private-factor", "response": "code"}, payload)
			w.Write([]byte(`{"access_token":"private-platform-token","user":{"id":"operator","username":"qa","role":"operator"},"expires_at":"2099-01-01T00:00:00Z"}`))
		}
	}))
	defer server.Close()
	client, e := sessionclient.New(server.URL, "")
	require.NoError(t, e)
	path := filepath.Join(t.TempDir(), "auth.json")
	var out bytes.Buffer
	require.NoError(t, executeAuthentication(t.Context(), client, server.URL, []string{"login", "--state-file", path, "--file", "-"}, strings.NewReader(`{"username":"qa","password":"private-password"}`), &out))
	assert.NotContains(t, out.String(), "private-factor")
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "private-password")
	out.Reset()
	require.NoError(t, executeAuthentication(t.Context(), client, server.URL, []string{"continue", "--state-file", path, "--file", "-"}, strings.NewReader(`{"response":"code"}`), &out))
	assert.NotContains(t, out.String(), "private-platform-token")
	state, e := readAuthState(path, server.URL)
	require.NoError(t, e)
	assert.Equal(t, "authenticated", state.Next)
	assert.Empty(t, state.Result.FactorToken)
	_, e = readAuthState(path, "https://other.invalid")
	assert.Error(t, e)
	t.Setenv("JMS_TOKEN", "")
	t.Setenv("JMS_ACCESS_KEY_ID", "")
	t.Setenv("JMS_ACCESS_KEY_SECRET", "")
	t.Setenv("JMS_TOKEN_FILE", path)
	_, e = clientFromEnvironment(server.URL)
	require.NoError(t, e)
	t.Setenv("JMS_TOKEN", "another")
	_, e = clientFromEnvironment(server.URL)
	assert.Error(t, e)
}
func TestCLIAuthenticationRejectsExpiredAndUnsafeState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	require.NoError(t, saveAuthState(path, authState{Server: "https://platform.invalid", Result: sessionclient.AuthenticationResult{ExpiresAt: time.Now().Add(-time.Minute)}}))
	_, e := readAuthState(path, "https://platform.invalid")
	assert.Error(t, e)
	for _, u := range []string{"https://name:secret@example.org", "https://example.org?token=x", "ftp://example.org"} {
		_, e = authServer(u)
		assert.Error(t, e)
	}
	assert.Equal(t, "factor-complete", authNext("factor-complete", sessionclient.AuthenticationResult{RadiusChallenge: true}))
	assert.Equal(t, "radius-challenge", authNext("radius-login", sessionclient.AuthenticationResult{RadiusChallenge: true}))
}
