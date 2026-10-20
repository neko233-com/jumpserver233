package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSMSMFACLIContinuationKeepsCapabilitiesAndCodesOutOfOutput(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		switch calls {
		case 1:
			_, _ = w.Write([]byte(`{"sms_factor_required":true,"factor_token":"private-sms-capability","expires_at":"2099-01-01T00:00:00Z","status":{"active":true,"needs_phone":true,"expires_at":"2099-01-01T00:00:00Z"}}`))
		case 2:
			assert.Equal(t, "private-sms-capability", body["factor_token"])
			assert.Equal(t, "+8613800000000", body["phone"])
			_, _ = w.Write([]byte(`{"active":true,"needs_phone":false,"delivery_state":"sent","expires_at":"2099-01-01T00:00:00Z"}`))
		case 3:
			assert.Equal(t, "123456", body["code"])
			_, _ = w.Write([]byte(`{"access_token":"private-platform-token","expires_at":"2099-01-01T00:00:00Z","user":{"id":"user-safe","username":"safe"}}`))
		default:
			t.Fatal("unexpected request")
		}
	}))
	defer server.Close()
	client, e := sessionclient.New(server.URL, "")
	require.NoError(t, e)
	path := filepath.Join(t.TempDir(), "state.jms-auth.json")
	var output bytes.Buffer
	require.NoError(t, executeAuthentication(t.Context(), client, server.URL, []string{"login", "--state-file", path, "--file", "-"}, strings.NewReader(`{"username":"safe","password":"synthetic-password"}`), &output))
	assert.Contains(t, output.String(), "sms-bind")
	require.NoError(t, executeAuthentication(t.Context(), client, server.URL, []string{"continue", "--state-file", path, "--file", "-"}, strings.NewReader(`{"phone":"+8613800000000"}`), &output))
	assert.Contains(t, output.String(), "sms-complete")
	require.NoError(t, executeAuthentication(t.Context(), client, server.URL, []string{"continue", "--state-file", path, "--file", "-"}, strings.NewReader(`{"code":"123456"}`), &output))
	assert.Contains(t, output.String(), "authenticated")
	assert.NotContains(t, output.String(), "private-sms-capability")
	assert.NotContains(t, output.String(), "private-platform-token")
	assert.NotContains(t, output.String(), "123456")
	saved, e := readAuthState(path, server.URL)
	require.NoError(t, e)
	assert.Equal(t, "private-platform-token", saved.Result.AccessToken)
	assert.Empty(t, saved.Result.FactorToken)
}

func TestSMSMFACLIPersonalBindingUsesAuthenticatedSDKAndPrivateState(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/users/me/sms-mfa/enroll", r.URL.Path)
		assert.Equal(t, "Bearer synthetic-platform-token", r.Header.Get("Authorization"))
		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "+8613800000000", body["phone"])
		_, _ = w.Write([]byte(`{"factor_token":"private-binding-capability","status":{"active":true,"needs_phone":false,"masked_phone":"***0000","delivery_state":"sent","expires_at":"2099-01-01T00:00:00Z"}}`))
	}))
	defer server.Close()
	client, err := sessionclient.New(server.URL, "synthetic-platform-token")
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "binding.jms-auth.json")
	var out bytes.Buffer
	require.NoError(t, executeAuthentication(t.Context(), client, server.URL, []string{"sms-enroll", "--state-file", path, "--file", "-"}, strings.NewReader(`{"phone":"+8613800000000","password":"synthetic-password"}`), &out))
	assert.Contains(t, out.String(), "sms-complete")
	assert.NotContains(t, out.String(), "private-binding-capability")
	assert.NotContains(t, out.String(), "synthetic-password")
	assert.NotContains(t, out.String(), "+8613800000000")
	state, err := readAuthState(path, server.URL)
	require.NoError(t, err)
	assert.Equal(t, "private-binding-capability", state.Result.FactorToken)
}
