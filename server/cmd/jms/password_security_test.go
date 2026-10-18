package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestPasswordCLIRestrictedFlowNeverPrintsCapabilitiesOrPasswords(t *testing.T) {
	stage := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
		switch r.URL.Path {
		case "/api/v1/authentication/auth/":
			if stage == 0 {
				stage++
				w.WriteHeader(202)
				fmt.Fprint(w, `{"password_change_required":true,"change_token":"synthetic-change-capability","expires_at":"2099-01-01T00:00:00Z"}`)
			} else {
				fmt.Fprint(w, `{"access_token":"synthetic-session-capability","expires_at":"2099-01-01T00:00:00Z","user":{"id":"user-test"}}`)
			}
		case "/api/v1/authentication/password-change/pending":
			assert.Equal(t, "synthetic-change-capability", in["change_token"])
			fmt.Fprint(w, `{"password_change_required":true,"expires_at":"2099-01-01T00:00:00Z","policy":{"revision":2}}`)
		case "/api/v1/authentication/password-change/complete":
			assert.Equal(t, "synthetic-change-capability", in["change_token"])
			assert.Equal(t, "synthetic-new-password-233", in["new_password"])
			fmt.Fprint(w, `{"password_changed":true}`)
		}
	}))
	defer server.Close()
	c, e := sessionclient.New(server.URL, "")
	require.NoError(t, e)
	file := filepath.Join(t.TempDir(), "state.json")
	for _, step := range []struct{ action, body, next string }{{"login", `{"username":"operator","password":"synthetic-old-password-233"}`, "password-complete"}, {"status", `{}`, "password-complete"}, {"continue", `{"new_password":"synthetic-new-password-233"}`, "login"}, {"continue", `{"username":"operator","password":"synthetic-new-password-233"}`, "authenticated"}} {
		var out bytes.Buffer
		args := []string{step.action, "--state-file", file}
		if step.action != "status" {
			args = append(args, "--file", "-")
		}
		require.NoError(t, executeAuthentication(context.Background(), c, server.URL, args, strings.NewReader(step.body), &out))
		assert.Contains(t, out.String(), step.next)
		for _, secret := range []string{"synthetic-change-capability", "synthetic-session-capability", "synthetic-old-password-233", "synthetic-new-password-233"} {
			assert.NotContains(t, out.String(), secret)
		}
	}
	state, e := readAuthState(file, server.URL)
	require.NoError(t, e)
	assert.Empty(t, state.Result.ChangeToken)
	assert.Equal(t, "synthetic-session-capability", state.Result.AccessToken)
}
func TestPasswordCLIAdministrativeCommandsAndStrictInputs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/password/change") {
			w.WriteHeader(204)
			return
		}
		fmt.Fprint(w, `{"revision":2,"results":[],"total":0}`)
	}))
	defer server.Close()
	c, e := sessionclient.New(server.URL, "synthetic-cli-token")
	require.NoError(t, e)
	for _, args := range [][]string{{"password-settings"}, {"password-save", "--file", "-"}, {"password-audit"}} {
		var out bytes.Buffer
		require.NoError(t, executeAuthentication(context.Background(), c, server.URL, args, strings.NewReader(`{"revision":2}`), &out))
	}
	for _, args := range [][]string{{"reset-password", "user-test", "--file", "-"}, {"reset-mfa", "user-test", "--revision", "2"}, {"password", "--file", "-"}} {
		raw := `{"revision":2,"new_password":"synthetic-new-password-233"}`
		if args[0] == "password" {
			raw = `{"current_password":"synthetic-old-password-233","new_password":"synthetic-new-password-233"}`
		}
		var out bytes.Buffer
		require.NoError(t, executeUsers(context.Background(), c, args, strings.NewReader(raw), &out))
		assert.NotContains(t, out.String(), "synthetic-new-password-233")
	}
	var out bytes.Buffer
	assert.Error(t, executeUsers(context.Background(), c, []string{"reset-mfa", "user-test"}, strings.NewReader(`{}`), &out))
	assert.Error(t, executeAuthentication(context.Background(), c, server.URL, []string{"password-settings", "--file", "-"}, strings.NewReader(`{}`), &out))
}
