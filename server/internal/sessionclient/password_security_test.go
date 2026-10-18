package sessionclient

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPasswordSDKRoutesBodiesRestrictedStagesAndLimits(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if strings.Contains(r.URL.Path, "password-change") {
			var in map[string]string
			require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
			assert.Equal(t, "opaque-change-token", in["change_token"])
			if strings.HasSuffix(r.URL.Path, "complete") {
				assert.Equal(t, "synthetic-new-password-233", in["new_password"])
				fmt.Fprint(w, `{"password_changed":true}`)
			} else {
				fmt.Fprint(w, `{"password_change_required":true,"expires_at":"2099-01-01T00:00:00Z","policy":{"revision":2}}`)
			}
			return
		}
		assert.Equal(t, "Bearer synthetic-policy-token", r.Header.Get("Authorization"))
		if strings.HasSuffix(r.URL.Path, "/password/change") {
			w.WriteHeader(204)
			return
		}
		fmt.Fprint(w, `{"revision":2,"results":[],"total":0}`)
	}))
	defer server.Close()
	c, e := New(server.URL, "synthetic-policy-token")
	require.NoError(t, e)
	ctx := context.Background()
	p, e := c.PasswordPolicy(ctx)
	require.NoError(t, e)
	assert.Equal(t, 2, p.Revision)
	_, e = c.SavePasswordPolicy(ctx, PasswordPolicy{Revision: 2})
	require.NoError(t, e)
	_, e = c.PasswordPolicyAudit(ctx, 0, 25)
	require.NoError(t, e)
	_, e = c.ResetPassword(ctx, "user-test", PasswordResetInput{Revision: 2, NewPassword: "synthetic-new-password-233"})
	require.NoError(t, e)
	_, e = c.ResetMFA(ctx, "user-test", 2)
	require.NoError(t, e)
	require.NoError(t, c.ChangePassword(ctx, "synthetic-old-password-233", "synthetic-new-password-233"))
	out, e := c.Authentication(ctx, "password-status", AuthenticationInput{ChangeToken: "opaque-change-token"})
	require.NoError(t, e)
	assert.True(t, out.PasswordChangeRequired)
	require.NotNil(t, out.PasswordPolicy)
	out, e = c.Authentication(ctx, "password-complete", AuthenticationInput{ChangeToken: "opaque-change-token", NewPassword: "synthetic-new-password-233"})
	require.NoError(t, e)
	assert.True(t, out.PasswordChanged)
	assert.Equal(t, 8, calls)
	_, e = c.ResetPassword(ctx, "../escape", PasswordResetInput{Revision: 2, NewPassword: "synthetic-new-password-233"})
	require.Error(t, e)
	_, e = c.ResetMFA(ctx, "user-test", 0)
	require.Error(t, e)
	_, e = c.PasswordPolicyAudit(ctx, -1, 25)
	require.Error(t, e)
	assert.Error(t, c.ChangePassword(ctx, "current", "short"))
	assert.Equal(t, 8, calls)
}
func TestPasswordSDKRejectsConflictingPrivilegedResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"password_change_required":true,"access_token":"must-not-return","expires_at":"2099-01-01T00:00:00Z","user":{"id":"user-test"}}`)
	}))
	defer server.Close()
	c, e := New(server.URL, "")
	require.NoError(t, e)
	_, e = c.Authentication(context.Background(), "login", AuthenticationInput{})
	require.Error(t, e)
}
