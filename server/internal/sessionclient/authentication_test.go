package sessionclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticationSDKStrictStepPayloadAndCapabilities(t *testing.T) {
	for _, step := range []string{"login", "radius-login", "radius-challenge", "radius-complete", "factor-complete", "factor-cancel", "review-status", "review-complete", "mfa-setup"} {
		t.Run(step, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "POST", r.Method)
				assert.Empty(t, r.Header.Get("Authorization"))
				var payload map[string]string
				require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
				if step != "login" && step != "radius-login" {
					assert.NotContains(t, payload, "password")
					assert.NotContains(t, payload, "username")
				}
				if step == "factor-complete" {
					assert.Equal(t, map[string]string{"factor_token": "factor", "response": "code"}, payload)
				}
				w.WriteHeader(202)
				w.Write([]byte(`{"radius_factor_required":true,"factor_token":"factor"}`))
			}))
			defer server.Close()
			c, e := New(server.URL, "unused-platform-token")
			require.NoError(t, e)
			result, e := c.Authentication(t.Context(), step, AuthenticationInput{Username: "qa", Password: "private-password", Response: "code", PendingToken: "pending", ChallengeToken: "challenge", FactorToken: "factor", ReviewToken: "review", SetupToken: "setup"})
			require.NoError(t, e)
			assert.True(t, result.RadiusFactor)
			assert.Equal(t, "factor", result.FactorToken)
		})
	}
}
func TestAuthenticationSDKSafeErrorsAndLimits(t *testing.T) {
	for _, body := range []string{`{"detail":"private-password"}`, strings.Repeat("x", 65537)} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401); w.Write([]byte(body)) }))
		c, e := New(server.URL, "")
		require.NoError(t, e)
		_, e = c.Authentication(t.Context(), "radius-login", AuthenticationInput{})
		require.Error(t, e)
		assert.NotContains(t, e.Error(), "private-password")
		server.Close()
	}
}
func TestAuthenticationSDKReviewState(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/authentication/login-review/status", r.URL.Path)
		w.Write([]byte(`{"active":true,"state":"approved","review_id":"review"}`))
	}))
	defer server.Close()
	c, e := New(server.URL, "")
	require.NoError(t, e)
	out, e := c.Authentication(t.Context(), "review-status", AuthenticationInput{ReviewToken: "opaque-review"})
	require.NoError(t, e)
	assert.True(t, out.Active)
	assert.Equal(t, "approved", out.State)
	assert.Empty(t, out.AccessToken)
}
