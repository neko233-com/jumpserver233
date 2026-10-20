package sessionclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSMSMFASDKRestrictedAuthenticationStatusAndPublicDTOs(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path == "/api/v1/settings/security/sms-mfa" {
			_, _ = w.Write([]byte(`{"enabled":true,"policy":"all","user_ids":[],"revision":1,"secret":"synthetic-private"}`))
			return
		}
		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "private-sms-capability", body["factor_token"])
		switch r.URL.Path {
		case "/api/v1/authentication/sms/bind":
			assert.Equal(t, "+8613800000000", body["phone"])
			assert.NotEmpty(t, body["request_id"])
			_, _ = w.Write([]byte(`{"active":true,"purpose":"login-enroll","delivery_state":"sent","expires_at":"2099-01-01T00:00:00Z","needs_phone":false,"code":"synthetic-private"}`))
		case "/api/v1/authentication/sms/complete":
			assert.Equal(t, "123456", body["code"])
			_, _ = w.Write([]byte(`{"access_token":"synthetic-platform-token","expires_at":"2099-01-01T00:00:00Z","user":{"id":"user-safe","username":"safe"}}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	c, e := New(server.URL, "")
	require.NoError(t, e)
	out, e := c.Authentication(t.Context(), "sms-bind", AuthenticationInput{FactorToken: "private-sms-capability", Phone: "+8613800000000"})
	require.NoError(t, e)
	assert.True(t, out.SMSFactor)
	require.NotNil(t, out.SMSStatus)
	assert.False(t, out.SMSStatus.NeedsPhone)
	raw, _ := json.Marshal(out)
	assert.NotContains(t, string(raw), "synthetic-private")
	session, e := c.Authentication(t.Context(), "sms-complete", AuthenticationInput{FactorToken: "private-sms-capability", Code: "123456"})
	require.NoError(t, e)
	assert.Equal(t, "synthetic-platform-token", session.AccessToken)
	settings, e := c.SMSMFASettings(t.Context())
	require.NoError(t, e)
	raw, _ = json.Marshal(settings)
	assert.NotContains(t, string(raw), "synthetic-private")
	assert.Equal(t, 3, calls)
}
