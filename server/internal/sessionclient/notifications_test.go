package sessionclient

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNativeNotificationSDKPreservesProviderAndDropsUnrecognizedSecretFields(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "PUT", r.Method)
		var input map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
		assert.Equal(t, "sdk-native-settings-001", input["request_id"])
		_, _ = w.Write([]byte(`{"revision":2,"sms":{"provider":"tencent","secret_configured":true,"sms_secret":"synthetic-hidden","native_sms":{"access_key_id":"synthetic-id","verification":{"id":"verify","parameters":["code"]}}},"webhook":{"provider":"wecom","bearer_configured":true,"token":"synthetic-hidden"},"webhook_secret":"synthetic-hidden"}`))
	}))
	defer srv.Close()
	c, e := New(srv.URL, "synthetic-token")
	require.NoError(t, e)
	out, e := c.SaveNotificationSettings(t.Context(), NotificationSettingsInput{Revision: 1, RequestID: "sdk-native-settings-001"})
	require.NoError(t, e)
	assert.Equal(t, "tencent", out.SMS.Provider)
	assert.Equal(t, "wecom", out.Webhook.Provider)
	raw, e := json.Marshal(out)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "synthetic-hidden")
	assert.Equal(t, 1, calls)
}

func TestNotificationSourceSDKScopesValidatesAndDecodesOnlyDTO(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "00000000-0000-0000-0000-000000000002", r.Header.Get("X-JMS-ORG"))
		assert.Equal(t, "/api/v1/notifications/sources/command-alerts/command-event-safe", r.URL.Path)
		_, _ = w.Write([]byte(`{"id":"command-event-safe","kind":"command-alerts","state":"command_denied","password":"synthetic-extra-secret","stdout":"synthetic-extra-output"}`))
	}))
	defer srv.Close()
	c, e := New(srv.URL, "synthetic-token")
	require.NoError(t, e)
	c, e = c.WithOrganization("00000000-0000-0000-0000-000000000002")
	require.NoError(t, e)
	v, e := c.NotificationSource(context.Background(), "command-alerts", "command-event-safe")
	require.NoError(t, e)
	assert.Equal(t, "command_denied", v.State)
	raw, _ := json.Marshal(v)
	assert.NotContains(t, string(raw), "synthetic-extra")
	for _, pair := range [][2]string{{"unknown", "safe"}, {"command-alerts", "../safe"}, {"command-reviews", "x/y"}, {"access-reviews", ""}, {"agent-events", "?token=private"}} {
		_, e = c.NotificationSource(context.Background(), pair[0], pair[1])
		require.Error(t, e)
	}
	assert.Equal(t, 1, calls)
}
