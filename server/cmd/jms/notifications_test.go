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

func TestNativeNotificationCLISettingsStdinAndProviderSecretRedaction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/notifications/settings", r.URL.Path)
		var input map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
		assert.Equal(t, "native-cli-001", input["request_id"])
		assert.Equal(t, "synthetic-provider-secret", input["sms_secret"])
		_, _ = w.Write([]byte(`{"revision":2,"sms":{"provider":"huawei","secret_configured":true},"sms_secret":"synthetic-provider-secret","webhook_bearer":"synthetic-provider-secret"}`))
	}))
	defer server.Close()
	c, e := sessionclient.New(server.URL, "synthetic-token")
	require.NoError(t, e)
	var out bytes.Buffer
	body := `{"revision":1,"request_id":"native-cli-001","sms":{"provider":"huawei"},"sms_secret":"synthetic-provider-secret"}`
	require.NoError(t, executeNotifications(t.Context(), c, []string{"settings-save", "--file", "-"}, strings.NewReader(body), &out))
	assert.Contains(t, out.String(), "huawei")
	assert.NotContains(t, out.String(), "synthetic-provider-secret")
}

func TestNotificationCLIAndSDKPathsCASStdinVerificationAndRedaction(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "Bearer synthetic-notification-client", r.Header.Get("Authorization"))
		assert.True(t, strings.HasPrefix(r.URL.Path, "/api/v1/notifications/"))
		switch r.URL.Path {
		case "/api/v1/notifications/verification/confirm":
			var in map[string]string
			require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
			assert.Equal(t, "123456", in["code"])
			assert.Equal(t, "sms", in["channel"])
			_ = json.NewEncoder(w).Encode(sessionclient.NotificationPreferences{PhoneVerified: true})
		case "/api/v1/notifications/deliveries/delivery-synthetic/retry":
			var in struct {
				Revision int  `json:"revision"`
				Ack      bool `json:"acknowledge_uncertain"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
			assert.Equal(t, 3, in.Revision)
			assert.True(t, in.Ack)
			_ = json.NewEncoder(w).Encode(sessionclient.NotificationDelivery{ID: "delivery-synthetic", State: "queued"})
		case "/api/v1/notifications/inbox":
			assert.Equal(t, "true", r.URL.Query().Get("unread"))
			_ = json.NewEncoder(w).Encode(sessionclient.NotificationInbox{Unread: 2})
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer server.Close()
	c, e := sessionclient.New(server.URL, "synthetic-notification-client")
	require.NoError(t, e)
	var output bytes.Buffer
	for _, args := range [][]string{{}, {"retry"}, {"retry", "delivery-synthetic"}, {"verify", "sms"}, {"list", "--limit", "101"}, {"read"}, {"settings-save"}, {"source"}, {"source", "unknown", "id"}, {"source", "command-alerts", "../escape"}} {
		assert.Error(t, executeNotifications(context.Background(), c, args, strings.NewReader(""), &output))
	}
	assert.Zero(t, calls)
	require.NoError(t, executeNotifications(context.Background(), c, []string{"source", "command-alerts", "command-event-synthetic"}, strings.NewReader(""), &output))
	calls = 0
	bad := `{"revision":1,"language":"en","email_verified":true}`
	assert.Error(t, executeNotifications(context.Background(), c, []string{"preferences-save", "--file", "-"}, strings.NewReader(bad), &output))
	assert.Zero(t, calls)
	require.NoError(t, executeNotifications(context.Background(), c, []string{"verify", "sms", "--code-stdin"}, strings.NewReader("123456\n"), &output))
	require.NoError(t, executeNotifications(context.Background(), c, []string{"retry", "delivery-synthetic", "--revision", "3", "--acknowledge-uncertain"}, strings.NewReader(""), &output))
	require.NoError(t, executeNotifications(context.Background(), c, []string{"list", "--unread"}, strings.NewReader(""), &output))
	for _, args := range [][]string{{"settings"}, {"preferences"}, {"health"}, {"audit"}, {"deliveries"}, {"request-code", "email"}, {"read", "message-synthetic"}, {"read-all"}, {"test", "--request-id", "stable-test"}, {"settings-save", "--file", "-"}, {"preferences-save", "--file", "-"}} {
		require.NoError(t, executeNotifications(context.Background(), c, args, strings.NewReader("{}"), &output))
	}
	assert.NotContains(t, output.String(), "123456")
	assert.NotContains(t, output.String(), "synthetic-notification-client")
}
func TestNotificationSDKMapsBoundedErrorCodes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(409)
		_, _ = w.Write([]byte(`{"error_code":"verification_required"}`))
	}))
	defer server.Close()
	c, e := sessionclient.New(server.URL, "synthetic")
	require.NoError(t, e)
	_, e = c.NotificationPreferences(context.Background())
	var apiError *sessionclient.APIError
	require.ErrorAs(t, e, &apiError)
	assert.Equal(t, "verification_required", apiError.Detail)
}
