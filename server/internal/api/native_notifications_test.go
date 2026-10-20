package api

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/core/notifications"
	"github.com/neko233-com/jumpserver233/server/testsupport/enterpriseprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNativeNotificationAPIProviderSettingsAreWriteOnlyAuthorizedAndIdempotent(t *testing.T) {
	e := newPolicyEnv(t)
	var err error
	e.d.Notifications, err = notifications.Open(filepath.Join(t.TempDir(), "notifications.json"), make([]byte, 32), nil)
	require.NoError(t, err)
	defer e.d.Notifications.Close()
	e.router = NewRouter("test", e.d)
	cfg, err := e.d.Notifications.Settings(t.Context(), e.admin.ID)
	require.NoError(t, err)
	token, secret := enterpriseprovider.BotToken, enterpriseprovider.NotifySecret
	input := notifications.SettingsInput{Revision: cfg.Revision, RequestID: "native-api-001", Webhook: notifications.HTTPChannel{Provider: "feishu", Enabled: true}, WebhookBearer: &token, WebhookSecret: &secret, SMS: notifications.HTTPChannel{Provider: "tencent", NativeSMS: enterpriseprovider.SMSConfig("tencent"), Enabled: true}, SMSSecret: &secret}
	send := func(in notifications.SettingsInput, identity string) int {
		return e.send(t, "PUT", "/api/v1/notifications/settings", in, identity, "192.0.2.1:4000").Code
	}
	assert.Equal(t, 403, send(input, e.token))
	require.Equal(t, 200, send(input, e.adminToken))
	require.Equal(t, 200, send(input, e.adminToken))
	input.SMS.NativeSMS.SignName = "changed"
	assert.Equal(t, 409, send(input, e.adminToken))
	get := e.send(t, "GET", "/api/v1/notifications/settings", nil, e.adminToken, "192.0.2.1:4000")
	require.Equal(t, 200, get.Code)
	assert.NotContains(t, get.Body.String(), secret)
	assert.NotContains(t, get.Body.String(), token)
	var value notifications.Settings
	require.NoError(t, json.Unmarshal(get.Body.Bytes(), &value))
	assert.Equal(t, "feishu", value.Webhook.Provider)
	assert.Equal(t, "tencent", value.SMS.Provider)
	assert.True(t, value.SMS.SecretConfigured)
	audit := e.send(t, "GET", "/api/v1/notifications/audit", nil, e.adminToken, "192.0.2.1:4000")
	assert.NotContains(t, audit.Body.String(), secret)
	assert.NotContains(t, audit.Body.String(), token)
}
