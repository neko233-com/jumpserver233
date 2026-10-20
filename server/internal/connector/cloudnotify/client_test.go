package cloudnotify_test

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/connector/cloudnotify"
	"github.com/neko233-com/jumpserver233/server/testsupport/enterpriseprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNativeNotificationSMSAndSignedChatUseVerifiedHTTPS(t *testing.T) {
	fixture, e := enterpriseprovider.New()
	require.NoError(t, e)
	defer fixture.Close()
	client := fixture.NativeClient()
	for _, kind := range []string{"aliyun", "tencent", "huawei"} {
		t.Run(kind, func(t *testing.T) {
			cfg := enterpriseprovider.SMSConfig(kind)
			result := client.SendSMS(t.Context(), kind, cfg, enterpriseprovider.NotifySecret, fixture.CAPEM, "+8613800000000", "synthetic-delivery-001", true, map[string]string{"code": "123456"}, nil)
			assert.Equal(t, "sent", result.State)
			require.NotEmpty(t, result.Receipt)
			captures := fixture.NotificationCaptures()
			last := captures[len(captures)-1]
			assert.Equal(t, kind, last.Provider)
			assert.Equal(t, "123456", last.Code)
			assert.Equal(t, "+8613800000000", last.To)
			result = client.SendSMS(t.Context(), kind, cfg, enterpriseprovider.NotifySecret, fixture.CAPEM, "+8613800000000", "synthetic-notification-001", false, map[string]string{"title": "Security notification", "state": "failed"}, nil)
			assert.Equal(t, "sent", result.State)
			result = client.SendSMS(t.Context(), kind, cfg, "wrong-secret", fixture.CAPEM, "+8613800000000", "synthetic-rejection", true, map[string]string{"code": "123456"}, nil)
			assert.Equal(t, "failed", result.State)
		})
	}
	for _, kind := range []string{"wecom", "dingtalk", "feishu", "lark"} {
		t.Run(kind, func(t *testing.T) {
			out := client.SendChat(t.Context(), kind, enterpriseprovider.BotToken, enterpriseprovider.NotifySecret, fixture.CAPEM, "synthetic-chat-001", "Synthetic security metadata", nil)
			assert.Equal(t, "sent", out.State)
			captures := fixture.NotificationCaptures()
			last := captures[len(captures)-1]
			assert.Equal(t, kind, last.Provider)
			assert.Equal(t, "Synthetic security metadata", last.Text)
		})
	}
	rejected := client.SendChat(t.Context(), "wecom", enterpriseprovider.BotToken, "", "", "synthetic-chat-tls", "metadata", nil)
	assert.Equal(t, "failed", rejected.State)
	assert.Equal(t, "tls_invalid", rejected.Code)
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestNativeNotificationReceiptClassificationNeverLeaksPayloadOrRetriesUnknownAcceptance(t *testing.T) {
	for _, row := range []struct {
		name, body, state string
		status            int
	}{{"accepted", `{"errcode":0}`, "sent", 200}, {"rejected", `{"errcode":40013}`, "failed", 200}, {"missing", `{}`, "uncertain", 200}, {"duplicate", `{"errcode":1,"errcode":0}`, "uncertain", 200}, {"oversize", strings.Repeat("x", 65537), "uncertain", 200}, {"redirect", `{}`, "failed", 302}, {"rate", `{}`, "retry", 429}, {"unavailable", `{}`, "uncertain", 500}} {
		t.Run(row.name, func(t *testing.T) {
			calls := 0
			c := cloudnotify.New()
			c.Transport = func(*tls.Config) http.RoundTripper {
				return roundTrip(func(r *http.Request) (*http.Response, error) {
					calls++
					return &http.Response{StatusCode: row.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(row.body))}, nil
				})
			}
			out := c.SendChat(t.Context(), "wecom", enterpriseprovider.BotToken, "", "", "synthetic-id", "private-metadata", nil)
			assert.Equal(t, row.state, out.State)
			assert.Equal(t, 1, calls)
			assert.NotContains(t, out.Code, "private-metadata")
			assert.NotContains(t, out.Code, enterpriseprovider.BotToken)
		})
	}
	c := cloudnotify.New()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	out := c.SendChat(ctx, "wecom", enterpriseprovider.BotToken, "", "", "synthetic-id", "metadata", nil)
	assert.Equal(t, "suppressed", out.State)
}
func TestNativeNotificationConfigurationRejectsAlternateHostsAndMalformedTemplates(t *testing.T) {
	cfg := enterpriseprovider.SMSConfig("huawei")
	for _, endpoint := range []string{"http://smsapi.cn-north-4.myhuaweicloud.com", "https://smsapi.cn-north-4.myhuaweicloud.com.attacker.invalid", "https://user@smsapi.cn-north-4.myhuaweicloud.com", "https://smsapi.cn-north-4.myhuaweicloud.com/?secret=x"} {
		cfg.Endpoint = endpoint
		assert.ErrorIs(t, cloudnotify.ValidateSMS("huawei", cfg), cloudnotify.ErrConfig)
	}
	cfg = enterpriseprovider.SMSConfig("aliyun")
	cfg.Verification.Parameters = []string{"code", "id"}
	assert.Error(t, cloudnotify.ValidateSMS("aliyun", cfg))
	cfg = enterpriseprovider.SMSConfig("cmpp")
	cfg.Endpoint = "tcp://127.0.0.1:7890"
	assert.Error(t, cloudnotify.ValidateSMS("cmpp", cfg))
}
