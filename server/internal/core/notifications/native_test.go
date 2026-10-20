package notifications

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/neko233-com/jumpserver233/server/testsupport/enterpriseprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNativeNotificationSettingsReceiptsAreEncryptedIndependentAndSurviveReopen(t *testing.T) {
	s, f, path := setup(t)
	secret, token := enterpriseprovider.NotifySecret, enterpriseprovider.BotToken
	cfg, e := s.Settings(t.Context(), "admin")
	require.NoError(t, e)
	in := SettingsInput{Revision: cfg.Revision, RequestID: "native-settings-001", Webhook: HTTPChannel{Enabled: true, Provider: "dingtalk"}, WebhookBearer: &token, WebhookSecret: &secret, SMS: HTTPChannel{Enabled: true, Provider: "aliyun", NativeSMS: enterpriseprovider.SMSConfig("aliyun")}, SMSSecret: &secret}
	saved, e := s.SaveSettings(t.Context(), "admin", in)
	require.NoError(t, e)
	saved.SMS.NativeSMS.Verification.Parameters[0] = "mutated"
	again, e := s.SaveSettings(t.Context(), "admin", in)
	require.NoError(t, e)
	assert.Equal(t, []string{"code"}, again.SMS.NativeSMS.Verification.Parameters)
	assert.Equal(t, in.Revision+1, again.Revision)
	changed := in
	changed.SMS.NativeSMS.SignName = "changed"
	_, e = s.SaveSettings(t.Context(), "admin", changed)
	assert.ErrorIs(t, e, ErrConflict)
	public, e := json.Marshal(again)
	require.NoError(t, e)
	assert.NotContains(t, string(public), secret)
	assert.NotContains(t, string(public), token)
	disk, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.NotContains(t, string(disk), secret)
	assert.NotContains(t, string(disk), "dingtalk")
	_, e = s.SaveSettings(t.Context(), "operator", in)
	assert.ErrorIs(t, e, ErrDenied)
	switchProvider := SettingsInput{Revision: again.Revision, RequestID: "native-settings-002", Webhook: HTTPChannel{Enabled: true, Provider: "feishu"}, SMS: again.SMS}
	_, e = s.SaveSettings(t.Context(), "admin", switchProvider)
	assert.ErrorIs(t, e, ErrInvalid)
	s.Close()
	reopened, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	defer reopened.Close()
	reopened.SetRunner(f.runner())
	receipt, e := reopened.SaveSettings(t.Context(), "admin", in)
	require.NoError(t, e)
	assert.Equal(t, again, receipt)
}
func TestNativeNotificationCloudSMSUsesExistingContactBindingAndExactlyOnceQueue(t *testing.T) {
	for _, kind := range []string{"aliyun", "tencent", "huawei"} {
		t.Run(kind, func(t *testing.T) {
			s, f, _ := setup(t)
			cfg, e := s.Settings(t.Context(), "admin")
			require.NoError(t, e)
			secret := enterpriseprovider.NotifySecret
			_, e = s.SaveSettings(t.Context(), "admin", SettingsInput{Revision: cfg.Revision, SMS: HTTPChannel{Enabled: true, Provider: kind, NativeSMS: enterpriseprovider.SMSConfig(kind)}, SMSSecret: &secret})
			require.NoError(t, e)
			p, e := s.Preferences(t.Context(), "operator")
			require.NoError(t, e)
			_, e = s.SavePreferences(t.Context(), "operator", PreferencesInput{Revision: p.Revision, Language: "en", Phone: "+8613800000000", Topics: p.Topics})
			require.NoError(t, e)
			_, e = s.RequestVerification(t.Context(), "operator", "sms")
			require.NoError(t, e)
			drain(t, s)
			f.mu.Lock()
			require.Len(t, f.sent, 1)
			out := f.sent[0]
			f.mu.Unlock()
			assert.Equal(t, kind, out.Settings.SMS.Provider)
			assert.Equal(t, "+8613800000000", out.Destination)
			require.Len(t, out.VerificationCode, 6)
			verified, e := s.Verify(t.Context(), "operator", "sms", out.VerificationCode)
			require.NoError(t, e)
			assert.True(t, verified.PhoneVerified)
			_, e = s.Verify(t.Context(), "operator", "sms", out.VerificationCode)
			assert.Error(t, e)
			verified.Topics["system"] = []string{"inbox", "sms"}
			_, e = s.SavePreferences(t.Context(), "operator", PreferencesInput{Revision: verified.Revision, Language: "en", Phone: verified.Phone, Topics: verified.Topics})
			require.NoError(t, e)
			a, e := s.Test(t.Context(), "operator", "native-test-receipt")
			require.NoError(t, e)
			b, e := s.Test(t.Context(), "operator", "native-test-receipt")
			require.NoError(t, e)
			assert.Equal(t, a.ID, b.ID)
			drain(t, s)
			drain(t, s)
			f.mu.Lock()
			assert.Len(t, f.sent, 2)
			f.mu.Unlock()
		})
	}
}
