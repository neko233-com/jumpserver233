package enterpriseoauth_test

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/connector/enterpriseoauth"
	"github.com/neko233-com/jumpserver233/server/testsupport/enterpriseprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestEnterpriseOAuthNativeHTTPSContractsAndOneTimeCodes(t *testing.T) {
	for _, tc := range []struct{ kind, region, version string }{{"wecom", "cn", "v3"}, {"dingtalk", "cn", "v3"}, {"feishu", "cn", "v3"}, {"feishu", "global", "v3"}, {"feishu", "cn", "v2"}, {"feishu", "global", "v2"}} {
		t.Run(tc.kind+"-"+tc.region+"-"+tc.version, func(t *testing.T) {
			fixture, e := enterpriseprovider.New()
			require.NoError(t, e)
			defer fixture.Close()
			c := enterpriseprovider.Config(tc.kind, "https://console.example.invalid/callback")
			c.CAPEM = fixture.CAPEM
			c.Region = tc.region
			c.OAuthVersion = tc.version
			client := fixture.Client()
			verifier := strings.Repeat("a", 43)
			start, e := client.Begin(c, strings.Repeat("s", 43), verifier)
			require.NoError(t, e)
			assert.Contains(t, start, "state=")
			assert.NotContains(t, start, enterpriseprovider.Secret)
			if tc.kind == "feishu" {
				assert.Contains(t, start, "code_challenge_method=S256")
				if tc.region == "global" {
					assert.Contains(t, start, "accounts.larksuite.com")
				} else {
					assert.Contains(t, start, "accounts.feishu.cn")
				}
			}
			code := fixture.Issue(tc.kind, c.CallbackURL, verifier, "")
			identity, e := client.Exchange(t.Context(), c, enterpriseprovider.Secret, code, verifier)
			require.NoError(t, e)
			expected := map[string]string{"wecom": enterpriseprovider.WeComSubject, "dingtalk": enterpriseprovider.DingSubject, "feishu": enterpriseprovider.FeishuSubject}
			assert.Equal(t, expected[tc.kind], identity.Subject)
			_, e = client.Exchange(t.Context(), c, enterpriseprovider.Secret, code, verifier)
			assert.Error(t, e)
			require.NoError(t, client.Check(t.Context(), c, enterpriseprovider.Secret))
			assert.Equal(t, int32(1), fixture.AppTokens.Load())
		})
	}
}
func TestEnterpriseOAuthRejectsExternalInactiveMismatchedAndAmbiguousIdentities(t *testing.T) {
	for _, tc := range []struct{ kind, scenario string }{{"wecom", "external"}, {"wecom", "inactive"}, {"wecom", "duplicate"}, {"dingtalk", "tenant"}, {"dingtalk", "external"}, {"dingtalk", "inactive"}, {"feishu", "tenant"}, {"feishu", "external"}, {"feishu", "inactive"}, {"feishu", "redirect"}} {
		t.Run(tc.kind+"-"+tc.scenario, func(t *testing.T) {
			fixture, e := enterpriseprovider.New()
			require.NoError(t, e)
			defer fixture.Close()
			c := enterpriseprovider.Config(tc.kind, "https://console.example.invalid/callback")
			c.CAPEM = fixture.CAPEM
			client := fixture.Client()
			verifier := strings.Repeat("v", 43)
			code := fixture.Issue(tc.kind, c.CallbackURL, verifier, tc.scenario)
			identity, e := client.Exchange(t.Context(), c, enterpriseprovider.Secret, code, verifier)
			require.Error(t, e)
			assert.Empty(t, identity.Subject)
			assert.NotContains(t, e.Error(), enterpriseprovider.Secret)
			assert.NotContains(t, e.Error(), code)
		})
	}
}
func TestEnterpriseOAuthPKCEAndConfigurationBoundaries(t *testing.T) {
	fixture, e := enterpriseprovider.New()
	require.NoError(t, e)
	defer fixture.Close()
	c := enterpriseprovider.Config("feishu", "https://console.example.invalid/callback")
	c.CAPEM = fixture.CAPEM
	client := fixture.Client()
	verifier := strings.Repeat("a", 43)
	code := fixture.Issue("feishu", c.CallbackURL, verifier, "")
	_, e = client.Exchange(t.Context(), c, enterpriseprovider.Secret, code, strings.Repeat("b", 43))
	assert.Error(t, e)
	c.CallbackURL = "http://console.example.invalid/callback"
	assert.ErrorIs(t, enterpriseoauth.Validate(c), enterpriseoauth.ErrConfig)
	c.CallbackURL = "http://127.0.0.1:5177/callback"
	c.AllowLoopbackHTTP = true
	require.NoError(t, enterpriseoauth.Validate(c))
	c.Scopes = []string{"offline_access"}
	assert.ErrorIs(t, enterpriseoauth.Validate(c), enterpriseoauth.ErrConfig)
	c.Scopes = []string{}
	c.Region = "unknown"
	assert.ErrorIs(t, enterpriseoauth.Validate(c), enterpriseoauth.ErrConfig)
	c.Region = "cn"
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, e = client.Exchange(ctx, c, enterpriseprovider.Secret, "synthetic-code", verifier)
	assert.Error(t, e)
}
