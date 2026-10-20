package api

import (
	"encoding/json"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/enterpriselogin"
	"github.com/neko233-com/jumpserver233/server/internal/core/identityscope"
	"github.com/neko233-com/jumpserver233/server/internal/core/identitysources"
	"github.com/neko233-com/jumpserver233/server/internal/core/loginaudit"
	"github.com/neko233-com/jumpserver233/server/testsupport/enterpriseprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"html"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

func TestEnterpriseLoginNativeHTTPSMFACookiesAuditReplayAndDisablement(t *testing.T) {
	for _, kind := range []string{"wecom", "dingtalk", "feishu"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			identities, e := coreauth.OpenServiceWithVaultKey(filepath.Join(root, "users.json"), make([]byte, 32))
			require.NoError(t, e)
			_, e = identities.Bootstrap("local.admin", "synthetic-local-admin-password")
			require.NoError(t, e)
			fixture, e := enterpriseprovider.New()
			require.NoError(t, e)
			defer fixture.Close()
			bank, e := identitysources.Open(filepath.Join(root, "identity-sources.json"), make([]byte, 32), nil, "http://127.0.0.1:5177", identities, identitysources.Options{EnterpriseProvider: fixture.Client()})
			require.NoError(t, e)
			defer bank.Close()
			source, e := bank.Save("", "actor", identitysources.Input{Name: kind, Kind: kind, Enabled: true, RequestID: "native-api-source-001"})
			require.NoError(t, e)
			prefix := identityscope.Prefix(source.ID)
			_, runtime, _ := bank.Get(source.ID)
			c := enterpriseprovider.Config(kind, "http://127.0.0.1:5177"+prefix+"/api/v1/authentication/"+kind+"/callback")
			c.AllowLoopbackHTTP = true
			c.CAPEM = fixture.CAPEM
			_, e = runtime.Enterprise.Save(enterpriselogin.Input{Config: enterpriselogin.Config{Config: c, Enabled: true, ProvisionNew: true}, ClientSecret: enterpriseprovider.Secret, RequestID: "native-api-config-001"}, "actor", "admin")
			require.NoError(t, e)
			audit, e := loginaudit.Open(filepath.Join(root, "audit"), make([]byte, 32), nil)
			require.NoError(t, e)
			defer audit.Close()
			router := NewRouter("test", Dependencies{Auth: identities, IdentitySources: bank, LoginAudit: audit})
			_, e = identities.SetMFAEnforcement(coreauth.MFAEnforcementAll)
			require.NoError(t, e)
			base := prefix + "/api/v1/authentication/" + kind
			start := oidcSend(t, router, "GET", base+"/start", "")
			require.Equal(t, 303, start.Code, start.Body.String())
			flow := cookieNamed(t, start, "jms_"+kind+"_flow")
			assert.Equal(t, base, flow.Path)
			assert.True(t, flow.HttpOnly)
			location, e := url.Parse(start.Header().Get("Location"))
			require.NoError(t, e)
			authorization := httptest.NewRecorder()
			fixture.Authorize(authorization, httptest.NewRequest("GET", "/authorize?"+location.RawQuery, nil), kind)
			require.Equal(t, 200, authorization.Code)
			match := regexp.MustCompile(`href="([^"]+)"`).FindStringSubmatch(authorization.Body.String())
			require.Len(t, match, 2)
			back, e := url.Parse(html.UnescapeString(match[1]))
			require.NoError(t, e)
			callback := oidcSend(t, router, "GET", back.RequestURI(), "", flow)
			require.Equal(t, 303, callback.Code, callback.Body.String())
			assert.Contains(t, callback.Header().Get("Location"), "enterprise="+kind)
			pending := cookieNamed(t, callback, "jms_"+kind+"_pending")
			assert.Equal(t, base, pending.Path)
			assert.Equal(t, 401, oidcSend(t, router, "GET", "/api/v1/users/me", "", pending).Code)
			challenge := oidcSend(t, router, "POST", base+"/complete", `{}`, pending)
			require.Equal(t, 401, challenge.Code, challenge.Body.String())
			var setup struct {
				Token      string                 `json:"setup_token"`
				Enrollment coreauth.MFAEnrollment `json:"enrollment"`
			}
			require.NoError(t, json.Unmarshal(challenge.Body.Bytes(), &setup))
			require.NotEmpty(t, setup.Token)
			code := apiTOTPCode(t, setup.Enrollment.Secret, uint64(time.Now().Unix()/30))
			body := `{"setup_token":"` + setup.Token + `","otp":"` + code + `"}`
			complete := oidcSend(t, router, "POST", base+"/complete", body, pending)
			require.Equal(t, 200, complete.Code, complete.Body.String())
			assert.NotContains(t, complete.Body.String(), "access_token")
			assert.NotContains(t, complete.Body.String(), enterpriseprovider.Secret)
			var result struct {
				User coreauth.User `json:"user"`
			}
			require.NoError(t, json.Unmarshal(complete.Body.Bytes(), &result))
			assert.Equal(t, source.ID, result.User.SourceID)
			assert.Equal(t, kind, result.User.Source)
			assert.Equal(t, "operator", result.User.Role)
			session := cookieNamed(t, complete, sessionCookieName)
			assert.Equal(t, "/", session.Path)
			assertGrantedAudit(t, audit, kind)
			assert.Equal(t, 401, oidcSend(t, router, "POST", base+"/complete", body, pending).Code)
			second := oidcSend(t, router, "GET", back.RequestURI(), "", flow)
			assert.Contains(t, second.Header().Get("Location"), "enterprise_error=1")
			assert.Equal(t, 401, oidcSend(t, router, "POST", "/api/v1/authentication/auth/", `{"username":"`+result.User.Username+`","password":"synthetic-password"}`).Code)
			in := source.Input
			in.Enabled = false
			in.RequestID = "native-api-disable-001"
			off, e := bank.Save(source.ID, "actor", in)
			require.NoError(t, e)
			assert.Equal(t, 401, oidcSend(t, router, "GET", "/api/v1/users/me", "", session).Code)
			in = off.Input
			in.Enabled = true
			in.RequestID = "native-api-enable-001"
			_, e = bank.Save(source.ID, "actor", in)
			require.NoError(t, e)
			assert.Equal(t, 401, oidcSend(t, router, "GET", "/api/v1/users/me", "", session).Code)
		})
	}
}
