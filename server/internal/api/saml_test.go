package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/samlclient"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/samllogin"
	"github.com/neko233-com/jumpserver233/server/testsupport/samlprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type samlEnvironment struct {
	router     http.Handler
	auth       *coreauth.Service
	saml       *samllogin.Service
	provider   *samlprovider.Provider
	adminToken string
}

func samlEnv(t *testing.T) *samlEnvironment {
	t.Helper()
	p, e := samlprovider.New("https://idp.example.invalid")
	require.NoError(t, e)
	root := t.TempDir()
	auth, e := coreauth.OpenServiceWithVaultKey(filepath.Join(root, "users.json"), make([]byte, 32))
	require.NoError(t, e)
	_, e = auth.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, e)
	admin, e := auth.Authenticate("admin", bootstrapPassword)
	require.NoError(t, e)
	saml, e := samllogin.Open(filepath.Join(root, "saml.json"), make([]byte, 32), nil, "")
	require.NoError(t, e)
	_, e = saml.Save(samllogin.Config{Config: samlclient.Config{EntityID: "http://127.0.0.1:5177/sp", ACSURL: "http://127.0.0.1:5177" + samlclient.ACSPath, MetadataXML: p.Metadata(), AllowLoopbackHTTP: true}, Enabled: true}, "admin-id", "admin")
	require.NoError(t, e)
	return &samlEnvironment{router: NewRouter("test", Dependencies{Auth: auth, SAML: saml, Assets: testAssetService(t)}), auth: auth, saml: saml, provider: p, adminToken: admin.AccessToken}
}
func samlCallback(t *testing.T, e *samlEnvironment) *httptest.ResponseRecorder {
	t.Helper()
	start := oidcSend(t, e.router, "GET", "/api/v1/authentication/saml/start", "")
	require.Equal(t, 303, start.Code)
	req, state, err := samlprovider.Request(start.Header().Get("Location"))
	require.NoError(t, err)
	raw, err := e.provider.Response(req, nil)
	require.NoError(t, err)
	form := url.Values{"RelayState": {state}, "SAMLResponse": {raw}}
	r := httptest.NewRequest("POST", samlclient.ACSPath, strings.NewReader(form.Encode()))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", e.provider.BaseURL)
	accepted := httptest.NewRecorder()
	e.router.ServeHTTP(accepted, r)
	require.Equal(t, 303, accepted.Code)
	require.Contains(t, accepted.Header().Get("Location"), "/finalize?code=")
	target, err := url.Parse(accepted.Header().Get("Location"))
	require.NoError(t, err)
	callback := oidcSend(t, e.router, "GET", target.RequestURI(), "", cookieNamed(t, start, samlFlowCookie))
	require.Equal(t, 303, callback.Code)
	assert.NotContains(t, callback.Header().Get("Location"), samlprovider.Subject)
	assert.Equal(t, "no-referrer", callback.Header().Get("Referrer-Policy"))
	return callback
}
func TestSAMLProvisioningNeverLinksLocalAdminAndIssuesOnlyCookies(t *testing.T) {
	e := samlEnv(t)
	denied := samlCallback(t, e)
	assert.Contains(t, denied.Header().Get("Location"), "saml_error=1")
	assert.Len(t, e.auth.ListUsers(), 1)
	cfg := e.saml.Snapshot()
	cfg.ProvisionNew = true
	_, err := e.saml.Save(cfg, "admin", "admin")
	require.NoError(t, err)
	callback := samlCallback(t, e)
	assert.Contains(t, callback.Header().Get("Location"), "saml=continue")
	pending := cookieNamed(t, callback, samlPendingCookie)
	assert.True(t, pending.HttpOnly)
	assert.Equal(t, samlCookiePath, pending.Path)
	assert.Equal(t, 401, oidcSend(t, e.router, "GET", "/api/v1/users/me", "", pending).Code)
	complete := oidcSend(t, e.router, "POST", "/api/v1/authentication/saml/complete", "{}", pending)
	require.Equal(t, 200, complete.Code, complete.Body.String())
	assert.NotContains(t, complete.Body.String(), "access_token")
	var result struct {
		User coreauth.User `json:"user"`
	}
	require.NoError(t, json.Unmarshal(complete.Body.Bytes(), &result))
	assert.Equal(t, "saml", result.User.Source)
	assert.Equal(t, "operator", result.User.Role)
	assert.NotEqual(t, "admin", result.User.Username)
	session := cookieNamed(t, complete, sessionCookieName)
	assert.True(t, session.HttpOnly)
	assert.Equal(t, "[]\n", oidcSend(t, e.router, "GET", "/api/v1/assets", "", session).Body.String())
	assert.Equal(t, 403, oidcSend(t, e.router, "GET", "/api/v1/settings/security/saml", "", session).Code)
	assert.Equal(t, 401, oidcSend(t, e.router, "POST", "/api/v1/authentication/saml/complete", "{}", pending).Code)
	cfg = e.saml.Snapshot()
	cfg.Enabled = false
	_, err = e.saml.Save(cfg, "admin", "admin")
	require.NoError(t, err)
	assert.Equal(t, 401, oidcSend(t, e.router, "GET", "/api/v1/users/me", "", session).Code)
}
func TestSAMLMandatoryMFAAndCancellationStayBrowserBound(t *testing.T) {
	e := samlEnv(t)
	prepared := doJSONRequest(t, e.router, "POST", "/api/v1/settings/security/saml/users", `{"subject":"synthetic-saml-subject","username":"saml.operator"}`, e.adminToken, "127.0.0.1:1234")
	require.Equal(t, 201, prepared.Code)
	_, err := e.auth.SetMFAEnforcement(coreauth.MFAEnforcementAll)
	require.NoError(t, err)
	pending := cookieNamed(t, samlCallback(t, e), samlPendingCookie)
	setupResponse := oidcSend(t, e.router, "POST", "/api/v1/authentication/saml/complete", "{}", pending)
	require.Equal(t, 401, setupResponse.Code, setupResponse.Body.String())
	var setup struct {
		Token      string                 `json:"setup_token"`
		Enrollment coreauth.MFAEnrollment `json:"enrollment"`
	}
	require.NoError(t, json.Unmarshal(setupResponse.Body.Bytes(), &setup))
	require.NotEmpty(t, setup.Token)
	code := apiTOTPCode(t, setup.Enrollment.Secret, uint64(time.Now().Unix()/30))
	body, _ := json.Marshal(map[string]string{"setup_token": setup.Token, "otp": code})
	assert.Equal(t, 401, oidcSend(t, e.router, "POST", "/api/v1/authentication/mfa/setup/confirm", string(body)).Code)
	assert.Equal(t, 401, oidcSend(t, e.router, "POST", "/api/v1/authentication/saml/complete", string(body)).Code)
	assert.Equal(t, 401, oidcSend(t, e.router, "POST", "/api/v1/authentication/saml/complete", `{"setup_token":"foreign","otp":"000000"}`, pending).Code)
	done := oidcSend(t, e.router, "POST", "/api/v1/authentication/saml/complete", string(body), pending)
	require.Equal(t, 200, done.Code, done.Body.String())
	assert.Contains(t, done.Body.String(), `"mfa_enabled":true`)
	session := cookieNamed(t, done, sessionCookieName)
	assert.Equal(t, 403, oidcSend(t, e.router, "POST", "/api/v1/users/me/password/change", `{"current_password":"any","new_password":"synthetic-new-password"}`, session).Code)
	next := cookieNamed(t, samlCallback(t, e), samlPendingCookie)
	assert.Equal(t, 204, oidcSend(t, e.router, "DELETE", "/api/v1/authentication/saml/pending", "", next).Code)
	assert.Equal(t, 401, oidcSend(t, e.router, "POST", "/api/v1/authentication/saml/complete", "{}", next).Code)
}
func TestSAMLSourceIsolationRateBudgetAndSecureCookies(t *testing.T) {
	e := samlEnv(t)
	user, err := e.auth.EnsureExternalUser("saml", e.saml.Namespace(), samlprovider.Subject, "", true)
	require.NoError(t, err)
	enroll, err := e.auth.StartMFAEnrollment(user.ID)
	require.NoError(t, err)
	_, err = e.auth.ConfirmMFAEnrollment(user.ID, apiTOTPCode(t, enroll.Secret, uint64(time.Now().Unix()/30)))
	require.NoError(t, err)
	for i := 0; i < 6; i++ {
		pending := cookieNamed(t, samlCallback(t, e), samlPendingCookie)
		r := oidcSend(t, e.router, "POST", "/api/v1/authentication/saml/complete", `{"otp":"invalid"}`, pending)
		if i < 5 {
			assert.Equal(t, 401, r.Code)
		} else {
			assert.Equal(t, 429, r.Code)
		}
	}
	cfg := e.saml.Snapshot()
	cfg.ACSURL = "https://console.example.invalid" + samlclient.ACSPath
	next, err := samllogin.Open(filepath.Join(t.TempDir(), "saml.json"), make([]byte, 32), nil, "https://console.example.invalid")
	require.NoError(t, err)
	cfg.Revision = 0
	_, err = next.Save(cfg, "admin", "admin")
	require.NoError(t, err)
	router := NewRouter("test", Dependencies{Auth: e.auth, SAML: next, PublicURL: "https://console.example.invalid"})
	start := oidcSend(t, router, "GET", "/api/v1/authentication/saml/start", "")
	require.Equal(t, 303, start.Code)
	assert.True(t, cookieNamed(t, start, samlFlowCookie).Secure)
	r := httptest.NewRequest("POST", "/api/v1/authentication/saml/complete", strings.NewReader("{}"))
	r.Header.Set("Origin", "https://attacker.example.invalid")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	assert.Equal(t, 403, w.Code)
}
