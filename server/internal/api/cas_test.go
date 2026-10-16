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

	"github.com/neko233-com/jumpserver233/server/internal/connector/casclient"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/caslogin"
	"github.com/neko233-com/jumpserver233/server/testsupport/casprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type casEnvironment struct {
	router     http.Handler
	auth       *coreauth.Service
	cas        *caslogin.Service
	provider   *casprovider.Provider
	adminToken string
}

func casEnv(t *testing.T) *casEnvironment {
	t.Helper()
	p := casprovider.New("", casprovider.Options{Subject: "admin"})
	server := httptest.NewServer(p)
	t.Cleanup(server.Close)
	p.BaseURL = server.URL + "/cas"
	root := t.TempDir()
	auth, e := coreauth.OpenServiceWithVaultKey(filepath.Join(root, "users.json"), make([]byte, 32))
	require.NoError(t, e)
	_, e = auth.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, e)
	admin, e := auth.Authenticate("admin", bootstrapPassword)
	require.NoError(t, e)
	cas, e := caslogin.Open(filepath.Join(root, "cas.json"), make([]byte, 32), nil, "", nil)
	require.NoError(t, e)
	_, e = cas.Save(caslogin.Config{Config: casclient.Config{BaseURL: p.BaseURL, Protocol: "3", AllowLoopbackHTTP: true}, Enabled: true, CallbackURL: "http://127.0.0.1:5177" + caslogin.CallbackPath}, "admin-id", "admin")
	require.NoError(t, e)
	return &casEnvironment{router: NewRouter("test", Dependencies{Auth: auth, CAS: cas, Assets: testAssetService(t)}), auth: auth, cas: cas, provider: p, adminToken: admin.AccessToken}
}
func casCallback(t *testing.T, e *casEnvironment) *httptest.ResponseRecorder {
	t.Helper()
	start := oidcSend(t, e.router, "GET", "/api/v1/authentication/cas/start", "")
	require.Equal(t, 303, start.Code)
	login, err := url.Parse(start.Header().Get("Location"))
	require.NoError(t, err)
	service, err := url.Parse(login.Query().Get("service"))
	require.NoError(t, err)
	ticket, err := e.provider.Issue(service.String())
	require.NoError(t, err)
	q := service.Query()
	q.Set("ticket", ticket)
	callback := oidcSend(t, e.router, "GET", caslogin.CallbackPath+"?"+q.Encode(), "", cookieNamed(t, start, casFlowCookie))
	require.Equal(t, 303, callback.Code)
	assert.NotContains(t, callback.Header().Get("Location"), ticket)
	assert.Equal(t, "no-referrer", callback.Header().Get("Referrer-Policy"))
	return callback
}
func TestCASProvisioningNeverLinksLocalAdminAndIssuesOnlyCookies(t *testing.T) {
	e := casEnv(t)
	denied := casCallback(t, e)
	assert.Contains(t, denied.Header().Get("Location"), "cas_error=1")
	assert.Len(t, e.auth.ListUsers(), 1)
	cfg := e.cas.Snapshot()
	cfg.ProvisionNew = true
	_, err := e.cas.Save(cfg, "admin", "admin")
	require.NoError(t, err)
	callback := casCallback(t, e)
	assert.Contains(t, callback.Header().Get("Location"), "cas=continue")
	pending := cookieNamed(t, callback, casPendingCookie)
	assert.True(t, pending.HttpOnly)
	assert.Equal(t, casCookiePath, pending.Path)
	assert.Equal(t, 401, oidcSend(t, e.router, "GET", "/api/v1/users/me", "", pending).Code)
	complete := oidcSend(t, e.router, "POST", "/api/v1/authentication/cas/complete", "{}", pending)
	require.Equal(t, 200, complete.Code, complete.Body.String())
	assert.NotContains(t, complete.Body.String(), "access_token")
	var result struct {
		User coreauth.User `json:"user"`
	}
	require.NoError(t, json.Unmarshal(complete.Body.Bytes(), &result))
	assert.Equal(t, "cas", result.User.Source)
	assert.Equal(t, "operator", result.User.Role)
	assert.NotEqual(t, "admin", result.User.Username)
	session := cookieNamed(t, complete, sessionCookieName)
	assert.True(t, session.HttpOnly)
	assert.Equal(t, "[]\n", oidcSend(t, e.router, "GET", "/api/v1/assets", "", session).Body.String())
	assert.Equal(t, 403, oidcSend(t, e.router, "GET", "/api/v1/settings/security/cas", "", session).Code)
	assert.Equal(t, 401, oidcSend(t, e.router, "POST", "/api/v1/authentication/cas/complete", "{}", pending).Code)
	cfg = e.cas.Snapshot()
	cfg.Enabled = false
	_, err = e.cas.Save(cfg, "admin", "admin")
	require.NoError(t, err)
	assert.Equal(t, 401, oidcSend(t, e.router, "GET", "/api/v1/users/me", "", session).Code)
}
func TestCASMandatoryMFAAndCancellationStayBrowserBound(t *testing.T) {
	e := casEnv(t)
	prepared := doJSONRequest(t, e.router, "POST", "/api/v1/settings/security/cas/users", `{"subject":"admin","username":"cas.operator"}`, e.adminToken, "127.0.0.1:1234")
	require.Equal(t, 201, prepared.Code)
	_, err := e.auth.SetMFAEnforcement(coreauth.MFAEnforcementAll)
	require.NoError(t, err)
	pending := cookieNamed(t, casCallback(t, e), casPendingCookie)
	setupResponse := oidcSend(t, e.router, "POST", "/api/v1/authentication/cas/complete", "{}", pending)
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
	assert.Equal(t, 401, oidcSend(t, e.router, "POST", "/api/v1/authentication/cas/complete", string(body)).Code)
	assert.Equal(t, 401, oidcSend(t, e.router, "POST", "/api/v1/authentication/cas/complete", `{"setup_token":"foreign","otp":"000000"}`, pending).Code)
	done := oidcSend(t, e.router, "POST", "/api/v1/authentication/cas/complete", string(body), pending)
	require.Equal(t, 200, done.Code, done.Body.String())
	assert.Contains(t, done.Body.String(), `"mfa_enabled":true`)
	session := cookieNamed(t, done, sessionCookieName)
	assert.Equal(t, 403, oidcSend(t, e.router, "POST", "/api/v1/users/me/password/change", `{"current_password":"any","new_password":"synthetic-new-password"}`, session).Code)
	next := cookieNamed(t, casCallback(t, e), casPendingCookie)
	assert.Equal(t, 204, oidcSend(t, e.router, "DELETE", "/api/v1/authentication/cas/pending", "", next).Code)
	assert.Equal(t, 401, oidcSend(t, e.router, "POST", "/api/v1/authentication/cas/complete", "{}", next).Code)
}
func TestCASSourceIsolationRateBudgetAndSecureCookies(t *testing.T) {
	e := casEnv(t)
	user, err := e.auth.EnsureExternalUser("cas", e.provider.BaseURL, "admin", "", true)
	require.NoError(t, err)
	enroll, err := e.auth.StartMFAEnrollment(user.ID)
	require.NoError(t, err)
	_, err = e.auth.ConfirmMFAEnrollment(user.ID, apiTOTPCode(t, enroll.Secret, uint64(time.Now().Unix()/30)))
	require.NoError(t, err)
	for i := 0; i < 6; i++ {
		pending := cookieNamed(t, casCallback(t, e), casPendingCookie)
		r := oidcSend(t, e.router, "POST", "/api/v1/authentication/cas/complete", `{"otp":"invalid"}`, pending)
		if i < 5 {
			assert.Equal(t, 401, r.Code)
		} else {
			assert.Equal(t, 429, r.Code)
		}
	}
	cfg := e.cas.Snapshot()
	cfg.CallbackURL = "https://console.example.invalid" + caslogin.CallbackPath
	next, err := caslogin.Open(filepath.Join(t.TempDir(), "cas.json"), make([]byte, 32), nil, "https://console.example.invalid", nil)
	require.NoError(t, err)
	cfg.Revision = 0
	_, err = next.Save(cfg, "admin", "admin")
	require.NoError(t, err)
	router := NewRouter("test", Dependencies{Auth: e.auth, CAS: next, PublicURL: "https://console.example.invalid"})
	start := oidcSend(t, router, "GET", "/api/v1/authentication/cas/start", "")
	require.Equal(t, 303, start.Code)
	assert.True(t, cookieNamed(t, start, casFlowCookie).Secure)
	r := httptest.NewRequest("POST", "/api/v1/authentication/cas/complete", strings.NewReader("{}"))
	r.Header.Set("Origin", "https://attacker.example.invalid")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	assert.Equal(t, 403, w.Code)
}
