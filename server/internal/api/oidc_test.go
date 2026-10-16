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

	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/oidclogin"
	fixture "github.com/neko233-com/jumpserver233/server/testsupport/oidcprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type oidcEnvironment struct {
	router     http.Handler
	auth       *coreauth.Service
	oidc       *oidclogin.Service
	provider   *fixture.Provider
	adminToken string
}

func oidcEnv(t *testing.T) *oidcEnvironment {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	issuer := "http://" + server.Listener.Addr().String()
	provider, err := fixture.New(issuer, fixture.Options{})
	require.NoError(t, err)
	server.Config.Handler = provider
	server.Start()
	t.Cleanup(server.Close)
	dir := t.TempDir()
	identities, err := coreauth.OpenServiceWithVaultKey(filepath.Join(dir, "users.json"), make([]byte, 32))
	require.NoError(t, err)
	_, err = identities.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, err)
	admin, err := identities.Authenticate("admin", bootstrapPassword)
	require.NoError(t, err)
	oidc, err := oidclogin.Open(filepath.Join(dir, "oidc.json"), make([]byte, 32), nil, "")
	require.NoError(t, err)
	_, err = oidc.Save(oidclogin.Input{Config: oidclogin.Config{Enabled: true, Issuer: issuer, ClientID: fixture.ClientID, RedirectURL: "http://127.0.0.1:5177/api/v1/authentication/oidc/callback", TokenAuthMethod: "client_secret_basic", AllowLoopbackHTTP: true}, ClientSecret: fixture.ClientSecret}, "admin", "admin")
	require.NoError(t, err)
	router := NewRouter("test", Dependencies{Auth: identities, OIDC: oidc, Assets: testAssetService(t)})
	return &oidcEnvironment{router: router, auth: identities, oidc: oidc, provider: provider, adminToken: admin.AccessToken}
}
func oidcSend(t *testing.T, h http.Handler, method, path, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:43210"
	r.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func cookieNamed(t *testing.T, w *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == name && c.Value != "" {
			return c
		}
	}
	t.Fatalf("missing %s cookie", name)
	return nil
}
func oidcCallback(t *testing.T, e *oidcEnvironment) *httptest.ResponseRecorder {
	t.Helper()
	start := oidcSend(t, e.router, "GET", "/api/v1/authentication/oidc/start", "")
	require.Equal(t, 303, start.Code, start.Body.String())
	authURL, err := url.Parse(start.Header().Get("Location"))
	require.NoError(t, err)
	code, err := e.provider.Issue(authURL.Query())
	require.NoError(t, err)
	query := url.Values{"state": {authURL.Query().Get("state")}, "code": {code}}
	callback := oidcSend(t, e.router, "GET", "/api/v1/authentication/oidc/callback?"+query.Encode(), "", cookieNamed(t, start, oidcFlowCookie))
	require.Equal(t, 303, callback.Code)
	assert.Equal(t, "no-referrer", callback.Header().Get("Referrer-Policy"))
	assert.NotContains(t, callback.Header().Get("Location"), "code=")
	return callback
}
func TestOIDCBrowserCookieProvisioningIsControlledAndNeverLinksAdmin(t *testing.T) {
	e := oidcEnv(t)
	denied := oidcCallback(t, e)
	assert.Contains(t, denied.Header().Get("Location"), "sso_error=1")
	assert.Len(t, e.auth.ListUsers(), 1)
	cfg := e.oidc.Snapshot().Config
	cfg.ProvisionNew = true
	_, err := e.oidc.Save(oidclogin.Input{Config: cfg}, "admin", "admin")
	require.NoError(t, err)
	callback := oidcCallback(t, e)
	assert.Contains(t, callback.Header().Get("Location"), "sso=continue")
	pending := cookieNamed(t, callback, oidcPendingCookie)
	assert.True(t, pending.HttpOnly)
	assert.Equal(t, oidcCookiePath, pending.Path)
	noSession := oidcSend(t, e.router, "GET", "/api/v1/users/me", "", pending)
	assert.Equal(t, 401, noSession.Code)
	complete := oidcSend(t, e.router, "POST", "/api/v1/authentication/oidc/complete", "{}", pending)
	require.Equal(t, 200, complete.Code, complete.Body.String())
	assert.Contains(t, complete.Body.String(), `"browser_session":true`)
	assert.NotContains(t, complete.Body.String(), "access_token")
	assert.NotContains(t, complete.Body.String(), "id_token")
	assert.NotContains(t, complete.Body.String(), fixture.ClientSecret)
	session := cookieNamed(t, complete, sessionCookieName)
	assert.True(t, session.HttpOnly)
	assert.Equal(t, "/", session.Path)
	assert.Equal(t, http.SameSiteLaxMode, session.SameSite)
	me := oidcSend(t, e.router, "GET", "/api/v1/users/me", "", session)
	require.Equal(t, 200, me.Code)
	var user coreauth.User
	require.NoError(t, json.Unmarshal(me.Body.Bytes(), &user))
	assert.Equal(t, "oidc", user.Source)
	assert.Equal(t, coreauth.RoleOperator, user.Role)
	assert.NotEqual(t, "admin", user.Username)
	assert.Equal(t, 403, oidcSend(t, e.router, "GET", "/api/v1/settings/security/oidc", "", session).Code)
	assert.Equal(t, 401, oidcSend(t, e.router, "POST", "/api/v1/authentication/oidc/complete", "{}", pending).Code)
	cfg = e.oidc.Snapshot().Config
	cfg.Enabled = false
	_, err = e.oidc.Save(oidclogin.Input{Config: cfg}, "admin", "admin")
	require.NoError(t, err)
	assert.Equal(t, 401, oidcSend(t, e.router, "GET", "/api/v1/users/me", "", session).Code)
}
func TestOIDCCompletesMandatoryLocalMFAWithoutBypass(t *testing.T) {
	e := oidcEnv(t)
	user, err := e.auth.EnsureOIDCUser(e.provider.Issuer, fixture.Subject, "sso.operator", true)
	require.NoError(t, err)
	_, err = e.auth.SetMFAEnforcement(coreauth.MFAEnforcementAll)
	require.NoError(t, err)
	callback := oidcCallback(t, e)
	pending := cookieNamed(t, callback, oidcPendingCookie)
	response := oidcSend(t, e.router, "POST", "/api/v1/authentication/oidc/complete", "{}", pending)
	require.Equal(t, 401, response.Code, response.Body.String())
	var setup struct {
		Token      string                 `json:"setup_token"`
		Enrollment coreauth.MFAEnrollment `json:"enrollment"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &setup))
	assert.NotEmpty(t, setup.Token)
	assert.Equal(t, 401, oidcSend(t, e.router, "GET", "/api/v1/users/me", "", pending).Code)
	bad := oidcSend(t, e.router, "POST", "/api/v1/authentication/oidc/complete", `{"setup_token":"not-this-flow","otp":"000000"}`, pending)
	assert.Equal(t, 401, bad.Code)
	code := apiTOTPCode(t, setup.Enrollment.Secret, uint64(time.Now().Unix()/30))
	body, err := json.Marshal(map[string]string{"setup_token": setup.Token, "otp": code})
	require.NoError(t, err)
	generic := oidcSend(t, e.router, "POST", "/api/v1/authentication/mfa/setup/confirm", string(body), pending)
	assert.Equal(t, 401, generic.Code, "external setup must remain bound to the OIDC pending flow")
	finished := oidcSend(t, e.router, "POST", "/api/v1/authentication/oidc/complete", string(body), pending)
	require.Equal(t, 200, finished.Code, finished.Body.String())
	session := cookieNamed(t, finished, sessionCookieName)
	current, ok := e.auth.UserByID(user.ID)
	require.True(t, ok)
	assert.True(t, current.MFAEnabled)
	change := oidcSend(t, e.router, "POST", "/api/v1/users/me/password/change", `{"current_password":"anything","new_password":"synthetic-new-password"}`, session)
	assert.Equal(t, 403, change.Code)
	assert.Contains(t, change.Body.String(), "identity provider")
}
func TestOIDCSettingsSecretRedactionAndHTTPSOriginPolicy(t *testing.T) {
	e := oidcEnv(t)
	snapshot := doJSONRequest(t, e.router, "GET", "/api/v1/settings/security/oidc", "", e.adminToken, "127.0.0.1:43210")
	require.Equal(t, 200, snapshot.Code)
	assert.Contains(t, snapshot.Body.String(), `"has_client_secret":true`)
	assert.NotContains(t, snapshot.Body.String(), fixture.ClientSecret)
	audit := doJSONRequest(t, e.router, "GET", "/api/v1/settings/security/oidc/audit", "", e.adminToken, "127.0.0.1:43210")
	assert.NotContains(t, audit.Body.String(), fixture.ClientSecret)
	assert.Contains(t, audit.Body.String(), `"actor":"admin"`)
	router := NewRouter("test", Dependencies{Auth: e.auth, PublicURL: "https://console.example.invalid"})
	r := httptest.NewRequest("POST", "/api/v1/authentication/auth/", strings.NewReader(`{"username":"admin","password":"`+bootstrapPassword+`"}`))
	r.RemoteAddr = "127.0.0.1:43210"
	r.Header.Set("Origin", "https://console.example.invalid")
	r.Header.Set(browserSessionHeader, "cookie")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	require.Equal(t, 200, w.Code, w.Body.String())
	assert.True(t, cookieNamed(t, w, sessionCookieName).Secure)
	r = httptest.NewRequest("POST", "/api/v1/authentication/auth/", strings.NewReader(`{"username":"admin","password":"`+bootstrapPassword+`"}`))
	r.RemoteAddr = "127.0.0.1:43210"
	r.Header.Set("Origin", "https://attacker.example.invalid")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, r)
	assert.Equal(t, 403, w.Code)
}

func TestOIDCSecondFactorBudgetSurvivesNewBrowserFlows(t *testing.T) {
	e := oidcEnv(t)
	user, err := e.auth.EnsureOIDCUser(e.provider.Issuer, fixture.Subject, "sso.operator", true)
	require.NoError(t, err)
	enrollment, err := e.auth.StartMFAEnrollment(user.ID)
	require.NoError(t, err)
	_, err = e.auth.ConfirmMFAEnrollment(user.ID, apiTOTPCode(t, enrollment.Secret, uint64(time.Now().Unix()/30)))
	require.NoError(t, err)
	for i := 0; i < 6; i++ {
		ticket, err := e.oidc.NewPending(user.ID, e.oidc.Snapshot().Revision)
		require.NoError(t, err)
		w := oidcSend(t, e.router, "POST", "/api/v1/authentication/oidc/complete", `{"otp":"NOT-OTP"}`, &http.Cookie{Name: oidcPendingCookie, Value: ticket})
		if i < 5 {
			assert.Equal(t, 401, w.Code, w.Body.String())
		} else {
			assert.Equal(t, 429, w.Code, w.Body.String())
			assert.NotEmpty(t, w.Header().Get("Retry-After"))
		}
	}
}
