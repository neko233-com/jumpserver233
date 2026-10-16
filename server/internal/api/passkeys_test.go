package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/passkeys"
	"github.com/neko233-com/jumpserver233/server/testsupport/passkeyauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type passkeyEnvironment struct {
	router http.Handler
	auth   *coreauth.Service
	keys   *passkeys.Service
	admin  coreauth.LoginSession
}

func passkeyEnv(t *testing.T) *passkeyEnvironment {
	t.Helper()
	root := t.TempDir()
	auth, e := coreauth.OpenServiceWithVaultKey(filepath.Join(root, "users.json"), make([]byte, 32))
	require.NoError(t, e)
	_, e = auth.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, e)
	admin, e := auth.Authenticate("admin", bootstrapPassword)
	require.NoError(t, e)
	keys, e := passkeys.Open(filepath.Join(root, "passkeys.json"), make([]byte, 32), nil, "https://console.example.invalid")
	require.NoError(t, e)
	_, e = keys.Save(passkeys.Config{Enabled: true}, admin.User.ID, admin.User.Username)
	require.NoError(t, e)
	return &passkeyEnvironment{router: NewRouter("test", Dependencies{Auth: auth, Passkeys: keys, Assets: testAssetService(t), PublicURL: "https://console.example.invalid"}), auth: auth, keys: keys, admin: admin}
}
func passkeySend(t *testing.T, h http.Handler, method, path string, body any, token string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	raw, e := json.Marshal(body)
	require.NoError(t, e)
	r := httptest.NewRequest(method, path, strings.NewReader(string(raw)))
	r.RemoteAddr = "127.0.0.1:4567"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://console.example.invalid")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func registerPasskey(t *testing.T, e *passkeyEnvironment, session coreauth.LoginSession) (passkeys.Metadata, *passkeyauth.Authenticator) {
	t.Helper()
	start := passkeySend(t, e.router, "POST", passkeyRegisterPath+"/registration/start", map[string]string{"name": "QA device", "password": bootstrapPassword}, session.AccessToken)
	require.Equal(t, 200, start.Code, start.Body.String())
	assert.NotContains(t, start.Body.String(), session.User.ID)
	var op any
	require.NoError(t, json.Unmarshal(start.Body.Bytes(), &op))
	a, err := passkeyauth.New("https://console.example.invalid", "console.example.invalid")
	require.NoError(t, err)
	raw, err := a.Registration(op, passkeyauth.Overrides{})
	require.NoError(t, err)
	registered := passkeySend(t, e.router, "POST", passkeyRegisterPath+"/registration/finish", map[string]any{"credential": raw}, session.AccessToken, cookieNamed(t, start, passkeyRegisterCookie))
	require.Equal(t, 201, registered.Code, registered.Body.String())
	assert.NotContains(t, registered.Body.String(), "publicKey")
	var key passkeys.Metadata
	require.NoError(t, json.Unmarshal(registered.Body.Bytes(), &key))
	return key, a
}
func pendingPasskey(t *testing.T, e *passkeyEnvironment, a *passkeyauth.Authenticator) *http.Cookie {
	t.Helper()
	start := passkeySend(t, e.router, "POST", passkeyCookiePath+"/start", nil, "")
	require.Equal(t, 200, start.Code, start.Body.String())
	var op any
	require.NoError(t, json.Unmarshal(start.Body.Bytes(), &op))
	raw, err := a.Assertion(op, passkeyauth.Overrides{})
	require.NoError(t, err)
	verify := passkeySend(t, e.router, "POST", passkeyCookiePath+"/verify", map[string]any{"credential": raw}, "", cookieNamed(t, start, passkeyLoginCookie))
	require.Equal(t, 200, verify.Code, verify.Body.String())
	assert.NotContains(t, verify.Body.String(), "access_token")
	cookie := cookieNamed(t, verify, passkeyPendingCookie)
	assert.True(t, cookie.HttpOnly)
	assert.True(t, cookie.Secure)
	assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
	assert.Equal(t, passkeyCookiePath, cookie.Path)
	return cookie
}
func TestPasskeyAPIRegistrationCookieCompletionAndPermanentRevocation(t *testing.T) {
	e := passkeyEnv(t)
	key, a := registerPasskey(t, e, e.admin)
	list := passkeySend(t, e.router, "GET", passkeyRegisterPath, nil, e.admin.AccessToken)
	require.Equal(t, 200, list.Code)
	assert.NotContains(t, list.Body.String(), "publicKey")
	assert.NotContains(t, list.Body.String(), "attestationObject")
	pending := pendingPasskey(t, e, a)
	assert.Equal(t, 401, passkeySend(t, e.router, "GET", "/api/v1/users/me", nil, "", pending).Code)
	assert.Equal(t, 401, passkeySend(t, e.router, "POST", passkeyCookiePath+"/complete", map[string]string{}, "").Code)
	done := passkeySend(t, e.router, "POST", passkeyCookiePath+"/complete", map[string]string{}, "", pending)
	require.Equal(t, 200, done.Code, done.Body.String())
	assert.NotContains(t, done.Body.String(), "access_token")
	session := cookieNamed(t, done, sessionCookieName)
	assert.Equal(t, 200, passkeySend(t, e.router, "GET", "/api/v1/users/me", nil, "", session).Code)
	// Fresh Passkey authentication does not replace local credential-management password proof.
	assert.Equal(t, 401, passkeySend(t, e.router, "POST", passkeyRegisterPath+"/registration/start", map[string]string{"name": "unproven"}, "", session).Code)
	assert.Equal(t, 401, passkeySend(t, e.router, "DELETE", passkeyRegisterPath+"/"+key.ID, map[string]string{}, "", session).Code)
	assert.Equal(t, 401, passkeySend(t, e.router, "POST", passkeyCookiePath+"/complete", map[string]string{}, "", pending).Code)
	// A disable/re-enable sequence must revoke without requiring a request while disabled.
	cfg := e.keys.Snapshot()
	cfg.Enabled = false
	cfg, err := e.keys.Save(cfg, "admin", "admin")
	require.NoError(t, err)
	cfg.Enabled = true
	_, err = e.keys.Save(cfg, "admin", "admin")
	require.NoError(t, err)
	assert.Equal(t, 401, passkeySend(t, e.router, "GET", "/api/v1/users/me", nil, "", session).Code)
	pending = pendingPasskey(t, e, a)
	done = passkeySend(t, e.router, "POST", passkeyCookiePath+"/complete", map[string]string{}, "", pending)
	require.Equal(t, 200, done.Code)
	session = cookieNamed(t, done, sessionCookieName)
	removed := passkeySend(t, e.router, "DELETE", passkeyRegisterPath+"/"+key.ID, map[string]string{"password": bootstrapPassword}, e.admin.AccessToken)
	require.Equal(t, 204, removed.Code, removed.Body.String())
	assert.Equal(t, 401, passkeySend(t, e.router, "GET", "/api/v1/users/me", nil, "", session).Code)
	assert.Equal(t, 200, passkeySend(t, e.router, "GET", "/api/v1/users/me", nil, e.admin.AccessToken).Code)
}
func TestPasskeyMFAPolicySetupAndCancellationStayBound(t *testing.T) {
	e := passkeyEnv(t)
	_, a := registerPasskey(t, e, e.admin)
	_, err := e.auth.SetMFAEnforcement(coreauth.MFAEnforcementAll)
	require.NoError(t, err)
	pending := pendingPasskey(t, e, a)
	setupResponse := passkeySend(t, e.router, "POST", passkeyCookiePath+"/complete", map[string]string{}, "", pending)
	require.Equal(t, 401, setupResponse.Code, setupResponse.Body.String())
	var setup struct {
		Token      string                 `json:"setup_token"`
		Enrollment coreauth.MFAEnrollment `json:"enrollment"`
	}
	require.NoError(t, json.Unmarshal(setupResponse.Body.Bytes(), &setup))
	require.NotEmpty(t, setup.Token)
	body := map[string]string{"setup_token": setup.Token, "otp": apiTOTPCode(t, setup.Enrollment.Secret, uint64(time.Now().Unix()/30))}
	assert.Equal(t, 401, passkeySend(t, e.router, "POST", "/api/v1/authentication/mfa/setup/confirm", body, "").Code)
	assert.Equal(t, 401, passkeySend(t, e.router, "POST", passkeyCookiePath+"/complete", body, "").Code)
	done := passkeySend(t, e.router, "POST", passkeyCookiePath+"/complete", body, "", pending)
	require.Equal(t, 200, done.Code, done.Body.String())
	assert.Contains(t, done.Body.String(), `"mfa_enabled":true`)
	next := pendingPasskey(t, e, a)
	assert.Equal(t, 204, passkeySend(t, e.router, "DELETE", passkeyCookiePath+"/pending", nil, "", next).Code)
	assert.Equal(t, 401, passkeySend(t, e.router, "POST", passkeyCookiePath+"/complete", map[string]string{}, "", next).Code)
}
func TestPasskeyAPIRejectsForeignBrowserOwnerAndOrigin(t *testing.T) {
	e := passkeyEnv(t)
	_, a := registerPasskey(t, e, e.admin)
	operator, err := e.auth.CreateUser("operator", bootstrapPassword, coreauth.RoleOperator)
	require.NoError(t, err)
	op, err := e.auth.Authenticate(operator.Username, bootstrapPassword)
	require.NoError(t, err)
	assert.Equal(t, 403, passkeySend(t, e.router, "GET", "/api/v1/settings/security/passkeys", nil, op.AccessToken).Code)
	assert.Equal(t, 401, passkeySend(t, e.router, "GET", passkeyRegisterPath, nil, "").Code)
	start := passkeySend(t, e.router, "POST", passkeyRegisterPath+"/registration/start", map[string]string{"name": "Another key", "password": bootstrapPassword}, e.admin.AccessToken)
	require.Equal(t, 200, start.Code)
	var options any
	require.NoError(t, json.Unmarshal(start.Body.Bytes(), &options))
	reg, err := a.Registration(options, passkeyauth.Overrides{})
	require.NoError(t, err)
	wrong := passkeySend(t, e.router, "POST", passkeyRegisterPath+"/registration/finish", map[string]any{"credential": reg}, op.AccessToken, cookieNamed(t, start, passkeyRegisterCookie))
	assert.Equal(t, 401, wrong.Code)
	r := httptest.NewRequest("POST", passkeyCookiePath+"/start", nil)
	r.Header.Set("Origin", "https://attacker.invalid")
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, r)
	assert.Equal(t, 403, w.Code)
	start = passkeySend(t, e.router, "POST", passkeyCookiePath+"/start", nil, "")
	require.Equal(t, 200, start.Code)
	require.NoError(t, json.Unmarshal(start.Body.Bytes(), &options))
	raw, err := a.Assertion(options, passkeyauth.Overrides{})
	require.NoError(t, err)
	assert.Equal(t, 401, passkeySend(t, e.router, "POST", passkeyCookiePath+"/verify", map[string]any{"credential": raw}, "").Code)
}

func TestPasskeyRemovedCredentialCannotResurrectAnUnvisitedSession(t *testing.T) {
	e := passkeyEnv(t)
	key, a := registerPasskey(t, e, e.admin)
	pending := pendingPasskey(t, e, a)
	done := passkeySend(t, e.router, "POST", passkeyCookiePath+"/complete", map[string]string{}, "", pending)
	require.Equal(t, 200, done.Code)
	oldSession := cookieNamed(t, done, sessionCookieName)
	require.Equal(t, 204, passkeySend(t, e.router, "DELETE", passkeyRegisterPath+"/"+key.ID, map[string]string{"password": bootstrapPassword}, e.admin.AccessToken).Code)
	start := passkeySend(t, e.router, "POST", passkeyRegisterPath+"/registration/start", map[string]string{"name": "Same authenticator again", "password": bootstrapPassword}, e.admin.AccessToken)
	require.Equal(t, 200, start.Code)
	var options any
	require.NoError(t, json.Unmarshal(start.Body.Bytes(), &options))
	raw, err := a.Registration(options, passkeyauth.Overrides{})
	require.NoError(t, err)
	registered := passkeySend(t, e.router, "POST", passkeyRegisterPath+"/registration/finish", map[string]any{"credential": raw}, e.admin.AccessToken, cookieNamed(t, start, passkeyRegisterCookie))
	require.Equal(t, 201, registered.Code, registered.Body.String())
	var added passkeys.Metadata
	require.NoError(t, json.Unmarshal(registered.Body.Bytes(), &added))
	assert.NotEqual(t, key.ID, added.ID)
	assert.Equal(t, 401, passkeySend(t, e.router, "GET", "/api/v1/users/me", nil, "", oldSession).Code)
}

func TestPasskeyRegistrationRejectsProofBeforePasswordChange(t *testing.T) {
	e := passkeyEnv(t)
	start := passkeySend(t, e.router, "POST", passkeyRegisterPath+"/registration/start", map[string]string{"name": "Stale proof", "password": bootstrapPassword}, e.admin.AccessToken)
	require.Equal(t, 200, start.Code)
	var options any
	require.NoError(t, json.Unmarshal(start.Body.Bytes(), &options))
	a, err := passkeyauth.New("https://console.example.invalid", "console.example.invalid")
	require.NoError(t, err)
	raw, err := a.Registration(options, passkeyauth.Overrides{})
	require.NoError(t, err)
	require.NoError(t, e.auth.ChangePassword(e.admin.User.ID, e.admin.AccessToken, bootstrapPassword, "synthetic-new-primary-password-456"))
	// The current platform session was retained; the primary proof still expires.
	require.Equal(t, 200, passkeySend(t, e.router, "GET", "/api/v1/users/me", nil, e.admin.AccessToken).Code)
	finish := passkeySend(t, e.router, "POST", passkeyRegisterPath+"/registration/finish", map[string]any{"credential": raw}, e.admin.AccessToken, cookieNamed(t, start, passkeyRegisterCookie))
	assert.Equal(t, 401, finish.Code)
	assert.Empty(t, e.keys.List(e.admin.User.ID))
}
