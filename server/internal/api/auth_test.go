package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const bootstrapPassword = "an-initial-admin-password-123"

func TestLoginCookieSupportsSessionAndLogout(t *testing.T) {
	identities, err := coreauth.OpenService(filepath.Join(t.TempDir(), "users.json"))
	require.NoError(t, err)
	_, err = identities.Bootstrap("admin.user", bootstrapPassword)
	require.NoError(t, err)
	router := NewRouter("test", Dependencies{Auth: identities})

	unauthenticatedSessionRequest := httptest.NewRequest(http.MethodGet, "/api/v1/authentication/session/", nil)
	unauthenticatedSessionRequest.RemoteAddr = "127.0.0.1:43210"
	unauthenticatedSessionResponse := httptest.NewRecorder()
	router.ServeHTTP(unauthenticatedSessionResponse, unauthenticatedSessionRequest)
	assert.Equal(t, http.StatusUnauthorized, unauthenticatedSessionResponse.Code, "loopback management access is not a browser login session")

	loginRequest := httptest.NewRequest(http.MethodPost, "/api/v1/authentication/auth/", strings.NewReader(`{"username":"admin.user","password":"`+bootstrapPassword+`"}`))
	loginRequest.RemoteAddr = "127.0.0.1:43210"
	loginRequest.Header.Set("Content-Type", "application/json")
	loginResponse := httptest.NewRecorder()
	router.ServeHTTP(loginResponse, loginRequest)
	require.Equal(t, http.StatusOK, loginResponse.Code, loginResponse.Body.String())
	cookie := loginResponse.Result().Cookies()
	require.Len(t, cookie, 1)
	assert.Equal(t, sessionCookieName, cookie[0].Name)
	assert.Equal(t, "/", cookie[0].Path)
	assert.True(t, cookie[0].HttpOnly)
	assert.False(t, cookie[0].Secure, "loopback HTTP should not emit a Secure cookie")
	assert.Equal(t, http.SameSiteLaxMode, cookie[0].SameSite)
	assert.Greater(t, cookie[0].MaxAge, 0)
	assert.Equal(t, "private, no-store", loginResponse.Header().Get("Cache-Control"))

	browserLoginRequest := httptest.NewRequest(http.MethodPost, "/api/v1/authentication/auth/", strings.NewReader(`{"username":"admin.user","password":"`+bootstrapPassword+`"}`))
	browserLoginRequest.RemoteAddr = "127.0.0.1:43210"
	browserLoginRequest.Header.Set("Content-Type", "application/json")
	browserLoginRequest.Header.Set(browserSessionHeader, "cookie")
	browserLoginResponse := httptest.NewRecorder()
	router.ServeHTTP(browserLoginResponse, browserLoginRequest)
	require.Equal(t, http.StatusOK, browserLoginResponse.Code, browserLoginResponse.Body.String())
	assert.Contains(t, browserLoginResponse.Body.String(), `"browser_session":true`)
	assert.NotContains(t, browserLoginResponse.Body.String(), `"access_token"`, "browser scripts should receive the HttpOnly cookie, not the session secret")
	browserCookie := browserLoginResponse.Result().Cookies()
	require.Len(t, browserCookie, 1)
	assert.True(t, browserCookie[0].HttpOnly)

	secureRequest := httptest.NewRequest(http.MethodPost, "https://localhost/api/v1/authentication/auth/", nil)
	secureRequest.TLS = &tls.ConnectionState{}
	secureResponse := httptest.NewRecorder()
	setLoginSession(secureResponse, secureRequest, coreauth.LoginSession{AccessToken: cookie[0].Value, ExpiresAt: cookie[0].Expires})
	secureCookies := secureResponse.Result().Cookies()
	require.Len(t, secureCookies, 1)
	assert.True(t, secureCookies[0].Secure)

	sessionRequest := httptest.NewRequest(http.MethodGet, "/api/v1/authentication/session/", nil)
	sessionRequest.RemoteAddr = "127.0.0.1:43210"
	sessionRequest.AddCookie(cookie[0])
	sessionResponse := httptest.NewRecorder()
	router.ServeHTTP(sessionResponse, sessionRequest)
	require.Equal(t, http.StatusOK, sessionResponse.Code, sessionResponse.Body.String())
	assert.Contains(t, sessionResponse.Body.String(), `"username":"admin.user"`)

	logoutRequest := httptest.NewRequest(http.MethodPost, "/api/v1/authentication/expire-session/", nil)
	logoutRequest.RemoteAddr = "127.0.0.1:43210"
	logoutRequest.AddCookie(cookie[0])
	logoutResponse := httptest.NewRecorder()
	router.ServeHTTP(logoutResponse, logoutRequest)
	require.Equal(t, http.StatusNoContent, logoutResponse.Code)
	assert.Equal(t, "private, no-store", logoutResponse.Header().Get("Cache-Control"))
	expired := logoutResponse.Result().Cookies()
	require.Len(t, expired, 1)
	assert.Equal(t, sessionCookieName, expired[0].Name)
	assert.Less(t, expired[0].MaxAge, 0)

	requestAfterLogout := httptest.NewRequest(http.MethodGet, "/api/v1/authentication/session/", nil)
	requestAfterLogout.RemoteAddr = "127.0.0.1:43210"
	requestAfterLogout.AddCookie(cookie[0])
	responseAfterLogout := httptest.NewRecorder()
	router.ServeHTTP(responseAfterLogout, requestAfterLogout)
	assert.Equal(t, http.StatusUnauthorized, responseAfterLogout.Code)
}

func TestPermanentTokenAuthorizationHeaderLifecycle(t *testing.T) {
	identities, err := coreauth.OpenService(filepath.Join(t.TempDir(), "users.json"))
	require.NoError(t, err)
	admin, err := identities.Bootstrap("admin.user", bootstrapPassword)
	require.NoError(t, err)
	session, err := identities.Authenticate("admin.user", bootstrapPassword)
	require.NoError(t, err)
	router := NewRouter("test", Dependencies{Auth: identities})

	created := doJSONRequest(t, router, http.MethodPost, "/api/v1/users/me/tokens", `{}`, session.AccessToken, "127.0.0.1:43210")
	require.Equal(t, http.StatusCreated, created.Code, created.Body.String())
	var credentials coreauth.PermanentTokenCredentials
	require.NoError(t, json.NewDecoder(created.Body).Decode(&credentials))
	require.NotEmpty(t, credentials.Token)
	require.NotEmpty(t, credentials.ID)

	identityRequest := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	identityRequest.RemoteAddr = "127.0.0.1:43210"
	identityRequest.Header.Set("Authorization", "Token "+credentials.Token)
	identityResponse := httptest.NewRecorder()
	router.ServeHTTP(identityResponse, identityRequest)
	require.Equal(t, http.StatusOK, identityResponse.Code, identityResponse.Body.String())
	assert.Contains(t, identityResponse.Body.String(), `"id":"`+admin.ID+`"`)

	wrongScheme := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	wrongScheme.RemoteAddr = "127.0.0.1:43210"
	wrongScheme.Header.Set("Authorization", "Bearer "+credentials.Token)
	wrongSchemeResponse := httptest.NewRecorder()
	router.ServeHTTP(wrongSchemeResponse, wrongScheme)
	assert.Equal(t, http.StatusUnauthorized, wrongSchemeResponse.Code, "permanent tokens use the Token scheme only")

	listed := doJSONRequest(t, router, http.MethodGet, "/api/v1/users/me/tokens", "", session.AccessToken, "127.0.0.1:43210")
	require.Equal(t, http.StatusOK, listed.Code, listed.Body.String())
	assert.NotContains(t, listed.Body.String(), credentials.Token)

	revoked := doJSONRequest(t, router, http.MethodDelete, "/api/v1/users/me/tokens/"+credentials.ID, "", session.AccessToken, "127.0.0.1:43210")
	require.Equal(t, http.StatusNoContent, revoked.Code)
	identityRequest = httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	identityRequest.RemoteAddr = "127.0.0.1:43210"
	identityRequest.Header.Set("Authorization", "Token "+credentials.Token)
	identityResponse = httptest.NewRecorder()
	router.ServeHTTP(identityResponse, identityRequest)
	assert.Equal(t, http.StatusUnauthorized, identityResponse.Code)
}

func TestBootstrapLoginAndRoleBoundary(t *testing.T) {
	identities, err := coreauth.OpenService(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter("test", Dependencies{Assets: testAssetService(t), Auth: identities})

	status := httptest.NewRecorder()
	statusRequest := httptest.NewRequest(http.MethodGet, "/api/v1/authentication/status", nil)
	statusRequest.RemoteAddr = "127.0.0.1:43210"
	router.ServeHTTP(status, statusRequest)
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"bootstrap_required":true`) {
		t.Fatalf("status response = %d %s", status.Code, status.Body.String())
	}

	bootstrap := doJSONRequest(t, router, http.MethodPost, "/api/v1/authentication/bootstrap", `{"username":"admin.user","password":"`+bootstrapPassword+`"}`, "", "127.0.0.1:43210")
	if bootstrap.Code != http.StatusCreated {
		t.Fatalf("bootstrap status = %d, body = %s", bootstrap.Code, bootstrap.Body.String())
	}
	var adminSession coreauth.LoginSession
	if err := json.NewDecoder(bootstrap.Body).Decode(&adminSession); err != nil {
		t.Fatal(err)
	}
	if adminSession.User.Role != coreauth.RoleAdmin || adminSession.AccessToken == "" || strings.Contains(bootstrap.Body.String(), bootstrapPassword) {
		t.Fatalf("bootstrap session = %+v", adminSession)
	}
	if got := bootstrap.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("bootstrap cache control = %q", got)
	}

	me := doJSONRequest(t, router, http.MethodGet, "/api/v1/users/me", "", adminSession.AccessToken, "127.0.0.1:43210")
	if me.Code != http.StatusOK || !strings.Contains(me.Body.String(), `"username":"admin.user"`) {
		t.Fatalf("admin identity response = %d %s", me.Code, me.Body.String())
	}
	assets := doJSONRequest(t, router, http.MethodGet, "/api/v1/assets", "", adminSession.AccessToken, "127.0.0.1:43210")
	if assets.Code != http.StatusOK {
		t.Fatalf("admin asset access status = %d, body = %s", assets.Code, assets.Body.String())
	}

	created := doJSONRequest(t, router, http.MethodPost, "/api/v1/users", `{"username":"operator.one","password":"an-operator-password-1234","role":"operator"}`, adminSession.AccessToken, "127.0.0.1:43210")
	if created.Code != http.StatusCreated || strings.Contains(created.Body.String(), "an-operator-password-1234") {
		t.Fatalf("create operator = %d %s", created.Code, created.Body.String())
	}
	operatorLogin := doJSONRequest(t, router, http.MethodPost, "/api/v1/authentication/auth/", `{"username":"operator.one","password":"an-operator-password-1234"}`, "", "127.0.0.1:43210")
	if operatorLogin.Code != http.StatusOK {
		t.Fatalf("operator login = %d %s", operatorLogin.Code, operatorLogin.Body.String())
	}
	var operatorSession coreauth.LoginSession
	if err := json.NewDecoder(operatorLogin.Body).Decode(&operatorSession); err != nil {
		t.Fatal(err)
	}
	denied := doJSONRequest(t, router, http.MethodGet, "/api/v1/assets", "", operatorSession.AccessToken, "127.0.0.1:43210")
	if denied.Code != http.StatusOK || strings.TrimSpace(denied.Body.String()) != "[]" {
		t.Fatalf("operator asset access = %d %s, want an empty authorized inventory", denied.Code, denied.Body.String())
	}

	secondBootstrap := doJSONRequest(t, router, http.MethodPost, "/api/v1/authentication/bootstrap", `{"username":"another.admin","password":"an-another-admin-password"}`, "", "127.0.0.1:43210")
	if secondBootstrap.Code != http.StatusConflict {
		t.Fatalf("second bootstrap status = %d, want conflict", secondBootstrap.Code)
	}
	revoked := doJSONRequest(t, router, http.MethodPost, "/api/v1/authentication/expire-session/", "", adminSession.AccessToken, "127.0.0.1:43210")
	if revoked.Code != http.StatusNoContent {
		t.Fatalf("expire session status = %d, want 204", revoked.Code)
	}
	afterRevoke := doJSONRequest(t, router, http.MethodGet, "/api/v1/users/me", "", adminSession.AccessToken, "127.0.0.1:43210")
	if afterRevoke.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token identity status = %d, want 401", afterRevoke.Code)
	}
}

func TestPasswordChangeRequiresCurrentPasswordAndKeepsOnlyCurrentSession(t *testing.T) {
	identities, err := coreauth.OpenService(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	const newPassword = "a-new-admin-password-with-24"
	admin, err := identities.Bootstrap("admin.user", bootstrapPassword)
	if err != nil {
		t.Fatal(err)
	}
	currentSession, err := identities.Authenticate("admin.user", bootstrapPassword)
	if err != nil {
		t.Fatal(err)
	}
	otherSession, err := identities.Authenticate("admin.user", bootstrapPassword)
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter("test", Dependencies{Assets: testAssetService(t), Auth: identities})

	unauthorized := doJSONRequest(t, router, http.MethodPost, "/api/v1/users/me/password/change", `{"current_password":"`+bootstrapPassword+`","new_password":"`+newPassword+`"}`, "", "192.0.2.51:43210")
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated password change = %d, want 401", unauthorized.Code)
	}
	wrongCurrent := doJSONRequest(t, router, http.MethodPost, "/api/v1/users/me/password/change", `{"current_password":"incorrect-current-password","new_password":"`+newPassword+`"}`, currentSession.AccessToken, "127.0.0.1:43210")
	if wrongCurrent.Code != http.StatusForbidden {
		t.Fatalf("wrong current password status = %d, want 403", wrongCurrent.Code)
	}
	unchanged := doJSONRequest(t, router, http.MethodPost, "/api/v1/users/me/password/change", `{"current_password":"`+bootstrapPassword+`","new_password":"`+bootstrapPassword+`"}`, currentSession.AccessToken, "127.0.0.1:43210")
	if unchanged.Code != http.StatusBadRequest {
		t.Fatalf("unchanged password status = %d, want 400", unchanged.Code)
	}
	tooShort := doJSONRequest(t, router, http.MethodPost, "/api/v1/users/me/password/change", `{"current_password":"`+bootstrapPassword+`","new_password":"short"}`, currentSession.AccessToken, "127.0.0.1:43210")
	if tooShort.Code != http.StatusBadRequest {
		t.Fatalf("short new password status = %d, want 400", tooShort.Code)
	}

	changed := doJSONRequest(t, router, http.MethodPost, "/api/v1/users/me/password/change", `{"current_password":"`+bootstrapPassword+`","new_password":"`+newPassword+`"}`, currentSession.AccessToken, "127.0.0.1:43210")
	if changed.Code != http.StatusNoContent || changed.Header().Get("Cache-Control") != "private, no-store" || changed.Body.Len() != 0 {
		t.Fatalf("password change = %d %s cache=%q, want empty 204 no-store", changed.Code, changed.Body.String(), changed.Header().Get("Cache-Control"))
	}
	currentIdentity := doJSONRequest(t, router, http.MethodGet, "/api/v1/users/me", "", currentSession.AccessToken, "127.0.0.1:43210")
	if currentIdentity.Code != http.StatusOK || !strings.Contains(currentIdentity.Body.String(), `"id":"`+admin.ID+`"`) {
		t.Fatalf("current session after password change = %d %s, want retained identity", currentIdentity.Code, currentIdentity.Body.String())
	}
	otherIdentity := doJSONRequest(t, router, http.MethodGet, "/api/v1/users/me", "", otherSession.AccessToken, "127.0.0.1:43210")
	if otherIdentity.Code != http.StatusUnauthorized {
		t.Fatalf("other session after password change = %d, want 401", otherIdentity.Code)
	}
	newLogin := doJSONRequest(t, router, http.MethodPost, "/api/v1/authentication/auth/", `{"username":"admin.user","password":"`+newPassword+`"}`, "", "127.0.0.1:43210")
	if newLogin.Code != http.StatusOK || strings.Contains(newLogin.Body.String(), newPassword) {
		t.Fatalf("new password sign-in = %d %s", newLogin.Code, newLogin.Body.String())
	}
}

func TestAccessKeySignatureAuthenticationAndOneTimeSecret(t *testing.T) {
	identities, err := coreauth.OpenServiceWithVaultKey(filepath.Join(t.TempDir(), "users.json"), []byte(strings.Repeat("v", 32)))
	if err != nil {
		t.Fatal(err)
	}
	admin, err := identities.Bootstrap("admin.user", bootstrapPassword)
	if err != nil {
		t.Fatal(err)
	}
	adminSession, err := identities.Authenticate("admin.user", bootstrapPassword)
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter("test", Dependencies{Auth: identities})

	created := doJSONRequest(t, router, http.MethodPost, "/api/v1/users/me/access-keys", `{}`, adminSession.AccessToken, "127.0.0.1:43210")
	if created.Code != http.StatusCreated || created.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("create AccessKey = %d %s cache=%q", created.Code, created.Body.String(), created.Header().Get("Cache-Control"))
	}
	var credentials coreauth.AccessKeyCredentials
	if err := json.NewDecoder(created.Body).Decode(&credentials); err != nil {
		t.Fatal(err)
	}
	if credentials.ID == "" || credentials.Secret == "" || strings.Contains(credentials.ID, credentials.Secret) {
		t.Fatalf("AccessKey creation response is incomplete: %+v", credentials)
	}

	profile := signedAccessKeyRequest(t, router, http.MethodGet, "/api/v1/users/me?scope=profile", credentials.ID, credentials.Secret, time.Now(), "(request-target) accept date")
	if profile.Code != http.StatusOK || !strings.Contains(profile.Body.String(), `"username":"admin.user"`) {
		t.Fatalf("signed profile request = %d %s", profile.Code, profile.Body.String())
	}
	legacyProfile := signedAccessKeyRequest(t, router, http.MethodGet, "/api/v1/users/me", credentials.ID, credentials.Secret, time.Now(), "(request-target) date")
	if legacyProfile.Code != http.StatusOK {
		t.Fatalf("legacy date-only signature = %d %s", legacyProfile.Code, legacyProfile.Body.String())
	}
	invalid := signedAccessKeyRequest(t, router, http.MethodGet, "/api/v1/users/me", credentials.ID, "invalid-secret", time.Now(), "(request-target) date")
	if invalid.Code != http.StatusUnauthorized {
		t.Fatalf("invalid AccessKey signature = %d, want 401", invalid.Code)
	}
	stale := signedAccessKeyRequest(t, router, http.MethodGet, "/api/v1/users/me", credentials.ID, credentials.Secret, time.Now().Add(-10*time.Minute), "(request-target) date")
	if stale.Code != http.StatusUnauthorized {
		t.Fatalf("stale AccessKey signature = %d, want 401", stale.Code)
	}

	listed := doJSONRequest(t, router, http.MethodGet, "/api/v1/users/me/access-keys", "", adminSession.AccessToken, "127.0.0.1:43210")
	if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), credentials.Secret) || !strings.Contains(listed.Body.String(), credentials.ID) {
		t.Fatalf("AccessKey list = %d %s", listed.Code, listed.Body.String())
	}
	revoked := doJSONRequest(t, router, http.MethodDelete, "/api/v1/users/me/access-keys/"+credentials.ID, "", adminSession.AccessToken, "127.0.0.1:43210")
	if revoked.Code != http.StatusNoContent {
		t.Fatalf("revoke AccessKey = %d %s", revoked.Code, revoked.Body.String())
	}
	afterRevoke := signedAccessKeyRequest(t, router, http.MethodGet, "/api/v1/users/me", credentials.ID, credentials.Secret, time.Now(), "(request-target) date")
	if afterRevoke.Code != http.StatusUnauthorized {
		t.Fatalf("revoked AccessKey = %d, want 401", afterRevoke.Code)
	}
	if _, ok := identities.UserByID(admin.ID); !ok {
		t.Fatal("admin identity disappeared after AccessKey revocation")
	}
}

func TestRemoteBootstrapRequiresConfiguredAdminToken(t *testing.T) {
	identities, err := coreauth.OpenService(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	const adminToken = "0123456789abcdef0123456789abcdef"
	router := NewRouter("test", Dependencies{Auth: identities, AdminToken: adminToken})
	remote := doJSONRequest(t, router, http.MethodPost, "/api/v1/authentication/bootstrap", `{"username":"admin.user","password":"`+bootstrapPassword+`"}`, "", "192.0.2.40:43210")
	if remote.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized remote bootstrap = %d, want 401", remote.Code)
	}
	allowed := doJSONRequest(t, router, http.MethodPost, "/api/v1/authentication/bootstrap", `{"username":"admin.user","password":"`+bootstrapPassword+`"}`, adminToken, "192.0.2.40:43210")
	if allowed.Code != http.StatusCreated {
		t.Fatalf("authorized remote bootstrap = %d, body = %s", allowed.Code, allowed.Body.String())
	}
}

func TestLoginLimitsFailuresPerRemoteAddress(t *testing.T) {
	identities, err := coreauth.OpenService(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.Bootstrap("admin.user", bootstrapPassword); err != nil {
		t.Fatal(err)
	}
	router := NewRouter("test", Dependencies{Auth: identities})
	started := time.Now()
	for attempt := 0; attempt < loginFailureLimit; attempt++ {
		response := doJSONRequest(t, router, http.MethodPost, "/api/v1/authentication/auth/", `{"username":"admin.user","password":"incorrect-password"}`, "", "192.0.2.50:43210")
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("failed login %d status = %d, want 401", attempt+1, response.Code)
		}
	}
	blocked := doJSONRequest(t, router, http.MethodPost, "/api/v1/authentication/auth/", `{"username":"admin.user","password":"`+bootstrapPassword+`"}`, "", "192.0.2.50:43210")
	retryAfter, err := strconv.Atoi(blocked.Header().Get("Retry-After"))
	require.NoError(t, err)
	assert.Equal(t, http.StatusTooManyRequests, blocked.Code)
	assert.GreaterOrEqual(t, retryAfter, max(1, int(time.Until(started.Add(loginFailureWindow)).Seconds())))
	assert.LessOrEqual(t, retryAfter, int(loginFailureWindow.Seconds()))
	otherSource := doJSONRequest(t, router, http.MethodPost, "/api/v1/authentication/auth/", `{"username":"admin.user","password":"`+bootstrapPassword+`"}`, "", "192.0.2.51:43210")
	assert.Equal(t, http.StatusOK, otherSource.Code, "a different source must not inherit the failed source's limit")
}

func TestTOTPEnrollmentAndLoginChallenge(t *testing.T) {
	const password = "an-initial-admin-password-123"
	identities, err := coreauth.OpenServiceWithVaultKey(filepath.Join(t.TempDir(), "users.json"), []byte(strings.Repeat("m", 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.Bootstrap("admin.user", password); err != nil {
		t.Fatal(err)
	}
	adminSession, err := identities.Authenticate("admin.user", password)
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter("test", Dependencies{Auth: identities})

	started := doJSONRequest(t, router, http.MethodPost, "/api/v1/users/me/mfa/enrollment", "{}", adminSession.AccessToken, "127.0.0.1:43210")
	if started.Code != http.StatusOK || started.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("start enrollment = %d %s", started.Code, started.Body.String())
	}
	var enrollment coreauth.MFAEnrollment
	if err := json.NewDecoder(started.Body).Decode(&enrollment); err != nil {
		t.Fatal(err)
	}
	if enrollment.Secret == "" || !strings.HasPrefix(enrollment.ProvisioningURI, "otpauth://totp/") || enrollment.ExpiresAt.IsZero() {
		t.Fatalf("enrollment response = %+v", enrollment)
	}

	currentStep := uint64(time.Now().Unix() / 30)
	confirmed := doJSONRequest(t, router, http.MethodPost, "/api/v1/users/me/mfa/confirm", `{"otp":"`+apiTOTPCode(t, enrollment.Secret, currentStep)+`"}`, adminSession.AccessToken, "127.0.0.1:43210")
	if confirmed.Code != http.StatusOK || !strings.Contains(confirmed.Body.String(), `"mfa_enabled":true`) {
		t.Fatalf("confirm enrollment = %d %s", confirmed.Code, confirmed.Body.String())
	}
	me := doJSONRequest(t, router, http.MethodGet, "/api/v1/users/me", "", adminSession.AccessToken, "127.0.0.1:43210")
	if me.Code != http.StatusOK || !strings.Contains(me.Body.String(), `"mfa_enabled":true`) {
		t.Fatalf("current profile after enrollment = %d %s", me.Code, me.Body.String())
	}

	challenge := doJSONRequest(t, router, http.MethodPost, "/api/v1/authentication/auth/", `{"username":"admin.user","password":"`+password+`"}`, "", "127.0.0.1:43210")
	if challenge.Code != http.StatusUnauthorized || !strings.Contains(challenge.Body.String(), `"mfa_required":true`) || challenge.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("password-only MFA login = %d %s", challenge.Code, challenge.Body.String())
	}
	wrongOTP := doJSONRequest(t, router, http.MethodPost, "/api/v1/authentication/auth/", `{"username":"admin.user","password":"`+password+`","otp":"not-code"}`, "", "127.0.0.1:43210")
	if wrongOTP.Code != http.StatusUnauthorized || strings.Contains(wrongOTP.Body.String(), `"mfa_required":true`) {
		t.Fatalf("invalid OTP login = %d %s", wrongOTP.Code, wrongOTP.Body.String())
	}
	freshStep := uint64(time.Now().Unix()/30 + 1)
	validOTP := doJSONRequest(t, router, http.MethodPost, "/api/v1/authentication/auth/", fmt.Sprintf(`{"username":"admin.user","password":%q,"otp":%q}`, password, apiTOTPCode(t, enrollment.Secret, freshStep)), "", "127.0.0.1:43210")
	if validOTP.Code != http.StatusOK || !strings.Contains(validOTP.Body.String(), `"access_token"`) {
		t.Fatalf("password plus fresh OTP login = %d %s", validOTP.Code, validOTP.Body.String())
	}
}

func TestGlobalMFAPolicyAndRequiredEnrollmentLoginFlow(t *testing.T) {
	const password = "an-initial-admin-password-123"
	identities, err := coreauth.OpenServiceWithVaultKey(filepath.Join(t.TempDir(), "users.json"), []byte(strings.Repeat("g", 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.Bootstrap("admin.user", password); err != nil {
		t.Fatal(err)
	}
	adminSession, err := identities.Authenticate("admin.user", password)
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter("test", Dependencies{Auth: identities})
	remote := "127.0.0.1:43210"

	updated := doJSONRequest(t, router, http.MethodPut, "/api/v1/settings/security/mfa", `{"mode":"admins"}`, adminSession.AccessToken, remote)
	if updated.Code != http.StatusOK || updated.Body.String() != `{"mode":"admins"}`+"\n" {
		t.Fatalf("set global MFA policy = %d %s", updated.Code, updated.Body.String())
	}
	loaded := doJSONRequest(t, router, http.MethodGet, "/api/v1/settings/security/mfa", "", adminSession.AccessToken, remote)
	if loaded.Code != http.StatusOK || !strings.Contains(loaded.Body.String(), `"mode":"admins"`) {
		t.Fatalf("get global MFA policy = %d %s", loaded.Code, loaded.Body.String())
	}

	setupResponse := doJSONRequest(t, router, http.MethodPost, "/api/v1/authentication/auth/", `{"username":"admin.user","password":"`+password+`"}`, "", remote)
	if setupResponse.Code != http.StatusUnauthorized || setupResponse.Header().Get("Cache-Control") != "private, no-store" || !strings.Contains(setupResponse.Body.String(), `"mfa_setup_required":true`) || strings.Contains(setupResponse.Body.String(), `"access_token"`) {
		t.Fatalf("policy-enforced login setup = %d headers=%v body=%s", setupResponse.Code, setupResponse.Header(), setupResponse.Body.String())
	}
	var setup struct {
		SetupToken string                 `json:"setup_token"`
		Enrollment coreauth.MFAEnrollment `json:"enrollment"`
	}
	if err := json.NewDecoder(setupResponse.Body).Decode(&setup); err != nil {
		t.Fatal(err)
	}
	if setup.SetupToken == "" || setup.Enrollment.Secret == "" {
		t.Fatalf("setup response = %+v", setup)
	}
	step := uint64(time.Now().Unix() / 30)
	confirmed := doJSONRequest(t, router, http.MethodPost, "/api/v1/authentication/mfa/setup/confirm", fmt.Sprintf(`{"setup_token":%q,"otp":%q}`, setup.SetupToken, apiTOTPCode(t, setup.Enrollment.Secret, step)), "", remote)
	if confirmed.Code != http.StatusOK || confirmed.Header().Get("Cache-Control") != "private, no-store" || !strings.Contains(confirmed.Body.String(), `"access_token"`) {
		t.Fatalf("confirm required MFA setup = %d headers=%v body=%s", confirmed.Code, confirmed.Header(), confirmed.Body.String())
	}
	var login coreauth.LoginSession
	if err := json.NewDecoder(confirmed.Body).Decode(&login); err != nil {
		t.Fatal(err)
	}
	profile := doJSONRequest(t, router, http.MethodGet, "/api/v1/users/me", "", login.AccessToken, remote)
	if profile.Code != http.StatusOK || !strings.Contains(profile.Body.String(), `"mfa_enabled":true`) {
		t.Fatalf("profile after required setup = %d %s", profile.Code, profile.Body.String())
	}
	disabled := doJSONRequest(t, router, http.MethodPost, "/api/v1/users/me/mfa/disable", fmt.Sprintf(`{"password":%q,"otp":"000000"}`, password), login.AccessToken, remote)
	if disabled.Code != http.StatusConflict || !strings.Contains(disabled.Body.String(), "global MFA policy") {
		t.Fatalf("disable MFA under policy = %d %s", disabled.Code, disabled.Body.String())
	}
}

func TestGlobalMFAPolicyRequiresVaultKeyAndAdmin(t *testing.T) {
	const password = "an-initial-admin-password-123"
	identities, err := coreauth.OpenService(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.Bootstrap("admin.user", password); err != nil {
		t.Fatal(err)
	}
	adminSession, err := identities.Authenticate("admin.user", password)
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter("test", Dependencies{Auth: identities})
	response := doJSONRequest(t, router, http.MethodPut, "/api/v1/settings/security/mfa", `{"mode":"admins"}`, adminSession.AccessToken, "127.0.0.1:43210")
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "MFA encryption") {
		t.Fatalf("enable policy without Vault key = %d %s", response.Code, response.Body.String())
	}
	forbidden := doJSONRequest(t, router, http.MethodGet, "/api/v1/settings/security/mfa", "", "", "192.0.2.44:43210")
	if forbidden.Code != http.StatusUnauthorized {
		t.Fatalf("read MFA policy without authentication = %d, want 401", forbidden.Code)
	}
}

func TestMFARecoveryCodesArePrivateAndSingleUse(t *testing.T) {
	const password = "an-initial-admin-password-123"
	userPath := filepath.Join(t.TempDir(), "users.json")
	identities, err := coreauth.OpenServiceWithVaultKey(userPath, []byte(strings.Repeat("c", 32)))
	if err != nil {
		t.Fatal(err)
	}
	admin, err := identities.Bootstrap("admin.user", password)
	if err != nil {
		t.Fatal(err)
	}
	adminSession, err := identities.Authenticate("admin.user", password)
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter("test", Dependencies{Auth: identities})
	remote := "127.0.0.1:43210"

	started := doJSONRequest(t, router, http.MethodPost, "/api/v1/users/me/mfa/enrollment", "{}", adminSession.AccessToken, remote)
	if started.Code != http.StatusOK {
		t.Fatalf("start MFA enrollment = %d %s", started.Code, started.Body.String())
	}
	var enrollment coreauth.MFAEnrollment
	if err := json.NewDecoder(started.Body).Decode(&enrollment); err != nil {
		t.Fatal(err)
	}
	currentStep := uint64(time.Now().Unix() / 30)
	confirmed := doJSONRequest(t, router, http.MethodPost, "/api/v1/users/me/mfa/confirm", fmt.Sprintf(`{"otp":%q}`, apiTOTPCode(t, enrollment.Secret, currentStep)), adminSession.AccessToken, remote)
	if confirmed.Code != http.StatusOK {
		t.Fatalf("confirm MFA = %d %s", confirmed.Code, confirmed.Body.String())
	}
	unauthorized := doJSONRequest(t, router, http.MethodPost, "/api/v1/users/me/mfa/recovery-codes", `{"password":"`+password+`","otp":"000000"}`, "", "192.0.2.40:43210")
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated remote recovery-code generation = %d, want 401", unauthorized.Code)
	}

	nextStep := currentStep + 1
	generated := doJSONRequest(t, router, http.MethodPost, "/api/v1/users/me/mfa/recovery-codes", fmt.Sprintf(`{"password":%q,"otp":%q}`, password, apiTOTPCode(t, enrollment.Secret, nextStep)), adminSession.AccessToken, remote)
	if generated.Code != http.StatusOK || generated.Header().Get("Cache-Control") != "private, no-store" || generated.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("generate recovery codes = %d headers=%v body=%s", generated.Code, generated.Header(), generated.Body.String())
	}
	var recovery coreauth.MFARecoveryCodes
	if err := json.NewDecoder(generated.Body).Decode(&recovery); err != nil {
		t.Fatal(err)
	}
	if len(recovery.Codes) != 10 || recovery.GeneratedAt.IsZero() {
		t.Fatalf("recovery-code response = %d codes, generated at %v", len(recovery.Codes), recovery.GeneratedAt)
	}
	contents, err := os.ReadFile(userPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), recovery.Codes[0]) || strings.Contains(string(contents), strings.ReplaceAll(recovery.Codes[0], "-", "")) {
		t.Fatal("user store contains a plaintext recovery code")
	}
	profile := doJSONRequest(t, router, http.MethodGet, "/api/v1/users/me", "", adminSession.AccessToken, remote)
	if profile.Code != http.StatusOK || strings.Contains(profile.Body.String(), recovery.Codes[0]) || strings.Contains(profile.Body.String(), "recovery_code_hashes") {
		t.Fatalf("profile exposed recovery code data: %d %s", profile.Code, profile.Body.String())
	}

	firstLogin := doJSONRequest(t, router, http.MethodPost, "/api/v1/authentication/auth/", fmt.Sprintf(`{"username":"admin.user","password":%q,"otp":%q}`, password, recovery.Codes[0]), "", remote)
	if firstLogin.Code != http.StatusOK {
		t.Fatalf("recovery-code sign-in = %d %s", firstLogin.Code, firstLogin.Body.String())
	}
	reusedLogin := doJSONRequest(t, router, http.MethodPost, "/api/v1/authentication/auth/", fmt.Sprintf(`{"username":"admin.user","password":%q,"otp":%q}`, password, recovery.Codes[0]), "", remote)
	if reusedLogin.Code != http.StatusUnauthorized || strings.Contains(reusedLogin.Body.String(), `"mfa_required":true`) {
		t.Fatalf("reused recovery-code sign-in = %d %s, want 401", reusedLogin.Code, reusedLogin.Body.String())
	}
	if _, ok := identities.UserByID(admin.ID); !ok {
		t.Fatal("admin identity disappeared after recovery-code use")
	}
}

func TestAuthenticatedSessionRecordsOperatorIdentity(t *testing.T) {
	identities, err := coreauth.OpenService(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.Bootstrap("admin.user", bootstrapPassword); err != nil {
		t.Fatal(err)
	}
	session, err := identities.Authenticate("admin.user", bootstrapPassword)
	if err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	broker := gateway.NewBroker(dataDir, []byte("0123456789abcdef0123456789abcdef"), func(_ context.Context, assetID string, _, _ int) (gateway.AssetInfo, gateway.Terminal, error) {
		return gateway.AssetInfo{ID: assetID, Name: "test-host", Username: "root"}, sessionTestTerminal{}, nil
	})
	t.Cleanup(broker.CloseAll)
	router := NewRouter("test", Dependencies{Auth: identities, Sessions: broker})
	created := doJSONRequest(t, router, http.MethodPost, "/api/v1/sessions", `{"asset_id":"asset-01","cols":80,"rows":24}`, session.AccessToken, "127.0.0.1:43210")
	if created.Code != http.StatusCreated {
		t.Fatalf("create session = %d %s", created.Code, created.Body.String())
	}
	var createdSession gateway.CreatedSession
	if err := json.NewDecoder(created.Body).Decode(&createdSession); err != nil {
		t.Fatal(err)
	}
	if err := broker.Close(createdSession.SessionID); err != nil {
		t.Fatal(err)
	}
	audit, err := os.ReadFile(filepath.Join(dataDir, "sessions", "index.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), `"operator":"admin.user"`) || !strings.Contains(string(audit), `"operator_id":"`+session.User.ID+`"`) {
		t.Fatalf("session audit missing authenticated identity: %s", audit)
	}
}

func doJSONRequest(t *testing.T, handler http.Handler, method, path, body, bearer, remote string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.RemoteAddr = remote
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func signedAccessKeyRequest(t *testing.T, handler http.Handler, method, path, keyID, secret string, date time.Time, signedHeaders string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, nil)
	request.RemoteAddr = "192.0.2.30:43210"
	dateValue := date.UTC().Format(http.TimeFormat)
	request.Header.Set("Date", dateValue)
	request.Header.Set("Accept", "application/json")
	lines := []string{"(request-target): " + strings.ToLower(method) + " " + request.URL.RequestURI()}
	if strings.Contains(signedHeaders, "accept") {
		lines = append(lines, "accept: application/json")
	}
	lines = append(lines, "date: "+dateValue)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(strings.Join(lines, "\n")))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	request.Header.Set("Authorization", fmt.Sprintf(`Signature keyId=%q,algorithm="hmac-sha256",headers=%q,signature=%q`, keyID, signedHeaders, signature))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func apiTOTPCode(t *testing.T, secret string, step uint64) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], step)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := int(digest[len(digest)-1] & 0x0f)
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}
