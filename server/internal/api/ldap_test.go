package api

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/ldapclient"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/ldaplogin"
	"github.com/neko233-com/jumpserver233/server/testsupport/ldapserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ldapEnvironment struct {
	router     http.Handler
	auth       *coreauth.Service
	ldap       *ldaplogin.Service
	adminToken string
	fixture    *ldapserver.Server
}

func ldapEnv(t *testing.T) *ldapEnvironment {
	t.Helper()
	dir, e := ldapserver.Start(ldapserver.Options{})
	require.NoError(t, e)
	t.Cleanup(dir.Close)
	root := t.TempDir()
	auth, e := coreauth.OpenServiceWithVaultKey(filepath.Join(root, "users.json"), make([]byte, 32))
	require.NoError(t, e)
	_, e = auth.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, e)
	admin, e := auth.Authenticate("admin", bootstrapPassword)
	require.NoError(t, e)
	service, e := ldaplogin.Open(filepath.Join(root, "ldap.json"), make([]byte, 32), nil, nil)
	require.NoError(t, e)
	_, e = service.Save(ldaplogin.Input{Config: ldaplogin.Config{Config: ldapclient.Config{URL: dir.URL, BaseDN: ldapserver.BaseDN, BindDN: ldapserver.BindDN, Filter: "(uid={username})", IdentityAttribute: "entryUUID", CAPEM: dir.CAPEM}, Enabled: true}, BindPassword: ldapserver.BindPassword}, "admin-id", "admin")
	require.NoError(t, e)
	return &ldapEnvironment{router: NewRouter("test", Dependencies{Auth: auth, LDAP: service, Assets: testAssetService(t)}), auth: auth, ldap: service, adminToken: admin.AccessToken, fixture: dir}
}
func ldapPrimary(t *testing.T, e *ldapEnvironment) *http.Cookie {
	t.Helper()
	r := oidcSend(t, e.router, "POST", "/api/v1/authentication/ldap/login", `{"username":"directory.user","password":"`+ldapserver.Password+`"}`)
	require.Equal(t, 401, r.Code, r.Body.String())
	return cookieNamed(t, r, ldapPendingCookie)
}
func TestLDAPControlledProvisioningCookieOnlyAndDisablement(t *testing.T) {
	e := ldapEnv(t)
	r := oidcSend(t, e.router, "POST", "/api/v1/authentication/ldap/login", `{"username":"directory.user","password":"`+ldapserver.Password+`"}`)
	assert.Equal(t, 401, r.Code)
	assert.Len(t, e.auth.ListUsers(), 1)
	prepared := doJSONRequest(t, e.router, "POST", "/api/v1/settings/security/ldap/users", `{"directory_username":"directory.user","username":"ldap.operator"}`, e.adminToken, "127.0.0.1:1234")
	require.Equal(t, 201, prepared.Code, prepared.Body.String())
	r = oidcSend(t, e.router, "POST", "/api/v1/authentication/ldap/login", `{"username":"directory.user","password":"`+ldapserver.Password+`"}`)
	require.Equal(t, 200, r.Code, r.Body.String())
	assert.NotContains(t, r.Body.String(), "access_token")
	assert.NotContains(t, r.Body.String(), ldapserver.Password)
	session := cookieNamed(t, r, sessionCookieName)
	assert.True(t, session.HttpOnly)
	assert.Equal(t, "/", session.Path)
	var payload struct {
		User coreauth.User `json:"user"`
	}
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &payload))
	assert.Equal(t, "ldap", payload.User.Source)
	assert.Equal(t, "operator", payload.User.Role)
	assert.Equal(t, "ldap.operator", payload.User.Username)
	assert.Equal(t, 403, oidcSend(t, e.router, "GET", "/api/v1/settings/security/ldap", "", session).Code)
	assert.Equal(t, "[]\n", oidcSend(t, e.router, "GET", "/api/v1/assets", "", session).Body.String())
	assert.Equal(t, 401, oidcSend(t, e.router, "POST", "/api/v1/authentication/auth/", `{"username":"ldap.operator","password":"`+ldapserver.Password+`"}`).Code)
	assert.Equal(t, 403, oidcSend(t, e.router, "POST", "/api/v1/users/me/password/change", `{"current_password":"anything","new_password":"synthetic-new-password"}`, session).Code)
	cfg := e.ldap.Snapshot().Config
	cfg.Enabled = false
	_, err := e.ldap.Save(ldaplogin.Input{Config: cfg}, "admin", "admin")
	require.NoError(t, err)
	assert.Equal(t, 401, oidcSend(t, e.router, "GET", "/api/v1/users/me", "", session).Code)
}
func TestLDAPMandatoryMFAIsBoundToPendingCookie(t *testing.T) {
	e := ldapEnv(t)
	cfg := e.ldap.Snapshot().Config
	cfg.ProvisionNew = true
	_, err := e.ldap.Save(ldaplogin.Input{Config: cfg}, "admin", "admin")
	require.NoError(t, err)
	_, err = e.auth.SetMFAEnforcement(coreauth.MFAEnforcementAll)
	require.NoError(t, err)
	r := oidcSend(t, e.router, "POST", "/api/v1/authentication/ldap/login", `{"username":"directory.user","password":"`+ldapserver.Password+`"}`)
	require.Equal(t, 401, r.Code, r.Body.String())
	pending := cookieNamed(t, r, ldapPendingCookie)
	assert.True(t, pending.HttpOnly)
	assert.Equal(t, ldapCookiePath, pending.Path)
	var setup struct {
		Token      string                 `json:"setup_token"`
		Enrollment coreauth.MFAEnrollment `json:"enrollment"`
	}
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &setup))
	require.NotEmpty(t, setup.Token)
	code := apiTOTPCode(t, setup.Enrollment.Secret, uint64(time.Now().Unix()/30))
	body, _ := json.Marshal(map[string]string{"setup_token": setup.Token, "otp": code})
	assert.Equal(t, 401, oidcSend(t, e.router, "POST", "/api/v1/authentication/mfa/setup/confirm", string(body)).Code)
	assert.Equal(t, 401, oidcSend(t, e.router, "POST", "/api/v1/authentication/ldap/complete", string(body)).Code)
	assert.Equal(t, 401, oidcSend(t, e.router, "POST", "/api/v1/authentication/ldap/complete", `{"setup_token":"other-flow","otp":"000000"}`, pending).Code)
	completed := oidcSend(t, e.router, "POST", "/api/v1/authentication/ldap/complete", string(body), pending)
	require.Equal(t, 200, completed.Code, completed.Body.String())
	assert.Contains(t, completed.Body.String(), `"mfa_enabled":true`)
	assert.NotContains(t, completed.Body.String(), "access_token")
	assert.Equal(t, 401, oidcSend(t, e.router, "POST", "/api/v1/authentication/ldap/complete", string(body), pending).Code)
	require.Len(t, e.auth.ListUsers(), 2)
}
func TestLDAPSettingsRedactionAndCrossFlowMFAFailureBudget(t *testing.T) {
	e := ldapEnv(t)
	for _, path := range []string{"/api/v1/settings/security/ldap", "/api/v1/settings/security/ldap/audit"} {
		r := doJSONRequest(t, e.router, "GET", path, "", e.adminToken, "127.0.0.1:1234")
		require.Equal(t, 200, r.Code)
		assert.NotContains(t, r.Body.String(), ldapserver.BindPassword)
	}
	cfg := e.ldap.Snapshot().Config
	cfg.ProvisionNew = true
	_, err := e.ldap.Save(ldaplogin.Input{Config: cfg}, "admin", "admin")
	require.NoError(t, err)
	id, err := e.ldap.Lookup(t.Context(), ldapserver.Username)
	require.NoError(t, err)
	user, err := e.auth.EnsureExternalUser("ldap", id.Issuer, id.Subject, "", true)
	require.NoError(t, err)
	enroll, err := e.auth.StartMFAEnrollment(user.ID)
	require.NoError(t, err)
	_, err = e.auth.ConfirmMFAEnrollment(user.ID, apiTOTPCode(t, enroll.Secret, uint64(time.Now().Unix()/30)))
	require.NoError(t, err)
	for i := 0; i < 5; i++ {
		pending := ldapPrimary(t, e)
		r := oidcSend(t, e.router, "POST", "/api/v1/authentication/ldap/complete", `{"otp":"invalid"}`, pending)
		assert.Equal(t, 401, r.Code)
	}
	r := oidcSend(t, e.router, "POST", "/api/v1/authentication/ldap/login", `{"username":"directory.user","password":"`+ldapserver.Password+`"}`)
	assert.Equal(t, 429, r.Code)
}
