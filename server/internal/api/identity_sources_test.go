package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/identityscope"
	"github.com/neko233-com/jumpserver233/server/internal/core/identitysources"
	"github.com/neko233-com/jumpserver233/server/internal/core/ldaplogin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestNamedSourceHTTPVerifyUsesOriginalURI(t *testing.T) {
	e := ldapEnv(t)
	bank, err := identitysources.Open(filepath.Join(t.TempDir(), "identity-sources.json"), make([]byte, 32), nil, "", e.auth)
	require.NoError(t, err)
	defer bank.Close()
	source, err := bank.Save("", "actor", identitysources.Input{Name: "Signed directory", Kind: "ldap", RequestID: "signature-source-001"})
	require.NoError(t, err)
	router := NewRouter("test", Dependencies{Auth: e.auth, IdentitySources: bank})
	users := e.auth.ListUsers()
	require.Len(t, users, 1)
	key, err := e.auth.CreateAccessKey(users[0].ID)
	require.NoError(t, err)
	path := identityscope.Prefix(source.ID) + "/api/v1/settings/security/ldap"
	date := time.Now().UTC().Format(http.TimeFormat)
	send := func(signed string) int {
		mac := hmac.New(sha256.New, []byte(key.Secret))
		mac.Write([]byte("(request-target): get " + signed + "\ndate: " + date))
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("Date", date)
		r.Header.Set("Authorization", `Signature keyId="`+key.ID+`",algorithm="hmac-sha256",headers="(request-target) date",signature="`+base64.StdEncoding.EncodeToString(mac.Sum(nil))+`"`)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w.Code
	}
	assert.Equal(t, 200, send(path))
	assert.Equal(t, 401, send("/api/v1/settings/security/ldap"))
	assert.Equal(t, 401, send(identityscope.Prefix("idp-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")+"/api/v1/settings/security/ldap"))
}
func TestNamedLDAPSourceCookiesMFABoundariesLegacyAndDisabledCredentialReplay(t *testing.T) {
	e := ldapEnv(t)
	bank, err := identitysources.Open(filepath.Join(t.TempDir(), "identity-sources.json"), make([]byte, 32), nil, "", e.auth)
	require.NoError(t, err)
	defer bank.Close()
	router := NewRouter("test", Dependencies{Auth: e.auth, LDAP: e.ldap, IdentitySources: bank, Assets: testAssetService(t)})
	sources := []identitysources.Source{}
	for i, name := range []string{"Directory A", "Directory B"} {
		source, err := bank.Save("", "admin", identitysources.Input{Name: name, Kind: "ldap", Enabled: true, RequestID: "api-create-source-00" + string(rune('1'+i))})
		require.NoError(t, err)
		_, runtime, _ := bank.Get(source.ID)
		cfg := e.ldap.Snapshot().Config
		cfg.ProvisionNew = true
		cfg.Revision = 0
		_, err = runtime.LDAP.Save(ldaplogin.Input{Config: cfg, BindPassword: "synthetic-directory-reader-password"}, "admin", "admin")
		require.NoError(t, err)
		sources = append(sources, source)
	}
	public := oidcSend(t, router, "GET", "/api/v1/authentication/sources", "")
	require.Equal(t, 200, public.Code)
	assert.NotContains(t, public.Body.String(), e.fixture.URL)
	assert.NotContains(t, public.Body.String(), "bind_password")
	var choices []map[string]any
	require.NoError(t, json.Unmarshal(public.Body.Bytes(), &choices))
	assert.Len(t, choices, 2)
	_, err = e.auth.SetMFAEnforcement(coreauth.MFAEnforcementAll)
	require.NoError(t, err)
	a := identityscope.Prefix(sources[0].ID)
	b := identityscope.Prefix(sources[1].ID)
	body := `{"username":"directory.user","password":"synthetic-directory-user-password"}`
	primary := oidcSend(t, router, "POST", a+"/api/v1/authentication/ldap/login", body)
	require.Equal(t, 401, primary.Code, primary.Body.String())
	pending := cookieNamed(t, primary, ldapPendingCookie)
	assert.Equal(t, a+ldapCookiePath, pending.Path)
	assert.True(t, pending.HttpOnly)
	var setup struct {
		Token      string                 `json:"setup_token"`
		Enrollment coreauth.MFAEnrollment `json:"enrollment"`
	}
	require.NoError(t, json.Unmarshal(primary.Body.Bytes(), &setup))
	require.NotEmpty(t, setup.Token)
	code := apiTOTPCode(t, setup.Enrollment.Secret, uint64(time.Now().Unix()/30))
	complete := `{"setup_token":"` + setup.Token + `","otp":"` + code + `"}`
	wrong := oidcSend(t, router, "POST", b+"/api/v1/authentication/ldap/complete", complete, pending)
	assert.Equal(t, 401, wrong.Code)
	legacy := oidcSend(t, router, "POST", ldapCookiePath+"/complete", complete, pending)
	assert.Equal(t, 401, legacy.Code)
	done := oidcSend(t, router, "POST", a+ldapCookiePath+"/complete", complete, pending)
	require.Equal(t, 200, done.Code, done.Body.String())
	session := cookieNamed(t, done, sessionCookieName)
	assert.Equal(t, "/", session.Path)
	assert.NotContains(t, done.Body.String(), "access_token")
	var result struct {
		User coreauth.User `json:"user"`
	}
	require.NoError(t, json.Unmarshal(done.Body.Bytes(), &result))
	assert.Equal(t, sources[0].ID, result.User.SourceID)
	replay := oidcSend(t, router, "POST", a+ldapCookiePath+"/complete", complete, pending)
	assert.Equal(t, 401, replay.Code)
	off := sources[0].Input
	off.Enabled = false
	off.RequestID = "api-disable-source-001"
	saved, err := bank.Save(sources[0].ID, "admin", off)
	require.NoError(t, err)
	assert.Equal(t, 401, oidcSend(t, router, "GET", "/api/v1/users/me", "", session).Code)
	on := saved.Input
	on.Enabled = true
	on.RequestID = "api-enable-source-001"
	_, err = bank.Save(sources[0].ID, "admin", on)
	require.NoError(t, err)
	assert.Equal(t, 401, oidcSend(t, router, "GET", "/api/v1/users/me", "", session).Code)
	// Named-user credentials never become the default provider's identity.
	_, _, err = e.auth.AuthenticateExternalUser(result.User.ID, "ldap", "")
	assert.ErrorIs(t, err, coreauth.ErrInvalidCredentials)
	assert.Equal(t, http.StatusUnauthorized, doJSONRequest(t, router, "GET", "/api/v1/identity-sources", "", "", "192.0.2.1:1234").Code)
}
