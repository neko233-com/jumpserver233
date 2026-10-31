package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/passwordvault"
	"github.com/stretchr/testify/require"
)

func TestPasswordVaultAPIConsentIsolationAndTransport(t *testing.T) {
	dir := t.TempDir()
	a, e := coreauth.OpenServiceWithVaultKey(filepath.Join(dir, "users.json"), make([]byte, 32))
	require.NoError(t, e)
	admin, e := a.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, e)
	login, e := a.Authenticate("admin", bootstrapPassword)
	require.NoError(t, e)
	other, e := a.CreateUser("other", "synthetic-other-password", coreauth.RoleOperator)
	require.NoError(t, e)
	otherLogin, e := a.Authenticate(other.Username, "synthetic-other-password")
	require.NoError(t, e)
	v, e := passwordvault.Open(filepath.Join(dir, "vault.json"), make([]byte, 32), nil)
	require.NoError(t, e)
	h := NewRouter("test", Dependencies{Auth: a, PasswordVault: v, AdminToken: "synthetic-service-token"})
	call := func(method, path, body, token string, cookie, secure bool) *httptest.ResponseRecorder {
		url := "http://localhost" + path
		if !secure {
			url = "http://192.168.1.2" + path
		}
		r := httptest.NewRequest(method, url, bytes.NewBufferString(body))
		r.RemoteAddr = "127.0.0.1:12345"
		if cookie {
			r.AddCookie(&http.Cookie{Name: "jms_sessionid", Value: token})
		} else {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	bodyCreate := `{"kind":"game","title":"Game","username":"alice","password":"synthetic-secret","request_id":"0123456789abcdef0123456789abcdef"}`
	create := call("POST", "/api/v1/password-vault/items", bodyCreate, login.AccessToken, false, true)
	require.Equal(t, 201, create.Code, create.Body.String())
	require.NotContains(t, create.Body.String(), "synthetic-secret")
	require.Equal(t, 403, call("GET", "/api/v1/password-vault/items", "", login.AccessToken, false, true).Code)
	retry := call("POST", "/api/v1/password-vault/items", bodyCreate, login.AccessToken, false, true)
	require.Equal(t, 201, retry.Code)
	require.Equal(t, create.Body.String(), retry.Body.String())
	var item passwordvault.Item
	require.NoError(t, json.Unmarshal(create.Body.Bytes(), &item))
	denied := call("POST", "/api/v1/password-vault/items/"+item.ID+"/grant", "", login.AccessToken, false, true)
	require.Equal(t, 403, denied.Code)
	grantBody := `{"request_id":"1123456789abcdef0123456789abcdef"}`
	foreign := call("POST", "/api/v1/password-vault/items/"+item.ID+"/grant", grantBody, otherLogin.AccessToken, true, true)
	require.Equal(t, 404, foreign.Code)
	grant := call("POST", "/api/v1/password-vault/items/"+item.ID+"/grant", grantBody, login.AccessToken, true, true)
	require.Equal(t, 201, grant.Code, grant.Body.String())
	grantRetry := call("POST", "/api/v1/password-vault/items/"+item.ID+"/grant", grantBody, login.AccessToken, true, true)
	require.Equal(t, grant.Body.String(), grantRetry.Body.String())
	var capability struct {
		ID    string `json:"grant_id"`
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(grant.Body.Bytes(), &capability))
	body, _ := json.Marshal(map[string]string{"token": capability.Token})
	path := "/api/v1/password-vault/grants/" + capability.ID + "/consume"
	denied = call("POST", path, string(body), otherLogin.AccessToken, false, true)
	require.Equal(t, 403, denied.Code)
	insecure := call("POST", path, string(body), login.AccessToken, false, false)
	require.Equal(t, 403, insecure.Code)
	key, e := a.CreateAccessKey(admin.ID)
	require.NoError(t, e)
	req := httptest.NewRequest("POST", "http://localhost"+path, bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	date := time.Now().UTC().Format(http.TimeFormat)
	req.Header.Set("Date", date)
	mac := hmac.New(sha256.New, []byte(key.Secret))
	mac.Write([]byte("(request-target): " + strings.ToLower(req.Method) + " " + req.URL.RequestURI() + "\ndate: " + date))
	req.Header.Set("Authorization", fmt.Sprintf(`Signature keyId=%q,algorithm="hmac-sha256",headers="(request-target) date",signature=%q`, key.ID, base64.StdEncoding.EncodeToString(mac.Sum(nil))))
	read := httptest.NewRecorder()
	h.ServeHTTP(read, req)
	require.Equal(t, 200, read.Code, read.Body.String())
	require.Contains(t, read.Body.String(), "synthetic-secret")
	require.Contains(t, read.Header().Get("Cache-Control"), "no-store")
	replay := call("POST", path, string(body), login.AccessToken, false, true)
	require.Equal(t, 403, replay.Code)
	shared := call("POST", "/api/v1/password-vault/items", `{"kind":"website","title":"shared","username":"team","password":"synthetic-team-secret","shared":true,"request_id":"2123456789abcdef0123456789abcdef"}`, login.AccessToken, false, true)
	require.Equal(t, 201, shared.Code, shared.Body.String())
	var teamItem passwordvault.Item
	require.NoError(t, json.Unmarshal(shared.Body.Bytes(), &teamItem))
	teamList := call("GET", "/api/v1/password-vault/items", "", otherLogin.AccessToken, true, true)
	require.Equal(t, 200, teamList.Code)
	require.Contains(t, teamList.Body.String(), teamItem.ID)
	require.NotContains(t, teamList.Body.String(), item.ID)
	teamReveal := call("POST", "/api/v1/password-vault/items/"+teamItem.ID+"/reveal", "", otherLogin.AccessToken, true, true)
	require.Equal(t, 200, teamReveal.Code)
	require.Contains(t, teamReveal.Body.String(), "synthetic-team-secret")
	teamGrant := call("POST", "/api/v1/password-vault/items/"+teamItem.ID+"/grant", `{"request_id":"3123456789abcdef0123456789abcdef"}`, otherLogin.AccessToken, true, true)
	require.Equal(t, 201, teamGrant.Code, teamGrant.Body.String())
	importBody, _ := json.Marshal(map[string]any{"kind": "service", "title": "import", "username": "fixture", "password": "synthetic-import-secret", "shared": true, "request_id": "5123456789abcdef0123456789abcdef", "owner_id": other.ID})
	blockedImport := call("POST", "/api/v1/password-vault/items", string(importBody), login.AccessToken, false, true)
	require.Equal(t, 403, blockedImport.Code)
	imported := call("POST", "/api/v1/password-vault/items", string(importBody), "synthetic-service-token", false, true)
	require.Equal(t, 201, imported.Code, imported.Body.String())
	remoteImport := httptest.NewRequest("POST", "https://vault.example.test/api/v1/password-vault/items", bytes.NewReader(importBody))
	remoteImport.RemoteAddr = "192.0.2.10:12345"
	remoteImport.Header.Set("Authorization", "Bearer synthetic-service-token")
	remoteResponse := httptest.NewRecorder()
	h.ServeHTTP(remoteResponse, remoteImport)
	require.Equal(t, 403, remoteResponse.Code)
	restricted := NewRouter("test", Dependencies{Auth: a, PasswordVault: v, AdminToken: "synthetic-service-token", OrganizationAllowed: func(u coreauth.User) bool { return u.ID != other.ID }})
	wrongOrg := httptest.NewRequest("POST", "http://localhost/api/v1/password-vault/items", bytes.NewReader(importBody))
	wrongOrg.RemoteAddr = "127.0.0.1:12345"
	wrongOrg.Header.Set("Authorization", "Bearer synthetic-service-token")
	wrongOrgResponse := httptest.NewRecorder()
	restricted.ServeHTTP(wrongOrgResponse, wrongOrg)
	require.Equal(t, 403, wrongOrgResponse.Code)
	var importedItem passwordvault.Item
	require.NoError(t, json.Unmarshal(imported.Body.Bytes(), &importedItem))
	listAfterImport := call("GET", "/api/v1/password-vault/items", "", otherLogin.AccessToken, true, true)
	require.Contains(t, listAfterImport.Body.String(), importedItem.ID)
	var ownList struct {
		Results []passwordvault.Item `json:"results"`
	}
	require.NoError(t, json.Unmarshal(listAfterImport.Body.Bytes(), &ownList))
	for _, item := range ownList.Results {
		if item.ID == importedItem.ID {
			require.True(t, item.CanManageSharing)
		}
	}
}

func TestPasswordVaultTrustedTLSProxy(t *testing.T) {
	r := httptest.NewRequest("GET", "http://vault.example.test/api/v1/password-vault/items", nil)
	r.RemoteAddr = "10.2.3.4:1234"
	r.Header.Set("X-Forwarded-Proto", "https")
	d := Dependencies{PublicURL: "https://vault.example.test", TrustedProxies: []string{"10.2.3.0/24"}}
	require.True(t, vaultSecureTransport(r, d))
	r.RemoteAddr = "10.3.3.4:1234"
	require.False(t, vaultSecureTransport(r, d))
	r.RemoteAddr = "10.2.3.4:1234"
	r.Header.Set("X-Forwarded-Proto", "http")
	require.False(t, vaultSecureTransport(r, d))
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Host = "attacker.example.test"
	require.False(t, vaultSecureTransport(r, d))
}

func TestAdditionalHTTPSOriginRequiresTrustedProxyAndPreservesLegacyOrigin(t *testing.T) {
	inspect := withAdditionalHTTPSOrigin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]bool{"allowed": allowedRequestOrigin(r), "secure_cookie": secureSessionCookie(r), "vault": vaultSecureTransport(r, Dependencies{})})
	}), "https://vault.example.invalid:18443", []string{"127.0.0.1/32"})
	check := func(host, origin, peer, proto string) (bool, bool, bool) {
		r := httptest.NewRequest("GET", "http://"+host+"/", nil)
		r.RemoteAddr = peer
		r.Header.Set("Origin", origin)
		if proto != "" {
			r.Header.Set("X-Forwarded-Proto", proto)
		}
		w := httptest.NewRecorder()
		inspect.ServeHTTP(w, r)
		var got map[string]bool
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
		return got["allowed"], got["secure_cookie"], got["vault"]
	}
	allowed, secure, vault := check("vault.example.invalid:18443", "https://vault.example.invalid:18443", "127.0.0.1:4444", "https")
	require.True(t, allowed)
	require.True(t, secure)
	require.True(t, vault)
	allowed, secure, vault = check("vault.example.invalid:18443", "https://vault.example.invalid:18443", "192.0.2.2:4444", "https")
	require.False(t, allowed)
	require.False(t, secure)
	require.False(t, vault)
	allowed, secure, vault = check("vault.example.invalid:18443", "https://vault.example.invalid:18443", "127.0.0.1:4444", "http")
	require.False(t, allowed)
	require.False(t, secure)
	require.False(t, vault)
	allowed, _, _ = check("vault.example.invalid:18443", "https://attacker.example.invalid", "127.0.0.1:4444", "https")
	require.False(t, allowed)
	allowed, secure, _ = check("192.168.10.20:8180", "http://192.168.10.20:8180", "127.0.0.1:4444", "http")
	require.True(t, allowed)
	require.False(t, secure)
}

func TestAdditionalHTTPSOriginRealLoginAndVault(t *testing.T) {
	dir := t.TempDir()
	auth, e := coreauth.OpenServiceWithVaultKey(filepath.Join(dir, "users.json"), make([]byte, 32))
	require.NoError(t, e)
	_, e = auth.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, e)
	store, e := passwordvault.Open(filepath.Join(dir, "vault.json"), make([]byte, 32), nil)
	require.NoError(t, e)
	h := NewRouter("test", Dependencies{Auth: auth, PasswordVault: store, AdditionalHTTPSOrigin: "https://vault.example.invalid:18443", TrustedProxies: []string{"127.0.0.1/32"}})
	request := httptest.NewRequest("POST", "http://vault.example.invalid:18443/api/v1/authentication/auth/", strings.NewReader(fmt.Sprintf(`{"username":"admin","password":%q}`, bootstrapPassword)))
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set("Origin", "https://vault.example.invalid:18443")
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-JMS-Browser-Session", "cookie")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	require.Equal(t, 200, response.Code, response.Body.String())
	var session *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == "jms_sessionid" {
			session = cookie
		}
	}
	require.NotNil(t, session)
	require.True(t, session.Secure)
	get := httptest.NewRequest("GET", "http://vault.example.invalid:18443/api/v1/password-vault/items", nil)
	get.RemoteAddr = "127.0.0.1:12345"
	get.Header.Set("Origin", "https://vault.example.invalid:18443")
	get.Header.Set("X-Forwarded-Proto", "https")
	get.AddCookie(session)
	result := httptest.NewRecorder()
	h.ServeHTTP(result, get)
	require.Equal(t, 200, result.Code, result.Body.String())
}
