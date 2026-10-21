package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStandaloneIntranetOrigins(t *testing.T) {
	for _, tc := range []struct {
		origin, host, public, site string
		allowed                    bool
	}{
		{"http://10.12.0.5:8180", "10.12.0.5:8180", "", "same-origin", true},
		{"http://10.12.0.6:8180", "10.12.0.5:8180", "", "cross-site", false},
		{"http://10.12.0.5:8181", "10.12.0.5:8180", "", "same-site", false},
		{"http://attacker.invalid:8180", "attacker.invalid:8180", "", "same-origin", false},
		{"http://10.12.0.5:8180", "10.12.0.5:8180", "https://canonical.example.invalid", "same-origin", false},
		{"http://10.12.0.5:8180", "127.0.0.1:18180", "http://10.12.0.5:8180", "same-origin", true},
		{"null", "10.12.0.5:8180", "", "cross-site", false},
		{"", "10.12.0.5:8180", "", "cross-site", false},
		{"", "10.12.0.5:8180", "", "", true},
	} {
		t.Run(tc.origin+"/"+tc.site+"/"+tc.public, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "http://"+tc.host+"/api/v1/authentication/auth/", nil)
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Sec-Fetch-Site", tc.site)
			h := withPublicOrigin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { assert.Equal(t, tc.allowed, allowedRequestOrigin(r)) }), tc.public)
			h.ServeHTTP(httptest.NewRecorder(), r)
		})
	}
}

func TestIntranetLoginOriginIsNotReportedAsBadPassword(t *testing.T) {
	identities, err := coreauth.OpenService(filepath.Join(t.TempDir(), "users.json"))
	require.NoError(t, err)
	router := NewRouter("test", Dependencies{Auth: identities})
	r := httptest.NewRequest(http.MethodPost, "http://10.12.0.5:8180/api/v1/authentication/auth/", strings.NewReader(`{"username":"synthetic","password":"synthetic"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://attacker.invalid")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), `"code":"origin_not_allowed"`)
	assert.Empty(t, w.Result().Cookies())
	r = httptest.NewRequest(http.MethodOptions, "http://10.12.0.5:8180/api/health", nil)
	r.Header.Set("Origin", "http://10.12.0.5:8180")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, r)
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "http://10.12.0.5:8180", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestDefaultAdministratorBrowserSessionOnIntranetIPSurvivesStoreReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	for range 2 {
		identities, err := coreauth.OpenService(path)
		require.NoError(t, err)
		require.NoError(t, identities.InitializeDefaultAdministrator())
		router := NewRouter("test", Dependencies{Auth: identities})
		r := httptest.NewRequest(http.MethodPost, "http://10.12.0.5:8180/api/v1/authentication/auth/", strings.NewReader(`{"username":"root","password":"root"}`))
		r.Header.Set("Origin", "http://10.12.0.5:8180")
		r.Header.Set(browserSessionHeader, "cookie")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.Contains(t, w.Body.String(), `"browser_session":true`)
		require.NotContains(t, w.Body.String(), "access_token")
		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1)
		assert.True(t, cookies[0].HttpOnly)
		assert.False(t, cookies[0].Secure)
		r = httptest.NewRequest(http.MethodGet, "http://10.12.0.5:8180/api/v1/authentication/session/", nil)
		r.Header.Set("Origin", "http://10.12.0.5:8180")
		r.AddCookie(cookies[0])
		w = httptest.NewRecorder()
		router.ServeHTTP(w, r)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	}
}
