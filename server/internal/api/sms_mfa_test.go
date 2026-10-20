package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/cloudnotify"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/loginaudit"
	"github.com/neko233-com/jumpserver233/server/internal/core/smsmfa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type smsTransport struct {
	mu   sync.Mutex
	code string
	rev  atomic.Int32
}

func (f *smsTransport) MFARevision() int { return int(f.rev.Load()) }
func (f *smsTransport) SendMFA(_ context.Context, _ int, _, _, code string, check func() error) cloudnotify.Outcome {
	if check() != nil {
		return cloudnotify.Outcome{State: "failed"}
	}
	f.mu.Lock()
	f.code = code
	f.mu.Unlock()
	return cloudnotify.Outcome{State: "sent"}
}
func (f *smsTransport) last() string { f.mu.Lock(); defer f.mu.Unlock(); return f.code }
func TestSMSMFABrowserFirstEnrollmentWithholdsSessionAndEnforcesProofRevocation(t *testing.T) {
	root := t.TempDir()
	identities, e := coreauth.OpenServiceWithVaultKey(filepath.Join(root, "users.json"), make([]byte, 32))
	require.NoError(t, e)
	admin, e := identities.Bootstrap("sms.admin", "synthetic-sms-admin-password")
	require.NoError(t, e)
	prior, e := identities.Authenticate(admin.Username, "synthetic-sms-admin-password")
	require.NoError(t, e)
	f := &smsTransport{}
	f.rev.Store(1)
	var now atomic.Int64
	now.Store(time.Now().UnixNano())
	sms, e := smsmfa.Open(filepath.Join(root, "sms.json"), make([]byte, 32), nil, identities, f, smsmfa.Options{Now: func() time.Time { return time.Unix(0, now.Load()) }})
	require.NoError(t, e)
	defer sms.Close()
	audit, e := loginaudit.Open(filepath.Join(root, "audit"), make([]byte, 32), nil)
	require.NoError(t, e)
	defer audit.Close()
	router := NewRouter("test", Dependencies{Auth: identities, SMSMFA: sms, LoginAudit: audit})
	send := func(method, path, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(browserSessionHeader, "cookie")
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	config := `{"enabled":true,"policy":"all","user_ids":[],"revision":0,"request_id":"sms-api-settings-001"}`
	token := &http.Cookie{Name: sessionCookieName, Value: prior.AccessToken}
	saved := send("PUT", "/api/v1/settings/security/sms-mfa", config, token)
	require.Equal(t, 200, saved.Code, saved.Body.String())
	assert.Equal(t, 200, send("PUT", "/api/v1/settings/security/sms-mfa", config, token).Code)
	primary := send("POST", "/api/v1/authentication/auth/", `{"username":"sms.admin","password":"synthetic-sms-admin-password"}`)
	require.Equal(t, 202, primary.Code, primary.Body.String())
	assert.NotContains(t, primary.Body.String(), "access_token")
	assert.NotContains(t, primary.Body.String(), "factor_token")
	cookie := cookieNamed(t, primary, smsCookie)
	assert.Equal(t, smsPath, cookie.Path)
	assert.True(t, cookie.HttpOnly)
	assert.Equal(t, 401, send("GET", "/api/v1/authentication/session/", "").Code)
	bound := send("POST", smsPath+"/bind", `{"phone":"+8613800000000","request_id":"sms-bind-001"}`, cookie)
	require.Equal(t, 200, bound.Code, bound.Body.String())
	assert.Equal(t, 200, send("POST", smsPath+"/bind", `{"phone":"+8613800000000","request_id":"sms-bind-001"}`, cookie).Code)
	wrong := f.last()
	if wrong == "000000" {
		wrong = "111111"
	} else {
		wrong = "000000"
	}
	assert.Equal(t, 401, send("POST", smsPath+"/complete", `{"code":"`+wrong+`"}`, cookie).Code)
	complete := send("POST", smsPath+"/complete", `{"code":"`+f.last()+`"}`, cookie)
	require.Equal(t, 200, complete.Code, complete.Body.String())
	assert.Contains(t, complete.Body.String(), `"browser_session":true`)
	assert.NotContains(t, complete.Body.String(), "access_token")
	session := cookieNamed(t, complete, sessionCookieName)
	assert.Equal(t, 200, send("GET", "/api/v1/authentication/session/", "", session).Code)
	_, ok := identities.ValidateToken(prior.AccessToken)
	assert.False(t, ok)
	assert.Equal(t, 401, send("POST", smsPath+"/complete", `{"code":"`+f.last()+`"}`, cookie).Code)
	now.Add(int64(65 * time.Second))
	next := send("POST", "/api/v1/authentication/auth/", `{"username":"sms.admin","password":"synthetic-sms-admin-password"}`)
	require.Equal(t, 202, next.Code, next.Body.String())
	pending := cookieNamed(t, next, smsCookie)
	assert.Equal(t, 200, send("GET", smsPath+"/pending", "", pending).Code)
	f.rev.Add(1)
	assert.Equal(t, 401, send("POST", smsPath+"/complete", `{"code":"`+f.last()+`"}`, pending).Code)
	records := send("GET", "/api/v1/settings/security/sms-mfa/audit", "", session)
	require.Equal(t, 200, records.Code)
	assert.NotContains(t, records.Body.String(), "+8613800000000")
	assert.NotContains(t, records.Body.String(), `"code"`)
	var body map[string]any
	require.NoError(t, json.Unmarshal(complete.Body.Bytes(), &body))
	assert.True(t, body["user"].(map[string]any)["sms_mfa_enabled"].(bool))
}
