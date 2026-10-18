package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/radiusclient"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/radiuslogin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type apiRadiusClient struct{}

func (apiRadiusClient) Exchange(_ context.Context, _ radiusclient.Config, _ radiusclient.Secrets, in radiusclient.Request) (radiusclient.Reply, error) {
	if in.Password == "reject" {
		return radiusclient.Reply{Code: radiusclient.AccessReject}, nil
	}
	if in.Username == "challenge" && len(in.State) == 0 {
		return radiusclient.Reply{Code: radiusclient.AccessChallenge, State: []byte("round-1")}, nil
	}
	return radiusclient.Reply{Code: radiusclient.AccessAccept}, nil
}
func radiusEnv(t *testing.T) *policyTestEnv {
	t.Helper()
	e := reviewEnv(t)
	var err error
	e.d.RADIUS, err = radiuslogin.Open(filepath.Join(t.TempDir(), "radius.json"), make([]byte, 32), nil, apiRadiusClient{})
	require.NoError(t, err)
	t.Cleanup(e.d.RADIUS.Close)
	_, err = e.d.RADIUS.Save(radiuslogin.Input{Config: radiuslogin.Config{Enabled: true, ProvisionNew: true, Realm: "test", Primary: radiusclient.Config{Host: "radius.synthetic.invalid", Transport: "udp", AllowUDP: true}, Factor: radiusclient.Config{Host: "factor.synthetic.invalid", Transport: "udp", AllowUDP: true}, FactorPolicy: "users", FactorUserIDs: []string{e.operator.ID}}, PrimarySecrets: radiuslogin.EndpointSecrets{SharedSecret: "synthetic-primary-secret-233"}, FactorSecrets: radiuslogin.EndpointSecrets{SharedSecret: "synthetic-factor-secret-233"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	e.router = NewRouter("test", e.d)
	return e
}
func radiusJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var v map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &v), w.Body.String())
	return v
}
func startRadiusFactor(t *testing.T, e *policyTestEnv, browser bool) string {
	t.Helper()
	headers := map[string]string{}
	if browser {
		headers[browserSessionHeader] = "cookie"
	}
	w := e.send(t, "POST", "/api/v1/authentication/auth/", map[string]string{"username": e.operator.Username, "password": "synthetic-policy-password"}, "", "192.0.2.5:123", headers)
	require.Equal(t, 202, w.Code, w.Body.String())
	v := radiusJSON(t, w)
	assert.Equal(t, true, v["radius_factor_required"])
	assert.NotContains(t, w.Body.String(), "access_token")
	assert.NotContains(t, w.Body.String(), "proof")
	ticket := ""
	for _, c := range w.Result().Cookies() {
		if c.Name == factorCookie {
			ticket = c.Value
			assert.True(t, c.HttpOnly)
			assert.Equal(t, factorCookiePath, c.Path)
		}
		if c.Name == sessionCookieName {
			assert.Less(t, c.MaxAge, 0)
		}
	}
	require.NotEmpty(t, ticket)
	if browser {
		assert.NotContains(t, v, "factor_token")
	} else {
		assert.Equal(t, ticket, v["factor_token"])
	}
	return ticket
}
func TestRADIUSFactorBeforeSessionAndOneUse(t *testing.T) {
	for _, browser := range []bool{false, true} {
		t.Run(map[bool]string{true: "browser", false: "SDK"}[browser], func(t *testing.T) {
			e := radiusEnv(t)
			ticket := startRadiusFactor(t, e, browser)
			assert.Equal(t, 401, e.send(t, "GET", "/api/v1/users/me", nil, ticket, "192.0.2.5:1").Code)
			w := e.send(t, "POST", factorCookiePath+"/complete", map[string]string{"factor_token": ticket, "response": "654321"}, "", "192.0.2.6:1")
			assert.Equal(t, 401, w.Code)
			w = e.send(t, "POST", factorCookiePath+"/complete", map[string]string{"factor_token": ticket, "response": "654321"}, "", "192.0.2.5:1")
			require.Equal(t, 200, w.Code, w.Body.String())
			v := radiusJSON(t, w)
			token := ""
			if browser {
				assert.Equal(t, true, v["browser_session"])
				assert.NotContains(t, v, "access_token")
				for _, c := range w.Result().Cookies() {
					if c.Name == sessionCookieName && c.MaxAge >= 0 {
						token = c.Value
					}
				}
			} else {
				token, _ = v["access_token"].(string)
			}
			require.NotEmpty(t, token)
			assert.Equal(t, 200, e.send(t, "GET", "/api/v1/users/me", nil, token, "192.0.2.5:1").Code)
			assert.Equal(t, 401, e.send(t, "POST", factorCookiePath+"/complete", map[string]string{"factor_token": ticket, "response": "654321"}, "", "192.0.2.5:1").Code)
		})
	}
}
func TestRADIUSFactorRejectionRevisionCancellationAndForgedStamp(t *testing.T) {
	e := radiusEnv(t)
	ticket := startRadiusFactor(t, e, false)
	w := e.send(t, "POST", factorCookiePath+"/complete", map[string]string{"factor_token": ticket, "response": "reject"}, "", "192.0.2.5:1")
	assert.Equal(t, 401, w.Code)
	assert.Equal(t, 401, e.send(t, "POST", factorCookiePath+"/complete", map[string]string{"factor_token": ticket, "response": "code"}, "", "192.0.2.5:1").Code)
	ticket = startRadiusFactor(t, e, false)
	cfg := e.d.RADIUS.Snapshot().Config
	_, err := e.d.RADIUS.Save(radiuslogin.Input{Config: cfg}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 401, e.send(t, "POST", factorCookiePath+"/complete", map[string]string{"factor_token": ticket, "response": "code"}, "", "192.0.2.5:1").Code)
	ticket = startRadiusFactor(t, e, false)
	assert.Equal(t, 204, e.send(t, "POST", factorCookiePath+"/cancel", map[string]string{"factor_token": ticket}, "", "192.0.2.5:1").Code)
	assert.Equal(t, 401, e.send(t, "POST", factorCookiePath+"/complete", map[string]string{"factor_token": ticket, "response": "code"}, "", "192.0.2.5:1").Code)
	w = e.send(t, "POST", "/api/v1/authentication/auth/", map[string]string{"username": e.operator.Username, "password": "synthetic-policy-password", "secondary_stamp": "forged"}, "", "192.0.2.5:1")
	assert.Equal(t, 400, w.Code)
}
func TestRADIUSPrimaryChallengeAndControlledIdentity(t *testing.T) {
	e := radiusEnv(t)
	original, _ := e.d.Auth.UserByID(e.admin.ID)
	w := e.send(t, "POST", radiusCookiePath+"/login", map[string]string{"username": "admin", "password": "code"}, "", "192.0.2.5:1")
	require.Equal(t, 202, w.Code, w.Body.String())
	v := radiusJSON(t, w)
	assert.Equal(t, true, v["radius_primary_verified"])
	assert.NotContains(t, v, "access_token")
	pending := v["pending_token"].(string)
	assert.Equal(t, 401, e.send(t, "POST", radiusCookiePath+"/complete", map[string]string{"pending_token": pending}, "", "192.0.2.6:1").Code)
	w = e.send(t, "POST", radiusCookiePath+"/complete", map[string]string{"pending_token": pending}, "", "192.0.2.5:1")
	require.Equal(t, 200, w.Code, w.Body.String())
	v = radiusJSON(t, w)
	user := v["user"].(map[string]any)
	assert.Equal(t, coreauth.RoleOperator, user["role"])
	assert.NotEqual(t, original.ID, user["id"])
	current, _ := e.d.Auth.UserByID(e.admin.ID)
	assert.Equal(t, original, current)
	assert.Equal(t, 401, e.send(t, "POST", radiusCookiePath+"/complete", map[string]string{"pending_token": pending}, "", "192.0.2.5:1").Code)
	w = e.send(t, "POST", radiusCookiePath+"/login", map[string]string{"username": "challenge", "password": "start"}, "", "192.0.2.5:1")
	require.Equal(t, 202, w.Code)
	v = radiusJSON(t, w)
	assert.Equal(t, true, v["radius_challenge_required"])
	ticket := v["challenge_token"].(string)
	w = e.send(t, "POST", radiusCookiePath+"/challenge", map[string]string{"challenge_token": ticket, "response": "code"}, "", "192.0.2.5:1")
	require.Equal(t, 202, w.Code, w.Body.String())
	assert.Equal(t, true, radiusJSON(t, w)["radius_primary_verified"])
}
func TestRADIUSSettingsPermissionsAndReviewComposition(t *testing.T) {
	e := radiusEnv(t)
	for _, path := range []string{"/api/v1/settings/security/radius", "/api/v1/settings/security/radius/audit"} {
		assert.Equal(t, 403, e.send(t, "GET", path, nil, e.token, "192.0.2.5:1").Code)
		w := e.send(t, "GET", path, nil, e.adminToken, "192.0.2.5:1")
		require.Equal(t, 200, w.Code)
		assert.NotContains(t, w.Body.String(), "synthetic-primary-secret-233")
	}
	assert.Equal(t, 400, e.send(t, "POST", "/api/v1/settings/security/radius/users", map[string]string{"subject": "bad\nsubject", "username": "invalid"}, e.adminToken, "192.0.2.5:1").Code)
	reviewRule(t, e, "review")
	ticket := startRadiusFactor(t, e, false)
	w := e.send(t, "POST", factorCookiePath+"/complete", map[string]string{"factor_token": ticket, "response": "code"}, "", "192.0.2.5:1")
	require.Equal(t, 202, w.Code, w.Body.String())
	v := radiusJSON(t, w)
	assert.Equal(t, true, v["login_review_required"])
	assert.NotContains(t, v, "access_token")
	id := v["review_id"].(string)
	review := v["review_token"].(string)
	require.Equal(t, 204, e.send(t, "POST", "/api/v1/login-reviews/"+id+"/approve", nil, e.adminToken, "192.0.2.6:1").Code)
	w = e.send(t, "POST", reviewCookiePath+"/complete", map[string]string{"review_token": review}, "", "192.0.2.5:1")
	require.Equal(t, 200, w.Code, w.Body.String())
	ticket = startRadiusFactor(t, e, false)
	w = e.send(t, "POST", factorCookiePath+"/complete", map[string]string{"factor_token": ticket, "response": "code"}, "", "192.0.2.5:1")
	require.Equal(t, 202, w.Code)
	v = radiusJSON(t, w)
	id = v["review_id"].(string)
	review = v["review_token"].(string)
	require.Equal(t, 204, e.send(t, "POST", "/api/v1/login-reviews/"+id+"/approve", nil, e.adminToken, "192.0.2.6:1").Code)
	cfg := e.d.RADIUS.Snapshot().Config
	_, err := e.d.RADIUS.Save(radiuslogin.Input{Config: cfg}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.NotEqual(t, 200, e.send(t, "POST", reviewCookiePath+"/complete", map[string]string{"review_token": review}, "", "192.0.2.5:1").Code)
}
func TestLocalMFAEnrollmentMustFinishBeforeRADIUSFactor(t *testing.T) {
	e := radiusEnv(t)
	_, err := e.d.Auth.SetMFAEnforcement(coreauth.MFAEnforcementAll)
	require.NoError(t, err)
	w := e.send(t, "POST", "/api/v1/authentication/auth/", map[string]string{"username": e.operator.Username, "password": "synthetic-policy-password"}, "", "192.0.2.5:1")
	require.Equal(t, 401, w.Code, w.Body.String())
	v := radiusJSON(t, w)
	assert.Equal(t, true, v["mfa_setup_required"])
	assert.NotContains(t, v, "factor_token")
	setup := v["setup_token"].(string)
	secret := v["enrollment"].(map[string]any)["secret"].(string)
	code := apiTOTPCode(t, secret, uint64(time.Now().Unix()/30))
	w = e.send(t, "POST", "/api/v1/authentication/mfa/setup/confirm", map[string]string{"setup_token": setup, "otp": code}, "", "192.0.2.5:1")
	require.Equal(t, 202, w.Code, w.Body.String())
	v = radiusJSON(t, w)
	assert.Equal(t, true, v["radius_factor_required"])
	assert.NotContains(t, v, "access_token")
}
func TestUnprovisionedRADIUSIdentityIsRejectedWithoutSession(t *testing.T) {
	e := radiusEnv(t)
	c := e.d.RADIUS.Snapshot().Config
	c.ProvisionNew = false
	_, err := e.d.RADIUS.Save(radiuslogin.Input{Config: c}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	w := e.send(t, "POST", radiusCookiePath+"/login", map[string]string{"username": "not-provisioned", "password": "code"}, "", "192.0.2.5:1")
	assert.Equal(t, 401, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "radius_rejected")
	assert.NotContains(t, w.Body.String(), "access_token")
	assert.Len(t, e.d.Auth.ListUsers(), 2)
}
