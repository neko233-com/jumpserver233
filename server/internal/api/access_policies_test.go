package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	corefiles "github.com/neko233-com/jumpserver233/server/internal/core/files"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type policyTestEnv struct {
	d                 Dependencies
	router            http.Handler
	admin, operator   coreauth.User
	adminToken, token string
	asset             coreassets.Asset
	execs, opens      atomic.Int32
}

func newPolicyEnv(t *testing.T) *policyTestEnv {
	t.Helper()
	e := &policyTestEnv{}
	dir := t.TempDir()
	var err error
	e.d.Auth, err = coreauth.OpenService(filepath.Join(dir, "users.json"))
	require.NoError(t, err)
	e.admin, err = e.d.Auth.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, err)
	e.operator, err = e.d.Auth.CreateUser("policy.operator", "synthetic-policy-password", coreauth.RoleOperator)
	require.NoError(t, err)
	a, err := e.d.Auth.Authenticate("admin", bootstrapPassword)
	require.NoError(t, err)
	o, err := e.d.Auth.Authenticate(e.operator.Username, "synthetic-policy-password")
	require.NoError(t, err)
	e.adminToken = a.AccessToken
	e.token = o.AccessToken
	e.d.AccessPolicies, err = accesspolicies.Open(filepath.Join(dir, "policies.json"), nil)
	require.NoError(t, err)
	e.d.RBAC, err = rbac.Open(filepath.Join(dir, "rbac.json"), nil)
	require.NoError(t, err)
	e.d.Assets = testAssetService(t)
	e.asset, err = e.d.Assets.Create(coreassets.Input{Name: "policy host", Host: "127.0.0.1", Port: 22, Username: "ops", Password: "synthetic-private-password", HostKeyFingerprint: validTestFingerprint()})
	require.NoError(t, err)
	e.d.Grants, err = grants.OpenStore(filepath.Join(dir, "grants.json"))
	require.NoError(t, err)
	_, err = e.d.Grants.Create(grants.Input{UserID: e.operator.ID, AssetID: e.asset.ID, Account: "ops", Actions: []string{"view", "connect", "sftp"}}, "admin")
	require.NoError(t, err)
	e.d.Jobs, err = jobs.Open(filepath.Join(dir, "jobs.json"), make([]byte, 32), nil, func(context.Context, string, string) (sshclient.ExecResult, error) {
		e.execs.Add(1)
		return sshclient.ExecResult{ExitCode: 0, Stdout: "policy-ok"}, nil
	})
	require.NoError(t, err)
	e.d.Operations, err = operations.Open(filepath.Join(dir, "operations.json"), make([]byte, 32), nil, e.d.Jobs)
	require.NoError(t, err)
	t.Cleanup(func() { e.d.Operations.Close(); e.d.Jobs.Close() })
	e.d.CommandFilters, err = commandfilters.OpenStore(filepath.Join(dir, "filters.json"))
	require.NoError(t, err)
	e.d.Sessions = gateway.NewBroker(dir, make([]byte, 32), func(context.Context, string, int, int) (gateway.AssetInfo, gateway.Terminal, error) {
		e.opens.Add(1)
		return gateway.AssetInfo{ID: e.asset.ID, Name: e.asset.Name, Username: e.asset.Username}, sessionTestTerminal{}, nil
	})
	t.Cleanup(e.d.Sessions.CloseAll)
	audit, err := corefiles.OpenAuditStore(filepath.Join(dir, "files.jsonl"))
	require.NoError(t, err)
	e.d.Files = corefiles.NewService(func(context.Context, string) (corefiles.Remote, error) {
		return nil, errors.New("unexpected file operation")
	}, audit)
	e.router = NewRouter("test", e.d)
	return e
}
func (e *policyTestEnv) send(t *testing.T, method, path string, input any, token, remote string, headers ...map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	var err error
	if input != nil {
		raw, err = json.Marshal(input)
		require.NoError(t, err)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.RemoteAddr = remote
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for _, group := range headers {
		for key, value := range group {
			r.Header.Set(key, value)
		}
	}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, r)
	return w
}
func (e *policyTestEnv) rule(t *testing.T, kind, method, source string) accesspolicies.Rule {
	t.Helper()
	in := accesspolicies.Input{Name: "test policy", Kind: kind, UserID: e.operator.ID, Action: "deny", Enabled: true, Priority: 50, Timezone: "UTC"}
	if method != "" {
		in.Methods = []string{method}
	}
	if source != "" {
		in.Sources = []string{source}
	}
	r, err := e.d.AccessPolicies.Save("", in, e.admin.ID, nil)
	require.NoError(t, err)
	return r
}
func TestRequestSourceIPRejectsSpoofedAndMalformedForwarders(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8:1::/48")}
	for _, tc := range []struct{ remote, xff, want string }{{"192.0.2.2:1234", "127.0.0.1", "192.0.2.2"}, {"10.0.0.1:1234", "192.0.2.3, 10.0.0.2", "192.0.2.3"}, {"10.0.0.1:1234", "127.0.0.1, 198.51.100.3", "198.51.100.3"}, {"10.0.0.1:1234", "", "unknown"}, {"10.0.0.1:1234", "bad, 192.0.2.3", "unknown"}, {"10.0.0.1:1234", strings.Repeat("192.0.2.3,", 32) + "192.0.2.4", "unknown"}, {"[2001:db8:1::1]:1234", "2001:db8:2::3", "2001:db8:2::3"}, {"[::ffff:192.0.2.3]:1234", "127.0.0.1", "192.0.2.3"}, {"malformed", "192.0.2.3", "unknown"}} {
		t.Run(tc.remote+tc.xff, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.remote
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			r.Header.Set("X-Real-IP", "127.0.0.1")
			assert.Equal(t, tc.want, requestSourceIP(r, trusted))
		})
	}
}
func TestLoginPoliciesRejectNewAndExistingSessionsWithoutLeakingTokens(t *testing.T) {
	e := newPolicyEnv(t)
	e.rule(t, accesspolicies.Login, "", "192.0.2.0/24")
	input := map[string]string{"username": e.operator.Username, "password": "synthetic-policy-password"}
	denied := e.send(t, "POST", "/api/v1/authentication/auth/", input, "", "192.0.2.8:1234", map[string]string{"X-JMS-Browser-Session": "cookie", "X-Forwarded-For": "127.0.0.1"})
	require.Equal(t, 403, denied.Code, denied.Body.String())
	assert.Contains(t, denied.Body.String(), "access_policy_denied")
	assert.NotContains(t, denied.Body.String(), "access_token")
	for _, cookie := range denied.Result().Cookies() {
		assert.NotEqual(t, "jms_sessionid", cookie.Name)
	}
	assert.Equal(t, 403, e.send(t, "GET", "/api/v1/users/me", nil, e.token, "192.0.2.9:1234").Code)
	assert.Equal(t, 403, e.send(t, "GET", "/api/v1/authentication/session/", nil, e.token, "192.0.2.9:1234").Code)
	assert.Equal(t, 200, e.send(t, "GET", "/api/v1/users/me", nil, e.token, "198.51.100.9:1234").Code)
	assert.Equal(t, 403, e.send(t, "GET", "/api/v1/users/me", nil, "", "192.0.2.9:1234", map[string]string{"Cookie": "jms_sessionid=" + e.token}).Code)
	allowed := e.send(t, "POST", "/api/v1/authentication/auth/", input, "", "198.51.100.9:1234", map[string]string{"X-JMS-Browser-Session": "cookie"})
	require.Equal(t, 200, allowed.Code)
	assert.Contains(t, allowed.Body.String(), "browser_session")
	assert.NotContains(t, allowed.Body.String(), "access_token")
	assert.Equal(t, 200, e.send(t, "GET", "/api/v1/users/me", nil, e.adminToken, "192.0.2.9:1234").Code)
	logout := e.send(t, "POST", "/api/v1/authentication/expire-session/", nil, e.token, "192.0.2.9:1234")
	assert.Equal(t, 204, logout.Code)
}
func TestPolicyPermissionsRevisionsSelfLockoutAndGrantIntersection(t *testing.T) {
	e := newPolicyEnv(t)
	input := accesspolicies.Input{Name: "global deny", Kind: accesspolicies.Login, Action: "deny", Enabled: true, Timezone: "UTC", Priority: 50}
	denied := e.send(t, "POST", "/api/v1/access-policies", input, e.token, "127.0.0.1:1234")
	assert.Equal(t, 403, denied.Code)
	locked := e.send(t, "POST", "/api/v1/access-policies", input, e.adminToken, "127.0.0.1:1234")
	assert.Equal(t, 409, locked.Code)
	assert.Contains(t, locked.Body.String(), "lockout")
	assert.Empty(t, e.d.AccessPolicies.List())
	input.UserID = e.operator.ID
	created := e.send(t, "POST", "/api/v1/access-policies", input, e.adminToken, "127.0.0.1:1234")
	require.Equal(t, 201, created.Code, created.Body.String())
	var rule accesspolicies.Rule
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &rule))
	input.Revision = 0
	assert.Equal(t, 409, e.send(t, "PUT", "/api/v1/access-policies/"+rule.ID, input, e.adminToken, "127.0.0.1:1234").Code)
	input.Revision = 1
	input.Enabled = false
	assert.Equal(t, 200, e.send(t, "PUT", "/api/v1/access-policies/"+rule.ID, input, e.adminToken, "127.0.0.1:1234").Code)
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "policy manager", Permissions: []string{"access_policies.manage"}}, e.admin.ID, "admin")
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, "admin")
	require.NoError(t, err)
	assert.Equal(t, 200, e.send(t, "GET", "/api/v1/access-policies", nil, e.token, "127.0.0.1:1234").Code)
	for _, grant := range e.d.Grants.List() {
		require.NoError(t, e.d.Grants.Delete(grant.ID))
	}
	in := accesspolicies.Input{Name: "ACL allow does not grant", Kind: accesspolicies.Asset, Action: "allow", Enabled: true, Priority: 0, Timezone: "UTC"}
	_, err = e.d.AccessPolicies.Save("", in, e.admin.ID, nil)
	require.NoError(t, err)
	assert.Equal(t, 403, e.send(t, "POST", "/api/v1/sessions", map[string]any{"asset_id": e.asset.ID, "cols": 80, "rows": 24}, e.token, "127.0.0.1:1234").Code)
	assert.Zero(t, e.opens.Load())
	assert.Equal(t, 400, e.send(t, "GET", "/api/v1/access-policies/audit?offset=-1", nil, e.adminToken, "127.0.0.1:1234").Code)
}
func TestAssetAndChannelPoliciesCoverSSHFilesAndJobs(t *testing.T) {
	e := newPolicyEnv(t)
	rule := e.rule(t, accesspolicies.Asset, "", "192.0.2.0/24")
	for _, path := range []string{"/api/v1/sessions", "/api/v1/assets/" + e.asset.ID + "/files/session", "/api/v1/ops/jobs"} {
		var body any
		if path == "/api/v1/sessions" {
			body = map[string]any{"asset_id": e.asset.ID, "cols": 80, "rows": 24}
		} else if strings.HasSuffix(path, "jobs") {
			body = jobs.Input{AssetID: e.asset.ID, Command: "whoami"}
		}
		res := e.send(t, "POST", path, body, e.token, "192.0.2.5:1234", map[string]string{"X-Forwarded-For": "198.51.100.8"})
		assert.Equal(t, 403, res.Code, res.Body.String())
	}
	assert.Zero(t, e.opens.Load())
	assert.Zero(t, e.execs.Load())
	require.NoError(t, e.d.AccessPolicies.Delete(rule.ID, rule.Revision, e.admin.ID, nil))
	channel := e.rule(t, accesspolicies.Method, "upload", "")
	upload := e.send(t, "PUT", "/api/v1/assets/"+e.asset.ID+"/files/content?path=x", nil, e.token, "127.0.0.1:1234")
	assert.Equal(t, 403, upload.Code)
	assert.Equal(t, 200, e.send(t, "POST", "/api/v1/assets/"+e.asset.ID+"/files/session", nil, e.token, "127.0.0.1:1234").Code)
	require.NoError(t, e.d.AccessPolicies.Delete(channel.ID, channel.Revision, e.admin.ID, nil))
	ssh := e.rule(t, accesspolicies.Method, "ssh", "")
	assert.Equal(t, 403, e.send(t, "POST", "/api/v1/sessions", map[string]any{"asset_id": e.asset.ID, "cols": 80, "rows": 24}, e.token, "127.0.0.1:1234").Code)
	require.NoError(t, e.d.AccessPolicies.Delete(ssh.ID, ssh.Revision, e.admin.ID, nil))
	response := e.send(t, "POST", "/api/v1/ops/jobs", map[string]any{"asset_id": e.asset.ID, "command": "whoami", "access_origin": map[string]string{"source_ip": "127.0.0.1"}}, e.token, "192.0.2.5:1234")
	assert.Equal(t, 400, response.Code)
}
func TestJobReviewUsesOriginalSourceAndScheduleRechecksCurrentPolicy(t *testing.T) {
	e := newPolicyEnv(t)
	_, err := e.d.CommandFilters.Create(commandfilters.Input{Name: "review", UserID: e.operator.ID, AssetID: e.asset.ID, Account: "ops", Match: "exact", Pattern: "whoami", Action: "review"}, e.admin.ID)
	require.NoError(t, err)
	created := e.send(t, "POST", "/api/v1/ops/jobs", jobs.Input{AssetID: e.asset.ID, Command: "whoami", RequestID: "pending-policy"}, e.token, "192.0.2.8:1234")
	require.Equal(t, 201, created.Code, created.Body.String())
	var job jobs.Job
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &job))
	assert.Equal(t, "192.0.2.8", job.AccessOrigin.SourceIP)
	assert.Equal(t, "pending_review", job.State)
	rule := e.rule(t, accesspolicies.Asset, "exec", "192.0.2.0/24")
	assert.Equal(t, 403, e.send(t, "POST", "/api/v1/ops/jobs/"+job.ID+"/review", map[string]bool{"approve": true}, e.adminToken, "127.0.0.1:1234").Code)
	assert.Zero(t, e.execs.Load())
	require.NoError(t, e.d.AccessPolicies.Delete(rule.ID, rule.Revision, e.admin.ID, nil))
	require.Equal(t, 200, e.send(t, "POST", "/api/v1/ops/jobs/"+job.ID+"/review", map[string]bool{"approve": true}, e.adminToken, "127.0.0.1:1234").Code)
	require.Eventually(t, func() bool { return e.execs.Load() == 1 }, time.Second, 5*time.Millisecond)
	plan := e.send(t, "POST", "/api/v1/ops/plans", operations.PlanInput{Name: "source-preserved", AssetIDs: []string{e.asset.ID}, Command: "printf source", Kind: "once", RunAt: time.Now().Add(2 * time.Second), RequestID: "source-plan"}, e.token, "192.0.2.8:1234")
	require.Equal(t, 201, plan.Code, plan.Body.String())
	assert.Contains(t, plan.Body.String(), `"source_ip":"192.0.2.8"`)
	e.rule(t, accesspolicies.Asset, "scheduled_exec", "192.0.2.0/24")
	require.Eventually(t, func() bool {
		result := e.send(t, "GET", "/api/v1/ops/runs", nil, e.adminToken, "127.0.0.1:1234")
		return strings.Contains(result.Body.String(), `"state":"denied"`)
	}, 8*time.Second, 100*time.Millisecond)
	assert.EqualValues(t, 1, e.execs.Load())
}
