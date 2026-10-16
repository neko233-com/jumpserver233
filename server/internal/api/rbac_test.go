package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	"github.com/neko233-com/jumpserver233/server/internal/core/groups"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type rbacTerminal struct{}

func (rbacTerminal) Read([]byte) (int, error)    { return 0, io.EOF }
func (rbacTerminal) Write(p []byte) (int, error) { return len(p), nil }
func (rbacTerminal) Close() error                { return nil }
func (rbacTerminal) Resize(int, int) error       { return nil }

func TestRBACDelegationIsolationGroupRevocationAndProtectedAdministrators(t *testing.T) {
	dir := t.TempDir()
	identities, err := coreauth.OpenServiceWithVaultKey(filepath.Join(dir, "users.json"), make([]byte, 32))
	require.NoError(t, err)
	admin, err := identities.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, err)
	operator, err := identities.CreateUser("role.operator", "synthetic-rbac-operator-password", coreauth.RoleOperator)
	require.NoError(t, err)
	adminLogin, err := identities.Authenticate("admin", bootstrapPassword)
	require.NoError(t, err)
	operatorLogin, err := identities.Authenticate("role.operator", "synthetic-rbac-operator-password")
	require.NoError(t, err)
	roles, err := rbac.Open(filepath.Join(dir, "rbac.json"), nil)
	require.NoError(t, err)
	groupStore, err := groups.OpenStore(filepath.Join(dir, "groups.json"))
	require.NoError(t, err)
	assets := testAssetService(t)
	asset, err := assets.Create(coreassets.Input{Name: "qa", Host: "127.0.0.1", Port: 22, Username: "ops", Password: "synthetic-only-password", HostKeyFingerprint: validTestFingerprint()})
	require.NoError(t, err)
	js, err := jobs.Open(filepath.Join(dir, "jobs.json"), make([]byte, 32), nil, func(context.Context, string, string) (sshclient.ExecResult, error) {
		return sshclient.ExecResult{ExitCode: 0}, nil
	})
	require.NoError(t, err)
	defer js.Close()
	job, err := js.Submit(jobs.Input{AssetID: asset.ID, Command: "whoami"}, admin.ID, "admin", "qa", "ops", "review", "")
	require.NoError(t, err)
	broker := gateway.NewBroker(dir, make([]byte, 32), func(context.Context, string, int, int) (gateway.AssetInfo, gateway.Terminal, error) {
		return gateway.AssetInfo{ID: asset.ID, Name: "qa", Username: "ops"}, rbacTerminal{}, nil
	})
	defer broker.CloseAll()
	session, err := broker.Create(context.Background(), gateway.CreateRequest{AssetID: asset.ID, OperatorID: admin.ID, Operator: "admin", Cols: 80, Rows: 24})
	require.NoError(t, err)
	router := NewRouter("test", Dependencies{Auth: identities, Assets: assets, Groups: groupStore, Jobs: js, Sessions: broker, RBAC: roles})
	for _, path := range []string{"/api/v1/rbac/me", "/api/v1/assets", "/api/v1/users"} {
		anonymous := doJSONRequest(t, router, "GET", path, "", "", "127.0.0.1:12345")
		assert.Equal(t, 401, anonymous.Code, path)
	}
	_, virtual := jobOwner(Dependencies{Auth: identities}, "loopback-admin")
	assert.False(t, virtual)
	send := func(method, path string, body any, token string) *httptest.ResponseRecorder {
		t.Helper()
		text := ""
		if body != nil {
			raw, err := json.Marshal(body)
			require.NoError(t, err)
			text = string(raw)
		}
		return doJSONRequest(t, router, method, path, text, token, "127.0.0.1:12345")
	}
	bind := func(ids []string, revision int) int {
		t.Helper()
		response := send("PUT", "/api/v1/rbac/bindings", rbac.BindingInput{SubjectType: "user", SubjectID: operator.ID, RoleIDs: ids, Revision: revision}, adminLogin.AccessToken)
		require.Equal(t, 200, response.Code, response.Body.String())
		var b rbac.Binding
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &b))
		return b.Revision
	}
	assert.Equal(t, 403, send("GET", "/api/v1/rbac/roles", nil, operatorLogin.AccessToken).Code)
	assert.Equal(t, 403, send("POST", "/api/v1/rbac/roles", rbac.RoleInput{Name: "escalate", Permissions: []string{"roles.manage"}}, operatorLogin.AccessToken).Code)
	revision := bind([]string{"asset-manager"}, 0)
	inventory := send("GET", "/api/v1/assets", nil, operatorLogin.AccessToken)
	require.Equal(t, 200, inventory.Code)
	assert.Contains(t, inventory.Body.String(), `"manage"`)
	assert.NotContains(t, inventory.Body.String(), `"connect"`)
	assert.NotContains(t, inventory.Body.String(), "synthetic-only-password")
	assert.Equal(t, 403, send("POST", "/api/v1/ops/jobs", jobs.Input{AssetID: asset.ID, Command: "whoami"}, operatorLogin.AccessToken).Code)
	assert.Equal(t, 403, send("POST", "/api/v1/assets/"+asset.ID+"/password-rotation", nil, operatorLogin.AccessToken).Code)
	assert.Equal(t, 403, send("GET", "/api/v1/assets/"+asset.ID+"/credential-backups", nil, operatorLogin.AccessToken).Code)
	assert.Equal(t, 403, send("PUT", "/api/v1/settings/security/mfa", map[string]string{"mode": "disabled"}, operatorLogin.AccessToken).Code)
	updated := send("PUT", "/api/v1/assets/"+asset.ID, map[string]any{"name": "renamed", "host": "127.0.0.1", "port": 22, "username": "ops", "host_key_fingerprint": validTestFingerprint()}, operatorLogin.AccessToken)
	require.Equal(t, 200, updated.Code, updated.Body.String())
	revision = bind([]string{"auditor"}, revision)
	assert.Equal(t, 200, send("GET", "/api/v1/ops/jobs/"+job.ID, nil, operatorLogin.AccessToken).Code)
	assert.Equal(t, 404, send("DELETE", "/api/v1/ops/jobs/"+job.ID, nil, operatorLogin.AccessToken).Code)
	assert.Equal(t, 403, send("POST", "/api/v1/ops/jobs/"+job.ID+"/review", map[string]bool{"approve": true}, operatorLogin.AccessToken).Code)
	sessions := send("GET", "/api/v1/sessions", nil, operatorLogin.AccessToken)
	require.Equal(t, 200, sessions.Code)
	assert.Contains(t, sessions.Body.String(), session.SessionID)
	assert.Equal(t, 404, send("DELETE", "/api/v1/sessions/"+session.SessionID, nil, operatorLogin.AccessToken).Code)
	roleResponse := send("POST", "/api/v1/rbac/roles", rbac.RoleInput{Name: "user manager", Permissions: []string{"users.manage"}}, adminLogin.AccessToken)
	require.Equal(t, 201, roleResponse.Code)
	var role rbac.Role
	require.NoError(t, json.Unmarshal(roleResponse.Body.Bytes(), &role))
	revision = bind([]string{role.ID}, revision)
	assert.Equal(t, 200, send("GET", "/api/v1/users", nil, operatorLogin.AccessToken).Code)
	assert.Equal(t, 403, send("POST", "/api/v1/users", map[string]string{"username": "evil.admin", "password": "synthetic-created-password", "role": "admin"}, operatorLogin.AccessToken).Code)
	assert.Equal(t, 201, send("POST", "/api/v1/users", map[string]string{"username": "new.operator", "password": "synthetic-created-password", "role": "operator"}, operatorLogin.AccessToken).Code)
	revision = bind([]string{}, revision)
	assert.Equal(t, 403, send("GET", "/api/v1/users", nil, operatorLogin.AccessToken).Code)
	assert.Equal(t, 404, send("GET", "/api/v1/ops/jobs/"+job.ID, nil, operatorLogin.AccessToken).Code)
	group, err := groupStore.Create("audit group", "")
	require.NoError(t, err)
	_, err = groupStore.AddMember(group.ID, operator.ID)
	require.NoError(t, err)
	groupBinding := send("PUT", "/api/v1/rbac/bindings", rbac.BindingInput{SubjectType: "group", SubjectID: group.ID, RoleIDs: []string{"auditor"}}, adminLogin.AccessToken)
	require.Equal(t, 200, groupBinding.Code, groupBinding.Body.String())
	assert.Equal(t, 200, send("GET", "/api/v1/ops/jobs/"+job.ID, nil, operatorLogin.AccessToken).Code)
	_, err = groupStore.RemoveMember(group.ID, operator.ID)
	require.NoError(t, err)
	assert.Equal(t, 404, send("GET", "/api/v1/ops/jobs/"+job.ID, nil, operatorLogin.AccessToken).Code)
	assert.Equal(t, 403, send("DELETE", "/api/v1/rbac/roles/auditor?revision=1", nil, adminLogin.AccessToken).Code)
	assert.Equal(t, 409, send("PUT", "/api/v1/rbac/bindings", rbac.BindingInput{SubjectType: "user", SubjectID: operator.ID, RoleIDs: []string{"auditor"}, Revision: revision - 1}, adminLogin.AccessToken).Code)
	audit := send("GET", "/api/v1/rbac/audit", nil, adminLogin.AccessToken)
	assert.Equal(t, 200, audit.Code)
	assert.Contains(t, audit.Body.String(), `"actor":"admin"`)
	assert.Equal(t, "private, no-store", audit.Header().Get("Cache-Control"))
}

func TestSystemPermissionRouteMappingIsExplicit(t *testing.T) {
	roles, err := rbac.Open(filepath.Join(t.TempDir(), "rbac.json"), nil)
	require.NoError(t, err)
	role, err := roles.SaveRole("", rbac.RoleInput{Name: "all", Permissions: rbac.Catalog()}, "a", "a")
	require.NoError(t, err)
	_, err = roles.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: "u", RoleIDs: []string{role.ID}}, "a", "a")
	require.NoError(t, err)
	user := coreauth.User{ID: "u", Role: coreauth.RoleOperator}
	for _, path := range []string{"/api/v1/rbac/roles", "/api/v1/users", "/api/v1/user-groups", "/api/v1/assets", "/api/v1/assets/nodes", "/api/v1/assets/a/probe", "/api/v1/assets/a/password-rotation", "/api/v1/assets/a/credential-backups", "/api/v1/settings/security/mfa", "/api/v1/grants", "/api/v1/command-filters", "/api/v1/command-reviews", "/api/v1/access-reviews", "/api/v1/ops/jobs/a/review"} {
		r := httptest.NewRequest("POST", path, nil)
		r = r.WithContext(context.WithValue(r.Context(), rbacPolicyKey{}, rbacPolicy{store: roles}))
		assert.True(t, adminAPIAllowed(r, user), path)
	}
	r := httptest.NewRequest("DELETE", "/api/v1/future-unmapped-resource", nil)
	r = r.WithContext(context.WithValue(r.Context(), rbacPolicyKey{}, rbacPolicy{store: roles}))
	assert.False(t, adminAPIAllowed(r, user))
}

func TestGlobalSSHRoleKeepsLoginAndCommandPoliciesAndScheduledRevocation(t *testing.T) {
	dir := t.TempDir()
	identities, err := coreauth.OpenService(filepath.Join(dir, "users.json"))
	require.NoError(t, err)
	_, err = identities.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, err)
	owner, err := identities.CreateUser("global.operator", "synthetic-global-operator-password", coreauth.RoleOperator)
	require.NoError(t, err)
	login, err := identities.Authenticate("global.operator", "synthetic-global-operator-password")
	require.NoError(t, err)
	roleStore, err := rbac.Open(filepath.Join(dir, "rbac.json"), nil)
	require.NoError(t, err)
	role, err := roleStore.SaveRole("", rbac.RoleInput{Name: "global SSH", Permissions: []string{"assets.connect_all"}}, "admin", "admin")
	require.NoError(t, err)
	binding, err := roleStore.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: owner.ID, RoleIDs: []string{role.ID}}, "admin", "admin")
	require.NoError(t, err)
	assets := testAssetService(t)
	required := true
	asset, err := assets.Create(coreassets.Input{Name: "qa", Host: "127.0.0.1", Port: 22, Username: "ops", Password: "synthetic-only", HostKeyFingerprint: validTestFingerprint(), LoginReviewRequired: &required})
	require.NoError(t, err)
	reviews, err := accessreviews.OpenStore(filepath.Join(dir, "reviews.json"))
	require.NoError(t, err)
	filters, err := commandfilters.OpenStore(filepath.Join(dir, "filters.json"))
	require.NoError(t, err)
	_, err = filters.Create(commandfilters.Input{Name: "blocked", UserID: owner.ID, AssetID: asset.ID, Account: "ops", Match: "exact", Pattern: "blocked", Action: "deny"}, "admin")
	require.NoError(t, err)
	var executions atomic.Int32
	js, err := jobs.Open(filepath.Join(dir, "jobs.json"), make([]byte, 32), nil, func(context.Context, string, string) (sshclient.ExecResult, error) {
		executions.Add(1)
		return sshclient.ExecResult{ExitCode: 0}, nil
	})
	require.NoError(t, err)
	defer js.Close()
	ops, err := operations.Open(filepath.Join(dir, "operations.json"), make([]byte, 32), nil, js)
	require.NoError(t, err)
	defer ops.Close()
	router := NewRouter("test", Dependencies{Auth: identities, Assets: assets, RBAC: roleStore, AccessReviews: reviews, CommandFilters: filters, Jobs: js, Operations: ops})
	submit := func(command, id string) *httptest.ResponseRecorder {
		raw, err := json.Marshal(jobs.Input{AssetID: asset.ID, Command: command, RequestID: id})
		require.NoError(t, err)
		return doJSONRequest(t, router, "POST", "/api/v1/ops/jobs", string(raw), login.AccessToken, "127.0.0.1:12345")
	}
	denied := submit("blocked", "blocked")
	require.Equal(t, 201, denied.Code, denied.Body.String())
	assert.Contains(t, denied.Body.String(), `"state":"denied"`)
	assert.Zero(t, executions.Load())
	pending := submit("whoami", "allowed")
	require.Equal(t, 202, pending.Code, pending.Body.String())
	var review struct {
		ID string `json:"review_id"`
	}
	require.NoError(t, json.Unmarshal(pending.Body.Bytes(), &review))
	require.NoError(t, reviews.Resolve(review.ID, "admin", true))
	allowed := submit("whoami", "allowed")
	require.Equal(t, 201, allowed.Code, allowed.Body.String())
	require.Eventually(t, func() bool { return executions.Load() == 1 }, time.Second, time.Millisecond)
	payload, err := json.Marshal(operations.PlanInput{Name: "role revoked before due", AssetIDs: []string{asset.ID}, Command: "whoami", Kind: "once", RunAt: time.Now().Add(time.Second), RequestID: "scheduled-role-revocation"})
	require.NoError(t, err)
	response := doJSONRequest(t, router, "POST", "/api/v1/ops/plans", string(payload), login.AccessToken, "127.0.0.1:12345")
	require.Equal(t, 201, response.Code, response.Body.String())
	var p operations.Plan
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &p))
	binding.RoleIDs = []string{}
	_, err = roleStore.SaveBinding(binding.BindingInput, "admin", "admin")
	require.NoError(t, err)
	assert.Equal(t, 403, submit("whoami", "after-revocation").Code)
	require.Eventually(t, func() bool {
		current, _ := ops.Plan(p.ID)
		run, _ := ops.Run(current.LastRunID)
		return run.State == "failed" && len(run.Items) == 1 && run.Items[0].ErrorCode == "access_denied"
	}, 4*time.Second, 10*time.Millisecond)
	assert.EqualValues(t, 1, executions.Load())
}
