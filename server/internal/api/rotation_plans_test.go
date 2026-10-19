package api

import (
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/credentialpolicy"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/core/rotationplans"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
	"time"
)

func rotationAPIEnv(t *testing.T) *policyTestEnv {
	e := newPolicyEnv(t)
	var err error
	e.d.RotationPlans, err = rotationplans.Open(filepath.Join(t.TempDir(), "plans.json"), make([]byte, 32), nil)
	require.NoError(t, err)
	t.Cleanup(e.d.RotationPlans.Close)
	c, err := assets.OpenPasswordCoordinator(filepath.Join(t.TempDir(), "shared.json"), make([]byte, 32), nil)
	require.NoError(t, err)
	require.NoError(t, e.d.Assets.CoordinatePasswords(c, "default"))
	e.router = NewRouter("test", e.d)
	return e
}
func TestRotationPlanAPIAuthorityCASMetadataAndLiveRevocation(t *testing.T) {
	e := rotationAPIEnv(t)
	_, err := e.d.Assets.Update(e.asset.ID, assets.Input{Name: "=HYPERLINK(\"example.invalid\")", Host: e.asset.Host, Port: e.asset.Port, Username: e.asset.Username, HostKeyFingerprint: e.asset.HostKeyFingerprint})
	require.NoError(t, err)
	send := func(method, path string, in any, token string) int {
		return e.send(t, method, path, in, token, "192.0.2.3:4000").Code
	}
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "rotation operator", Permissions: []string{"accounts.rotation.view", "accounts.rotation.manage", "accounts.rotation.execute", "assets.rotate"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 403, send("GET", "/api/v1/accounts/rotation-targets", nil, e.token))
	role, err = e.d.RBAC.SaveRole(role.ID, rbac.RoleInput{Name: role.Name, Revision: role.Revision, Permissions: append(role.Permissions, "assets.view_all")}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	rules := credentialpolicy.Defaults()
	rules.MinLength = 56
	rules.MinDigits = 8
	input := rotationplans.PlanInput{PasswordPolicy: rules, Name: "=Synthetic rotation plan", Kind: "manual", Targets: []rotationplans.Selection{{AccountID: e.asset.ID}}}
	created := e.send(t, "POST", "/api/v1/accounts/rotation-plans", input, e.token, "192.0.2.3:4000")
	require.Equal(t, 201, created.Code, created.Body.String())
	assert.NotContains(t, created.Body.String(), "synthetic-private-password")
	assert.NotContains(t, created.Body.String(), "Binding")
	var plan rotationplans.Plan
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &plan))
	assert.Equal(t, "192.0.2.3", plan.AccessOrigin.SourceIP)
	assert.Equal(t, "credential_rotation", plan.AccessOrigin.Method)
	assert.Equal(t, 1, plan.TargetCount)
	assert.Equal(t, rules, plan.PasswordPolicy)
	assert.Equal(t, 409, send("PUT", "/api/v1/accounts/rotation-plans/"+plan.ID, input, e.token))
	assert.Equal(t, 400, send("POST", "/api/v1/accounts/rotation-plans", map[string]any{"access_origin": map[string]string{"source_ip": "127.0.0.1"}}, e.token))
	row := e.send(t, "POST", "/api/v1/accounts/rotation-plans/"+plan.ID+"/runs", map[string]string{"request_id": "rotation-api-revoked"}, e.token, "192.0.2.3:4000")
	require.Equal(t, 202, row.Code, row.Body.String())
	var run rotationplans.Run
	require.NoError(t, json.Unmarshal(row.Body.Bytes(), &run))
	assert.Equal(t, rules, run.PasswordPolicy)
	retry := e.send(t, "POST", "/api/v1/accounts/rotation-plans/"+plan.ID+"/runs", map[string]string{"request_id": "rotation-api-revoked"}, e.token, "198.51.100.3:4000")
	require.Equal(t, 202, retry.Code)
	assert.Contains(t, retry.Body.String(), run.ID)
	assert.Equal(t, 409, send("DELETE", "/api/v1/accounts/rotation-plans/"+plan.ID+"?revision=1", nil, e.token))
	_, err = e.d.RBAC.SaveRole(role.ID, rbac.RoleInput{Name: role.Name, Revision: role.Revision, Permissions: []string{"accounts.rotation.view", "accounts.rotation.manage", "assets.view_all"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	e.d.RotationPlans.Tick()
	require.Eventually(t, func() bool { r, err := e.d.RotationPlans.Run(run.ID); return err == nil && r.State == "failed" }, time.Second, 5*time.Millisecond)
	completed, err := e.d.RotationPlans.Run(run.ID)
	require.NoError(t, err)
	assert.Equal(t, "denied", completed.Items[0].State)
	assert.Equal(t, 403, send("POST", "/api/v1/accounts/rotation-plans/"+plan.ID+"/runs", map[string]string{"request_id": "rotation-api-revoked"}, e.token))
	csv := e.send(t, "GET", "/api/v1/accounts/rotation-runs/"+run.ID+"/export", nil, e.token, "192.0.2.3:4000")
	require.Equal(t, 200, csv.Code)
	assert.Contains(t, csv.Header().Get("Cache-Control"), "no-store")
	assert.NotContains(t, csv.Body.String(), "synthetic-private-password")
	assert.Contains(t, csv.Body.String(), "'=HYPERLINK")
	assert.Equal(t, 204, send("DELETE", "/api/v1/accounts/rotation-plans/"+plan.ID+"?revision=1", nil, e.token))
	assert.Equal(t, 200, send("GET", "/api/v1/accounts/rotation-runs/"+run.ID, nil, e.token))
}
func TestCredentialMutationPoliciesCoverNativePasswordKeyAndRestoreRoutes(t *testing.T) {
	e := rotationAPIEnv(t)
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "credential admin", Permissions: []string{"assets.rotate", "assets.backups", "assets.view_all", "accounts.rotation.view", "accounts.rotation.manage", "accounts.rotation.execute"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	e.rule(t, accesspolicies.Method, "credential_rotation", "192.0.2.0/24")
	for _, path := range []string{"/password-rotation", "/ssh-key-rotation", "/credential-backups/backup-test/restore"} {
		r := e.send(t, "POST", "/api/v1/assets/"+e.asset.ID+path, nil, e.token, "192.0.2.3:4000")
		assert.Equal(t, 403, r.Code, r.Body.String())
	}
	collector, err := e.d.Assets.Create(assets.Input{Name: "root collector", Host: e.asset.Host, Port: e.asset.Port, Username: "root", Password: "synthetic-collector-fixture", HostKeyFingerprint: e.asset.HostKeyFingerprint})
	require.NoError(t, err)
	input := rotationplans.PlanInput{Name: "privileged", Kind: "manual", Targets: []rotationplans.Selection{{AccountID: e.asset.ID, CollectorID: collector.ID}}}
	r := e.send(t, "POST", "/api/v1/accounts/rotation-plans", input, e.token, "192.0.2.3:4000")
	require.Equal(t, 201, r.Code, r.Body.String())
	var plan rotationplans.Plan
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &plan))
	r = e.send(t, "POST", "/api/v1/accounts/rotation-plans/"+plan.ID+"/runs", map[string]string{"request_id": "collector-denied"}, e.token, "192.0.2.3:4000")
	assert.Equal(t, 403, r.Code)
}
