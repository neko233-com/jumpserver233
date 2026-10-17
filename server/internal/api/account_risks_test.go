package api

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/core/accountrisks"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func riskAPIEnv(t *testing.T) *policyTestEnv {
	t.Helper()
	e := newPolicyEnv(t)
	var err error
	e.d.AccountRisks, err = accountrisks.Open(filepath.Join(t.TempDir(), "risks.json"), make([]byte, 32), nil)
	require.NoError(t, err)
	t.Cleanup(e.d.AccountRisks.Close)
	e.router = NewRouter("test", e.d)
	account, err := e.d.Assets.ManagedAccount(e.asset.ID, e.asset.ID)
	require.NoError(t, err)
	_, err = e.d.Assets.UpdateManagedAccount(e.asset.ID, e.asset.ID, assets.AccountInput{Password: "admin123", Version: account.Version}, assets.AccountActor{ID: e.admin.ID, Name: e.admin.Username})
	require.NoError(t, err)
	return e
}
func riskAPIScan(t *testing.T, e *policyTestEnv, id string) accountrisks.Scan {
	t.Helper()
	r := e.send(t, "POST", "/api/v1/accounts/risks/scans", map[string]any{"revision": e.d.AccountRisks.Policy().Revision, "request_id": id}, e.adminToken, "192.0.2.3:4000")
	require.Equal(t, 201, r.Code, r.Body.String())
	var s accountrisks.Scan
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &s))
	require.Equal(t, "succeeded", s.State)
	return s
}
func TestAccountRisksAPIScopedVisibilityIndependentAuthorityAndCSVInjectionProtection(t *testing.T) {
	e := riskAPIEnv(t)
	other, err := e.d.Assets.Create(assets.Input{Name: "=HYPERLINK(\"example.invalid\")", Host: "192.0.2.91", Port: 22, Username: "other", Password: "admin123", HostKeyFingerprint: validTestFingerprint()})
	require.NoError(t, err)
	roles, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "risk viewer", Permissions: []string{"accounts.risks.view"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{roles.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 403, e.send(t, "POST", "/api/v1/accounts/risks/scans", map[string]any{"revision": 1, "request_id": "denied"}, e.token, "192.0.2.3:4000").Code)
	scan := riskAPIScan(t, e, "scoped-risks")
	r := e.send(t, "GET", "/api/v1/accounts/risks?limit=100", nil, e.token, "192.0.2.3:4000")
	require.Equal(t, 200, r.Code)
	var page accountrisks.Page
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &page))
	require.Len(t, page.Results, 1)
	assert.Equal(t, "weak_password", page.Results[0].Kind)
	assert.NotContains(t, r.Body.String(), other.ID)
	assert.NotContains(t, r.Body.String(), "admin123")
	assert.NotContains(t, r.Body.String(), "group_id")
	assert.Equal(t, 403, e.send(t, "GET", "/api/v1/accounts/risks/export", nil, e.token, "192.0.2.3:4000").Code)
	assert.Equal(t, 403, e.send(t, "GET", "/api/v1/accounts/risks/scans", nil, e.token, "192.0.2.3:4000").Code)
	_, err = e.d.Grants.Create(grants.Input{UserID: e.operator.ID, AssetID: other.ID, Account: other.Username, Actions: []string{"view"}}, "admin")
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveRole(roles.ID, rbac.RoleInput{Name: roles.Name, Revision: roles.Revision, Permissions: []string{"accounts.risks.view", "accounts.risks.export"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	r = e.send(t, "GET", "/api/v1/accounts/risks?kind=duplicate_password", nil, e.token, "192.0.2.3:4000")
	require.Equal(t, 200, r.Code)
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &page))
	assert.Len(t, page.Results, 2)
	r = e.send(t, "GET", "/api/v1/accounts/risks/export", nil, e.token, "192.0.2.3:4000")
	require.Equal(t, 200, r.Code)
	assert.Contains(t, r.Body.String(), "'=HYPERLINK")
	assert.NotContains(t, r.Body.String(), "admin123")
	assert.Contains(t, r.Header().Get("Cache-Control"), "no-store")
	again := riskAPIScan(t, e, "scoped-risks")
	assert.Equal(t, scan.ID, again.ID)
}
func TestAccountRiskReviewRejectsChangedSourceAndScanOwnerRevocation(t *testing.T) {
	e := riskAPIEnv(t)
	riskAPIScan(t, e, "review-risk")
	r := e.send(t, "GET", "/api/v1/accounts/risks", nil, e.adminToken, "192.0.2.3:4000")
	var page accountrisks.Page
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &page))
	require.Len(t, page.Results, 1)
	f := page.Results[0]
	_, err := e.d.Assets.UpdateManagedAccount(e.asset.ID, e.asset.ID, assets.AccountInput{Password: "synthetic-risk-remediated-password", Version: f.SourceVersion}, assets.AccountActor{ID: e.admin.ID, Name: e.admin.Username})
	require.NoError(t, err)
	assert.Equal(t, 409, e.send(t, "POST", "/api/v1/accounts/risks/"+f.ID+"/review", map[string]any{"revision": f.Revision, "action": "ignore", "note": ""}, e.adminToken, "192.0.2.3:4000").Code)
	riskAPIScan(t, e, "resolved-risk")
	r = e.send(t, "GET", "/api/v1/accounts/risks?state=resolved", nil, e.adminToken, "192.0.2.3:4000")
	assert.Contains(t, r.Body.String(), f.ID)
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "risk scanner", Permissions: []string{"accounts.risks.view", "accounts.risks.scan", "accounts.risks.manage", "assets.manage"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	binding, err := e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	p := e.d.AccountRisks.Policy()
	p.Enabled = true
	r = e.send(t, "PUT", "/api/v1/accounts/risks/policy", p, e.token, "192.0.2.3:4000")
	require.Equal(t, 200, r.Code, r.Body.String())
	p = e.d.AccountRisks.Policy()
	assert.Equal(t, e.operator.ID, p.Owner.ID)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, Revision: binding.Revision}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.AccountRisks.Scan(context.Background(), accountrisks.Actor{ID: e.operator.ID, Name: e.operator.Username}, "revoked-schedule", p.Revision, true)
	assert.ErrorIs(t, err, accountrisks.ErrDenied)
}
