package api

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func importAPIInput(t *testing.T, e *policyTestEnv, id string) accountImportRequest {
	t.Helper()
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	require.NoError(t, w.Write([]string{"action", "asset_id", "username", "password"}))
	require.NoError(t, w.Write([]string{"create", e.asset.ID, "importqa_user", "synthetic-import-secret"}))
	w.Flush()
	return accountImportRequest{Format: "csv", Content: b.Bytes(), RequestID: id}
}

func TestAccountImportAPIRechecksTargetGrantsAndIndependentRotationPermission(t *testing.T) {
	e := newPolicyEnv(t)
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "limited importer", Permissions: []string{"accounts.manage", "accounts.import"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	path := "/api/v1/accounts/imports"
	in := importAPIInput(t, e, "revoked-target-import")
	r := e.send(t, "POST", path+"/preview", in, e.token, "192.0.2.3:4000")
	require.Equal(t, 200, r.Code)
	var p assets.AccountImportPreview
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &p))
	require.NotEmpty(t, p.Token)
	in.PreviewToken = p.Token
	for _, grant := range e.d.Grants.List() {
		require.NoError(t, e.d.Grants.Delete(grant.ID))
	}
	assert.Equal(t, 403, e.send(t, "POST", path, in, e.token, "192.0.2.3:4000").Code)
	accounts, err := e.d.Assets.ManagedAccounts(e.asset.ID)
	require.NoError(t, err)
	assert.Len(t, accounts, 1)
	in = importAPIInput(t, e, "rotation-denied-import")
	in.Content = []byte(strings.Replace(string(in.Content), "username,password", "username,password,password_rotation_enabled", 1))
	in.Content = []byte(strings.TrimSpace(string(in.Content)) + ",false\n")
	r = e.send(t, "POST", path+"/preview", in, e.adminToken, "192.0.2.3:4000")
	require.Equal(t, 200, r.Code)
	// Restore target access, then isolate the separate rotation authority.
	_, err = e.d.Grants.Create(grants.Input{UserID: e.operator.ID, AssetID: e.asset.ID, Account: "ops", Actions: []string{"view"}}, "admin")
	require.NoError(t, err)
	r = e.send(t, "POST", path+"/preview", in, e.token, "192.0.2.3:4000")
	require.Equal(t, 200, r.Code)
	assert.Contains(t, r.Body.String(), "rotation_denied")
	assert.NotContains(t, r.Body.String(), "preview_token")
}
func TestAccountImportAPIRequiresIndependentPermissionAndCurrentAuthorityAtCommit(t *testing.T) {
	e := newPolicyEnv(t)
	in := importAPIInput(t, e, "api-import-001")
	path := "/api/v1/accounts/imports"
	require.Equal(t, 403, e.send(t, "POST", path+"/preview", in, e.token, "192.0.2.3:4000").Code)
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "account importer", Permissions: []string{"accounts.manage", "accounts.import"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	binding, err := e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	r := e.send(t, "POST", path+"/preview", in, e.token, "192.0.2.3:4000")
	require.Equal(t, 200, r.Code, r.Body.String())
	var p assets.AccountImportPreview
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &p))
	require.Empty(t, p.Issues)
	require.NotEmpty(t, p.Token)
	assert.NotContains(t, r.Body.String(), "synthetic-import-secret")
	in.PreviewToken = p.Token
	binding, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, Revision: binding.Revision}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 403, e.send(t, "POST", path, in, e.token, "192.0.2.3:4000").Code)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}, Revision: binding.Revision}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	r = e.send(t, "POST", path, in, e.token, "192.0.2.3:4000")
	require.Equal(t, 201, r.Code, r.Body.String())
	assert.NotContains(t, r.Body.String(), "synthetic-import-secret")
	var receipt assets.AccountImportReceipt
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &receipt))
	require.Len(t, receipt.Rows, 1)
	first := r.Body.String()
	assert.Equal(t, first, e.send(t, "POST", path, in, e.token, "192.0.2.3:4000").Body.String())
	r = e.send(t, "GET", path+"?limit=1", nil, e.token, "192.0.2.3:4000")
	assert.Equal(t, 200, r.Code)
	assert.Contains(t, r.Body.String(), `"total":1`)
	assert.NotContains(t, r.Body.String(), "importqa_user", "history summaries do not eagerly return all rows")
	r = e.send(t, "GET", path+"/"+in.RequestID, nil, e.token, "192.0.2.3:4000")
	assert.Equal(t, 200, r.Code)
	assert.Contains(t, r.Body.String(), receipt.Rows[0].AccountID)
	assert.Equal(t, 200, e.send(t, "GET", path+"/template?format=xlsx", nil, e.token, "192.0.2.3:4000").Code)
	assert.Equal(t, 400, e.send(t, "GET", path+"?limit=101", nil, e.token, "192.0.2.3:4000").Code)
}
func TestAccountImportAPIInvalidAndUnauthorizedTargetsNeverEchoCredentialCells(t *testing.T) {
	e := newPolicyEnv(t)
	path := "/api/v1/accounts/imports"
	in := importAPIInput(t, e, "api-hidden-import")
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	require.NoError(t, w.Write([]string{"action", "asset_id", "username", "password"}))
	require.NoError(t, w.Write([]string{"create", "unknown-private-target", "name", "synthetic-hidden-secret"}))
	w.Flush()
	in.Content = b.Bytes()
	r := e.send(t, "POST", path+"/preview", in, e.adminToken, "192.0.2.3:4000")
	require.Equal(t, 200, r.Code)
	assert.Contains(t, r.Body.String(), "asset_unavailable")
	assert.NotContains(t, r.Body.String(), "unknown-private-target")
	assert.NotContains(t, r.Body.String(), "synthetic-hidden-secret")
	in.Content = []byte("invalid,password\nvalue,synthetic-hidden-secret")
	r = e.send(t, "POST", path+"/preview", in, e.adminToken, "192.0.2.3:4000")
	assert.Equal(t, 200, r.Code)
	assert.NotContains(t, r.Body.String(), "synthetic-hidden-secret")
	assert.NotContains(t, r.Body.String(), "preview_token")
	in = importAPIInput(t, e, "other-owner-import")
	r = e.send(t, "POST", path+"/preview", in, e.adminToken, "192.0.2.3:4000")
	var p assets.AccountImportPreview
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &p))
	in.PreviewToken = p.Token
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "importer", Permissions: []string{"accounts.manage", "accounts.import"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 409, e.send(t, "POST", path, in, e.token, "192.0.2.3:4000").Code)
}
