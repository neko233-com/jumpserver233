package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/core/reporting"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
	"time"
)

func reportEnv(t *testing.T) *policyTestEnv {
	t.Helper()
	e := loginAuditEnv(t)
	_, grantError := e.d.Grants.Create(grants.Input{UserID: e.operator.ID, AssetID: e.asset.ID, Account: e.asset.Username, Actions: []string{"view", "connect", "sftp"}}, e.admin.Username)
	require.NoError(t, grantError)
	var err error
	e.d.Reports, err = reporting.Open(filepath.Join(t.TempDir(), "exports.json"), make([]byte, 32), nil)
	require.NoError(t, err)
	t.Cleanup(e.d.Reports.Close)
	e.router = NewRouter("test", e.d)
	return e
}
func reportSource(t *testing.T, e *policyTestEnv, path, token string) reporting.Stats {
	t.Helper()
	r := e.send(t, "GET", path, nil, token, "192.0.2.5:4567")
	require.Equal(t, 200, r.Code, r.Body.String())
	var out reporting.Report
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &out))
	require.Len(t, out.Sources, 1)
	assert.NotContains(t, r.Body.String(), "synthetic-private-password")
	assert.NotContains(t, r.Body.String(), "policy-ok")
	return out.Sources[0]
}
func TestReportsUseCurrentOwnershipAndNeverExposePayload(t *testing.T) {
	e := reportEnv(t)
	for _, u := range []struct{ id, name string }{{e.operator.ID, e.operator.Username}, {e.admin.ID, e.admin.Username}} {
		_, err := e.d.Jobs.Submit(jobs.Input{AssetID: e.asset.ID, Command: "echo synthetic-secret-command", TimeoutSeconds: 5, RequestID: u.id}, u.id, u.name, e.asset.Name, e.asset.Username, "allow", "")
		require.NoError(t, err)
	}
	require.Eventually(t, func() bool { return e.execs.Load() == 2 }, 2*time.Second, 10*time.Millisecond)
	own := reportSource(t, e, "/api/v1/reports/overview?sources=ssh_jobs", e.token)
	require.NotNil(t, own.Matched)
	assert.Equal(t, 1, *own.Matched)
	assert.Equal(t, "mine", own.Scope)
	admin := reportSource(t, e, "/api/v1/reports/overview?sources=ssh_jobs", e.adminToken)
	assert.Equal(t, 2, *admin.Matched)
	assert.Equal(t, "all", admin.Scope)
	assert.Equal(t, 403, e.send(t, "GET", "/api/v1/reports/export.csv?sources=ssh_jobs", nil, e.token, "192.0.2.5:4567").Code)
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "report exporter", Permissions: []string{"reports.export"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	exported := e.send(t, "GET", "/api/v1/reports/export.csv?sources=ssh_jobs", nil, e.token, "192.0.2.5:4567")
	require.Equal(t, 200, exported.Code)
	assert.NotContains(t, exported.Body.String(), "synthetic-secret-command")
	sum := sha256.Sum256(exported.Body.Bytes())
	assert.Equal(t, hex.EncodeToString(sum[:]), exported.Header().Get("X-JMS-Report-SHA256"))
	receipts, n, err := e.d.Reports.List(e.operator.ID, false, 0, 100)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	assert.Equal(t, exported.Header().Get("X-JMS-Report-ID"), receipts[0].ID)
	_, err = e.d.RBAC.SaveRole(role.ID, rbac.RoleInput{Name: role.Name, Revision: role.Revision, Permissions: []string{}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 403, e.send(t, "GET", "/api/v1/reports/export.csv?sources=ssh_jobs", nil, e.token, "192.0.2.5:4567").Code)
}
func TestReportPartialExportRequiresConsentAndAuditBeforeDownload(t *testing.T) {
	e := reportEnv(t)
	query := "/api/v1/reports/export.csv?sources=rdp_sessions"
	denied := e.send(t, "GET", query, nil, e.adminToken, "192.0.2.5:4567")
	assert.Equal(t, 409, denied.Code)
	ok := e.send(t, "GET", query+"&allow_partial=true", nil, e.adminToken, "192.0.2.5:4567")
	require.Equal(t, 200, ok.Code)
	assert.Contains(t, ok.Body.String(), "unavailable")
	e.d.Reports.Close()
	failed := e.send(t, "GET", "/api/v1/reports/export.csv?sources=assets", nil, e.adminToken, "192.0.2.5:4567")
	assert.Equal(t, 503, failed.Code)
	assert.NotContains(t, failed.Body.String(), "version,generated_at")
}
func TestReportInventoryVisibilityAndGlobalScopeAreExplicit(t *testing.T) {
	e := reportEnv(t)
	own := reportSource(t, e, "/api/v1/reports/overview?sources=assets", e.token)
	require.NotNil(t, own.Matched)
	assert.Equal(t, 1, *own.Matched)
	global := reportSource(t, e, "/api/v1/reports/overview?sources=platform_users&include_platform=true", e.token)
	assert.Equal(t, "platform_mine", global.Scope)
	assert.Equal(t, 1, *global.Matched)
	assert.Equal(t, 400, e.send(t, "GET", "/api/v1/reports/overview?sources=platform_users", nil, e.token, "192.0.2.5:4567").Code)
	for _, g := range e.d.Grants.List() {
		require.NoError(t, e.d.Grants.Delete(g.ID))
	}
	own = reportSource(t, e, "/api/v1/reports/overview?sources=assets", e.token)
	assert.Equal(t, 0, *own.Matched)
}
