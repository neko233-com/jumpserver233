package api

import (
	"encoding/json"
	"path/filepath"
	"testing"

	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/core/sessionpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionSecurityAPIRequiresPermissionAndPreservesRevision(t *testing.T) {
	dir := t.TempDir()
	auth, e := coreauth.OpenService(filepath.Join(dir, "users.json"))
	require.NoError(t, e)
	_, e = auth.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, e)
	u, e := auth.CreateUser("policy-operator", "synthetic-session-policy-233", coreauth.RoleOperator)
	require.NoError(t, e)
	login, e := auth.Authenticate(u.Username, "synthetic-session-policy-233")
	require.NoError(t, e)
	admin, e := auth.Authenticate("admin", bootstrapPassword)
	require.NoError(t, e)
	roles, e := rbac.Open(filepath.Join(dir, "roles.json"), nil)
	require.NoError(t, e)
	store, e := sessionpolicy.Open(filepath.Join(dir, "policy.json"), nil)
	require.NoError(t, e)
	router := NewRouter("test", Dependencies{Auth: auth, RBAC: roles, SessionPolicy: store})
	const path = "/api/v1/settings/security/sessions"
	for _, method := range []string{"GET", "PUT"} {
		r := doJSONRequest(t, router, method, path, `{"idle_minutes":1,"max_hours":1,"watermark":true,"revision":1}`, login.AccessToken, "192.0.2.1:1234")
		assert.Equal(t, 403, r.Code)
	}
	policy := store.Snapshot()
	raw, e := json.Marshal(policy)
	require.NoError(t, e)
	r := doJSONRequest(t, router, "PUT", path, string(raw), admin.AccessToken, "192.0.2.1:1234")
	require.Equal(t, 200, r.Code)
	r = doJSONRequest(t, router, "PUT", path, string(raw), admin.AccessToken, "192.0.2.1:1234")
	assert.Equal(t, 409, r.Code)
	role, e := roles.SaveRole("", rbac.RoleInput{Name: "session-security-admin", Permissions: []string{"security.manage"}}, "admin", "admin")
	require.NoError(t, e)
	_, e = roles.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: u.ID, RoleIDs: []string{role.ID}}, "admin", "admin")
	require.NoError(t, e)
	r = doJSONRequest(t, router, "GET", path+"/audit", "", login.AccessToken, "192.0.2.1:1234")
	require.Equal(t, 200, r.Code)
	assert.Contains(t, r.Body.String(), `"actor":"admin"`)
	r = doJSONRequest(t, router, "PUT", path, `{"idle_minutes":-1,"max_hours":1,"watermark":true,"revision":2}`, login.AccessToken, "192.0.2.1:1234")
	assert.Equal(t, 400, r.Code)
	assert.Equal(t, 2, store.Snapshot().Revision)
}
