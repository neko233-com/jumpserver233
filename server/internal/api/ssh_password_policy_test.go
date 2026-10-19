package api

import (
	"github.com/neko233-com/jumpserver233/server/internal/core/credentialpolicy"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
)

func TestSSHPasswordPolicyAPIPermissionsReplayAndRevocation(t *testing.T) {
	env := newPolicyEnv(t)
	store, e := credentialpolicy.Open(filepath.Join(t.TempDir(), "policy.json"), make([]byte, 32), nil)
	require.NoError(t, e)
	env.d.SSHPasswordPolicy = store
	env.router = NewRouter("test", env.d)
	send := func(method string, in any, token string) int {
		return env.send(t, method, sshPasswordPolicyPath, in, token, "192.0.2.3:4000").Code
	}
	assert.Equal(t, 200, send("GET", nil, env.adminToken))
	assert.Equal(t, 403, send("GET", nil, env.token))
	p := store.Snapshot()
	p.MinUpper = 3
	in := credentialpolicy.Input{RequestID: "api-policy", Policy: p}
	assert.Equal(t, 403, send("PUT", in, env.token))
	assert.Equal(t, 200, send("PUT", in, env.adminToken))
	assert.Equal(t, 200, send("PUT", in, env.adminToken))
	assert.Len(t, store.Audit(), 1)
	in.RequestID = "stale-policy"
	assert.Equal(t, 409, send("PUT", in, env.adminToken))
	role, e := env.d.RBAC.SaveRole("", rbac.RoleInput{Name: "policy manager", Permissions: []string{"accounts.password_policy.view", "accounts.password_policy.manage"}}, env.admin.ID, env.admin.Username)
	require.NoError(t, e)
	binding, e := env.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: env.operator.ID, RoleIDs: []string{role.ID}}, env.admin.ID, env.admin.Username)
	require.NoError(t, e)
	assert.Equal(t, 200, send("GET", nil, env.token))
	in.Policy = store.Snapshot()
	in.Policy.MinDigits = 4
	in.RequestID = "delegated-policy"
	assert.Equal(t, 200, send("PUT", in, env.token))
	_, e = env.d.RBAC.SaveRole(role.ID, rbac.RoleInput{Name: role.Name, Revision: role.Revision, Permissions: []string{"accounts.password_policy.view"}}, env.admin.ID, env.admin.Username)
	require.NoError(t, e)
	_ = binding
	in.Policy = store.Snapshot()
	in.RequestID = "revoked-policy"
	assert.Equal(t, 403, send("PUT", in, env.token))
}
