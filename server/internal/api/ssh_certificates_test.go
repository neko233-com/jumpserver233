package api

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/core/sshcertificates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSHCertificateAPIRevisionsIndependentPermissionsAndCurrentTargetAuthority(t *testing.T) {
	e := newPolicyEnv(t)
	var err error
	e.d.SSHCertificates, err = sshcertificates.Open(filepath.Join(t.TempDir(), "ssh-certificates.json"), make([]byte, 32), nil)
	require.NoError(t, err)
	t.Cleanup(e.d.SSHCertificates.Close)
	e.d.Assets.SetSSHCertificates(e.d.SSHCertificates)
	e.router = NewRouter("test", e.d)
	ip := "127.0.0.1:12345"
	base := "/api/v1/settings/ssh-certificates"
	in := sshcertificates.Input{Name: "API CA", Provider: "builtin", Enabled: true, RequestID: "api-create-ca-001"}
	assert.Equal(t, 403, e.send(t, "POST", base+"/issuers", in, e.token, ip).Code)
	created := e.send(t, "POST", base+"/issuers", in, e.adminToken, ip)
	require.Equal(t, 201, created.Code, created.Body.String())
	var issuer sshcertificates.Issuer
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &issuer))
	assert.NotContains(t, created.Body.String(), "private_key")
	replay := e.send(t, "POST", base+"/issuers", in, e.adminToken, ip)
	assert.JSONEq(t, created.Body.String(), replay.Body.String())
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "Read issuers and request assignment", Permissions: []string{"ssh_certificates.view", "ssh_certificates.assign"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	path := base + "/bindings/" + e.asset.ID
	bind := sshcertificates.BindingInput{IssuerID: issuer.ID, RequestID: "api-bind-ca-001"}
	assert.Equal(t, 404, e.send(t, "PUT", path, bind, e.token, ip).Code)
	assert.Equal(t, 200, e.send(t, "GET", base+"/issuers", nil, e.token, ip).Code)
	assert.Equal(t, 403, e.send(t, "GET", base+"/audit", nil, e.token, ip).Code)
	binding := e.send(t, "PUT", path, bind, e.adminToken, ip)
	require.Equal(t, 200, binding.Code, binding.Body.String())
	again := e.send(t, "PUT", path, bind, e.adminToken, ip)
	assert.JSONEq(t, binding.Body.String(), again.Body.String())
	assert.Equal(t, 409, e.send(t, "DELETE", base+"/issuers/"+issuer.ID, map[string]any{"revision": 1, "request_id": "api-delete-ca-001"}, e.adminToken, ip).Code)
	for _, g := range e.d.Grants.List() {
		require.NoError(t, e.d.Grants.Delete(g.ID))
	}
	assert.Equal(t, 404, e.send(t, "GET", path, nil, e.token, ip).Code)
	malformed := e.send(t, "PUT", path, map[string]any{"issuer_id": issuer.ID, "revision": 1, "request_id": "api-forged-ca-001", "private_key": "forged"}, e.adminToken, ip)
	assert.Equal(t, 400, malformed.Code)
	assert.Zero(t, e.opens.Load())
	assert.Zero(t, e.execs.Load())
	assert.Contains(t, rbac.OrganizationCatalog(), "ssh_certificates.manage")
}
