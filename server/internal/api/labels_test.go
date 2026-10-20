package api

import (
	"encoding/json"
	"path/filepath"
	"testing"

	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/neko233-com/jumpserver233/server/internal/core/labels"
	corenodes "github.com/neko233-com/jumpserver233/server/internal/core/nodes"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func labelAPIEnv(t *testing.T) *policyTestEnv {
	t.Helper()
	e := newPolicyEnv(t)
	var err error
	e.d.Labels, err = labels.Open(filepath.Join(t.TempDir(), "labels.json"), make([]byte, 32), nil)
	require.NoError(t, err)
	t.Cleanup(e.d.Labels.Close)
	e.d.Nodes, err = corenodes.OpenStore(filepath.Join(t.TempDir(), "nodes.json"))
	require.NoError(t, err)
	e.router = NewRouter("test", e.d)
	return e
}

func TestLabelAPIRequiresIndependentPermissionsAndRechecksVisibilityOnReplay(t *testing.T) {
	e := labelAPIEnv(t)
	ip := "127.0.0.1:12345"
	input := labels.Input{Name: "Team", Value: "Ops", RequestID: "api-label-001"}
	assert.Equal(t, 403, e.send(t, "POST", "/api/v1/labels/labels", input, e.token, ip).Code)
	created := e.send(t, "POST", "/api/v1/labels/labels/", input, e.adminToken, ip)
	require.Equal(t, 201, created.Code, created.Body.String())
	var l labels.Label
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &l))
	replay := e.send(t, "POST", "/api/v1/labels/labels", input, e.adminToken, ip)
	require.Equal(t, 201, replay.Code)
	assert.JSONEq(t, created.Body.String(), replay.Body.String())
	path := "/api/v1/labels/bindings/asset/" + e.asset.ID
	bind := labels.BindingInput{LabelIDs: []string{l.ID}, RequestID: "api-bind-001"}
	assert.Equal(t, 404, e.send(t, "PUT", path, bind, e.token, ip).Code)
	assert.Equal(t, 403, e.send(t, "GET", "/api/v1/labels/audit", nil, e.token, ip).Code)
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "Tag visible hosts", Permissions: []string{"labels.assign"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	written := e.send(t, "PUT", path, bind, e.token, ip)
	require.Equal(t, 200, written.Code, written.Body.String())
	var binding labels.Binding
	require.NoError(t, json.Unmarshal(written.Body.Bytes(), &binding))
	assert.Equal(t, 1, binding.Revision)
	replay = e.send(t, "PUT", path, bind, e.token, ip)
	require.Equal(t, 200, replay.Code)
	assert.JSONEq(t, written.Body.String(), replay.Body.String())
	invalid := map[string]any{"label_ids": []string{l.ID}, "revision": 1, "request_id": "forged-bind-001", "actor_id": "forged"}
	assert.Equal(t, 400, e.send(t, "PUT", path, invalid, e.token, ip).Code)
	assert.Equal(t, 200, e.send(t, "GET", "/api/v1/labels/choices", nil, e.token, ip).Code)
	for _, g := range e.d.Grants.List() {
		require.NoError(t, e.d.Grants.Delete(g.ID))
	}
	// Idempotency cannot bypass current resource authorization after revocation.
	assert.Equal(t, 404, e.send(t, "PUT", path, bind, e.token, ip).Code)
	assert.Equal(t, 404, e.send(t, "GET", path, nil, e.token, ip).Code)
	hidden := e.send(t, "GET", "/api/v1/assets?label="+l.ID, nil, e.token, ip)
	require.Equal(t, 200, hidden.Code)
	assert.JSONEq(t, "[]", hidden.Body.String())
	require.Zero(t, e.opens.Load())
	require.Zero(t, e.execs.Load())
}

func TestLabelAPIInheritsNodesFiltersAfterAuthorizationAndCanonicalizesManagedAccounts(t *testing.T) {
	e := labelAPIEnv(t)
	ip := "127.0.0.1:12345"
	root, err := e.d.Nodes.Create("Production", "")
	require.NoError(t, err)
	child, err := e.d.Nodes.Create("Servers", root.ID)
	require.NoError(t, err)
	host, err := e.d.Assets.Create(coreassets.Input{Name: "labeled host", Host: "127.0.0.1", Port: 22, Username: "ops", Password: "synthetic-label-password", NodeID: child.ID, HostKeyFingerprint: validTestFingerprint()})
	require.NoError(t, err)
	existing, err := e.d.Assets.ManagedAccounts(host.ID)
	require.NoError(t, err)
	require.NotEmpty(t, existing)
	account, err := e.d.Assets.CreateManagedAccount(host.ID, coreassets.AccountInput{Username: "reader", Password: "synthetic-label-child-password", Version: existing[0].Version}, coreassets.AccountActor{ID: e.admin.ID, Name: e.admin.Username})
	require.NoError(t, err)
	_, err = e.d.Grants.Create(grants.Input{UserID: e.operator.ID, AssetID: host.ID, Account: "reader", Actions: []string{"view"}}, "admin")
	require.NoError(t, err)
	prod, err := e.d.Labels.Save("", e.admin.ID, labels.Input{Name: "Environment", Value: "production", RequestID: "api-prod-001"})
	require.NoError(t, err)
	stage, err := e.d.Labels.Save("", e.admin.ID, labels.Input{Name: "environment", Value: "staging", RequestID: "api-stage-001"})
	require.NoError(t, err)
	team, err := e.d.Labels.Save("", e.admin.ID, labels.Input{Name: "Team", Value: "Ops", RequestID: "api-team-001"})
	require.NoError(t, err)
	for _, v := range []struct {
		resource labels.Resource
		ids      []string
		request  string
	}{{labels.Resource{Type: "node", ID: root.ID}, []string{prod.ID, team.ID}, "api-root-bind-001"}, {labels.Resource{Type: "node", ID: child.ID}, []string{stage.ID}, "api-child-bind-001"}} {
		_, err = e.d.Labels.Bind(v.resource, e.admin.ID, labels.BindingInput{LabelIDs: v.ids, RequestID: v.request})
		require.NoError(t, err)
	}
	filtered := e.send(t, "GET", "/api/v1/assets?label="+stage.ID+"&label="+team.ID, nil, e.token, ip)
	require.Equal(t, 200, filtered.Code, filtered.Body.String())
	var items []labeledAsset
	require.NoError(t, json.Unmarshal(filtered.Body.Bytes(), &items))
	require.Len(t, items, 1)
	assert.Equal(t, host.ID, items[0].ID)
	assert.True(t, items[0].Labels[0].Inherited)
	assert.Equal(t, stage.ID, items[0].Labels[0].ID)
	excluded := e.send(t, "GET", "/api/v1/assets?label="+prod.ID, nil, e.token, ip)
	assert.JSONEq(t, "[]", excluded.Body.String())
	assert.Equal(t, 400, e.send(t, "GET", "/api/v1/assets?label=unknown", nil, e.token, ip).Code)
	// Node browsing follows visible descendants; assignment requires both permissions.
	nodePath := "/api/v1/labels/bindings/node/" + child.ID
	assert.Equal(t, 200, e.send(t, "GET", nodePath, nil, e.token, ip).Code)
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "Tag visible hosts", Permissions: []string{"labels.assign"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 404, e.send(t, "PUT", nodePath, labels.BindingInput{Revision: 1, RequestID: "denied-node-001"}, e.token, ip).Code)
	accountPath := "/api/v1/labels/bindings/asset/" + account.ID
	written := e.send(t, "PUT", accountPath, labels.BindingInput{LabelIDs: []string{prod.ID}, RequestID: "api-account-bind-001"}, e.token, ip)
	require.Equal(t, 200, written.Code, written.Body.String())
	var binding labels.Binding
	require.NoError(t, json.Unmarshal(written.Body.Bytes(), &binding))
	assert.Equal(t, host.ID, binding.Resource.ID)
	physical := e.send(t, "GET", "/api/v1/labels/bindings/asset/"+host.ID, nil, e.token, ip)
	require.Equal(t, 200, physical.Code)
	assert.Contains(t, physical.Body.String(), prod.ID)
	// A live binding blocks catalog deletion, including from an administrator.
	remove := map[string]any{"revision": prod.Revision, "request_id": "api-inuse-delete-001"}
	assert.Equal(t, 409, e.send(t, "DELETE", "/api/v1/labels/labels/"+prod.ID, remove, e.adminToken, ip).Code)
	audit := e.send(t, "GET", "/api/v1/labels/audit", nil, e.adminToken, ip)
	require.Equal(t, 200, audit.Code)
	assert.Contains(t, audit.Body.String(), e.operator.ID)
	assert.NotContains(t, audit.Body.String(), "synthetic-label")
	assert.Contains(t, rbac.OrganizationCatalog(), "labels.assign")
}
