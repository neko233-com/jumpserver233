package api

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/accountdiscovery"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/nodes"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagedAccountDiscoveryBindingRequiresCurrentPresentIdentity(t *testing.T) {
	e := newPolicyEnv(t)
	store, err := accountdiscovery.Open(filepath.Join(t.TempDir(), "accounts"), make([]byte, 32), nil)
	require.NoError(t, err)
	defer store.Close()
	e.d.AccountDiscovery = store
	e.router = NewRouter("test", e.d)
	src := accountdiscovery.Source{AssetID: e.asset.ID, Binding: discoveryIdentity(e.asset), Account: e.asset.Username}
	rows := []hostagent.Account{{Username: "discovered-user", UID: 1003, GID: 1003, Home: "/home/discovered-user", Shell: "/bin/sh"}}
	_, err = store.Import(src, accountdiscovery.Actor{ID: e.admin.ID, Name: e.admin.Username}, "job-00000000000000000000000000000001", hostagent.AccountDigest(rows), rows)
	require.NoError(t, err)
	p, err := store.Findings(src, 0, 100)
	require.NoError(t, err)
	accounts, err := e.d.Assets.ManagedAccounts(e.asset.ID)
	require.NoError(t, err)
	path := "/api/v1/assets/" + e.asset.ID + "/accounts"
	in := map[string]any{"username": "wrong-user", "password": "synthetic-bound-password", "version": accounts[0].Version, "discovery_id": p.Results[0].ID}
	assert.Equal(t, 400, e.send(t, "POST", path, in, e.adminToken, "192.0.2.1:4000").Code)
	in["username"] = "discovered-user"
	r := e.send(t, "POST", path, in, e.adminToken, "192.0.2.1:4000")
	require.Equal(t, 201, r.Code, r.Body.String())
	var a assets.ManagedAccount
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &a))
	assert.Equal(t, p.Results[0].ID, a.DiscoveryID)
	rows[0].UID++
	_, err = store.Import(src, accountdiscovery.Actor{ID: e.admin.ID, Name: e.admin.Username}, "job-00000000000000000000000000000002", hostagent.AccountDigest(rows), rows)
	require.NoError(t, err)
	in["version"] = a.Version
	assert.Equal(t, 400, e.send(t, "PUT", path+"/"+a.ID, in, e.adminToken, "192.0.2.1:4000").Code)
}

func TestManagedAccountsAPIScopesInventoryJobsFiltersAndIndependentAuthority(t *testing.T) {
	e := newPolicyEnv(t)
	var err error
	e.d.Nodes, err = nodes.OpenStore(filepath.Join(t.TempDir(), "nodes.json"))
	require.NoError(t, err)
	node, err := e.d.Nodes.Create("Named accounts", "")
	require.NoError(t, err)
	e.asset, err = e.d.Assets.Update(e.asset.ID, assets.Input{Name: e.asset.Name, Host: e.asset.Host, Port: e.asset.Port, Username: e.asset.Username, HostKeyFingerprint: e.asset.HostKeyFingerprint, NodeID: node.ID})
	require.NoError(t, err)
	e.router = NewRouter("test", e.d)
	root := "/api/v1/assets/" + e.asset.ID + "/accounts"
	read := e.send(t, "GET", root, nil, e.adminToken, "192.0.2.1:4000")
	require.Equal(t, 200, read.Code)
	var page struct {
		Results []assets.ManagedAccount `json:"results"`
		Version string                  `json:"version"`
		Total   int                     `json:"total"`
	}
	require.NoError(t, json.Unmarshal(read.Body.Bytes(), &page))
	assert.Equal(t, 1, page.Total)
	input := map[string]any{"username": "second-user", "password": "synthetic-second-password", "version": page.Version}
	assert.Equal(t, 403, e.send(t, "POST", root, input, e.token, "192.0.2.1:4000").Code)
	response := e.send(t, "POST", root, input, e.adminToken, "192.0.2.1:4000")
	require.Equal(t, 201, response.Code, response.Body.String())
	assert.NotContains(t, response.Body.String(), "synthetic-second-password")
	assert.NotContains(t, response.Body.String(), `"password":`)
	var second assets.ManagedAccount
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &second))
	assert.Equal(t, e.asset.ID, second.AssetID)
	assert.Equal(t, 409, e.send(t, "POST", root, input, e.adminToken, "192.0.2.1:4000").Code)
	assert.Equal(t, 404, e.send(t, "GET", root+"/"+second.ID, nil, e.token, "192.0.2.1:4000").Code)
	jobInput := map[string]any{"asset_id": second.ID, "command": "printf account", "request_id": "named-before-grant"}
	assert.Equal(t, 403, e.send(t, "POST", "/api/v1/ops/jobs", jobInput, e.token, "192.0.2.1:4000").Code)
	assert.Zero(t, e.execs.Load())
	grant := e.send(t, "POST", "/api/v1/grants", map[string]any{"user_id": e.operator.ID, "asset_id": e.asset.ID, "account": second.Username, "actions": []string{"view", "connect", "sftp"}}, e.adminToken, "192.0.2.1:4000")
	require.Equal(t, 201, grant.Code, grant.Body.String())
	for _, g := range e.d.Grants.List() {
		if g.Account == e.asset.Username {
			require.NoError(t, e.d.Grants.Delete(g.ID))
		}
	}
	response = e.send(t, "GET", "/api/v1/assets", nil, e.token, "192.0.2.1:4000")
	require.Equal(t, 200, response.Code)
	var inventory []assets.ListItem
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &inventory))
	require.Len(t, inventory, 1)
	assert.Equal(t, e.asset.ID, inventory[0].ID)
	assert.Equal(t, second.ID, inventory[0].SelectedAccountID)
	assert.Equal(t, second.Username, inventory[0].Username)
	require.Len(t, inventory[0].Accounts, 1)
	assert.Equal(t, second.ID, inventory[0].Accounts[0].ID)
	response = e.send(t, "GET", root+"?username="+second.Username+"&limit=1", nil, e.token, "192.0.2.1:4000")
	require.Equal(t, 200, response.Code)
	page.Results = nil
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &page))
	require.Len(t, page.Results, 1)
	assert.Equal(t, second.ID, page.Results[0].ID)
	assert.Nil(t, page.Results[0].PasswordRotation)
	assert.Nil(t, page.Results[0].SSHKeyRotation)
	response = e.send(t, "GET", "/api/v1/assets/nodes", nil, e.token, "192.0.2.1:4000")
	require.Equal(t, 200, response.Code)
	assert.Contains(t, response.Body.String(), node.ID)
	assert.Equal(t, 404, e.send(t, "GET", root+"/"+e.asset.ID, nil, e.token, "192.0.2.1:4000").Code)
	jobInput["request_id"] = "named-after-grant"
	response = e.send(t, "POST", "/api/v1/ops/jobs", jobInput, e.token, "192.0.2.1:4000")
	require.Equal(t, 201, response.Code, response.Body.String())
	var job jobs.Job
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &job))
	assert.Equal(t, second.Username, job.Account)
	require.Eventually(t, func() bool { j, _ := e.d.Jobs.Get(job.ID); return j.State == "succeeded" }, time.Second, 5*time.Millisecond)
	assert.EqualValues(t, 1, e.execs.Load())
	filter := e.send(t, "POST", "/api/v1/command-filters", map[string]any{"name": "second-account-rule", "asset_id": e.asset.ID, "account": second.Username, "match": "contains", "pattern": "blocked", "action": "deny", "priority": 100}, e.adminToken, "192.0.2.1:4000")
	require.Equal(t, 201, filter.Code, filter.Body.String())
	jobInput["command"], jobInput["request_id"] = "printf blocked", "named-filtered"
	response = e.send(t, "POST", "/api/v1/ops/jobs", jobInput, e.token, "192.0.2.1:4000")
	require.Equal(t, 201, response.Code, response.Body.String())
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &job))
	assert.Equal(t, "denied", job.State)
	assert.EqualValues(t, 1, e.execs.Load())

	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "Scoped account custodian", Permissions: []string{"accounts.manage"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 403, e.send(t, "POST", "/api/v1/ops/jobs", map[string]any{"asset_id": e.asset.ID, "command": "printf primary", "request_id": "primary-still-denied"}, e.token, "192.0.2.1:4000").Code)
	assert.Equal(t, 403, e.send(t, "PUT", root+"/"+second.ID, map[string]any{"version": second.Version, "password_rotation_enabled": false}, e.token, "192.0.2.1:4000").Code)
	response = e.send(t, "PUT", root+"/"+second.ID, map[string]any{"version": second.Version, "active": false}, e.token, "192.0.2.1:4000")
	require.Equal(t, 200, response.Code, response.Body.String())
	var disabled assets.ManagedAccount
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &disabled))
	assert.False(t, disabled.Active)
	assert.Equal(t, 409, e.send(t, "PUT", root+"/"+second.ID, map[string]any{"version": second.Version, "active": true}, e.token, "192.0.2.1:4000").Code)
	assert.Equal(t, 404, e.send(t, "POST", "/api/v1/sessions", map[string]any{"asset_id": second.ID}, e.token, "192.0.2.1:4000").Code)
	assert.Zero(t, e.opens.Load())
	response = e.send(t, "DELETE", root+"/"+second.ID, map[string]string{"version": disabled.Version}, e.token, "192.0.2.1:4000")
	require.Equal(t, 204, response.Code, response.Body.String())
	response = e.send(t, "GET", root+"/"+e.asset.ID+"/activity", nil, e.adminToken, "192.0.2.1:4000")
	require.Equal(t, 200, response.Code)
	assert.Contains(t, response.Body.String(), `"action":"deleted"`)
	assert.NotContains(t, response.Body.String(), "synthetic-second-password")
}

func TestManagedAccountsRejectCrossAssetAndInjectedMetadata(t *testing.T) {
	e := newPolicyEnv(t)
	rows, err := e.d.Assets.ManagedAccounts(e.asset.ID)
	require.NoError(t, err)
	path := "/api/v1/assets/" + e.asset.ID + "/accounts"
	for key, value := range map[string]any{"parent_asset_id": "forged-parent", "id": "forged-id", "account_audit": []any{}, "credential_revision": 999, "host": "elsewhere.invalid"} {
		t.Run(key, func(t *testing.T) {
			body := map[string]any{"username": "injected", "password": "synthetic-injected-password", "version": rows[0].Version, key: value}
			assert.Equal(t, 400, e.send(t, "POST", path, body, e.adminToken, "192.0.2.1:4000").Code)
		})
	}
	assert.Equal(t, 400, e.send(t, "GET", path+"?limit=101", nil, e.adminToken, "192.0.2.1:4000").Code)
	assert.Equal(t, 400, e.send(t, "GET", path+"?offset=-1", nil, e.adminToken, "192.0.2.1:4000").Code)
	assert.Equal(t, 404, e.send(t, "GET", fmt.Sprintf("/api/v1/assets/%s/accounts", "unknown"), nil, e.token, "192.0.2.1:4000").Code)
	assert.Zero(t, e.execs.Load())
	assert.Zero(t, e.opens.Load())
}
