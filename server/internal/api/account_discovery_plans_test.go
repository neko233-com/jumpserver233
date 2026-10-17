package api

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	"github.com/neko233-com/jumpserver233/server/internal/core/accountdiscovery"
	"github.com/neko233-com/jumpserver233/server/internal/core/agentevents"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func discoveryScheduleEnv(t *testing.T) (*policyTestEnv, *accountTestHost, rbac.Binding) {
	t.Helper()
	e := newPolicyEnv(t)
	e.d.Operations.Close() // Replace the router's captured dependencies before starting the scheduler.
	var err error
	e.d.Operations, err = operations.Open(filepath.Join(t.TempDir(), "operations.json"), make([]byte, 32), nil, e.d.Jobs)
	require.NoError(t, err)
	e.d.AccountDiscovery, err = accountdiscovery.Open(filepath.Join(t.TempDir(), "accounts"), make([]byte, 32), nil)
	require.NoError(t, err)
	t.Cleanup(func() { e.d.Operations.Close(); e.d.AccountDiscovery.Close() })
	e.d.AccessReviews, err = accessreviews.OpenStore(filepath.Join(t.TempDir(), "reviews.json"))
	require.NoError(t, err)
	h := &accountTestHost{}
	e.d.HostPlugins = hostplugins.New(func(context.Context, string) (hostplugins.Transport, error) { return h, nil }, nil)
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "scheduled-discovery", Permissions: []string{"accounts.view", "accounts.discover", "accounts.schedule"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	binding, err := e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	e.router = NewRouter("test", e.d)
	return e, h, binding
}

func createDiscoverySchedule(t *testing.T, e *policyTestEnv) operations.Plan {
	t.Helper()
	r := e.send(t, "POST", "/api/v1/assets/"+e.asset.ID+"/account-discovery/plans", map[string]any{"request_id": "scheduled-test", "interval_seconds": 3600}, e.token, "192.0.2.3:4000")
	require.Equal(t, 201, r.Code, r.Body.String())
	var p operations.Plan
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &p))
	return p
}

func TestDiscoveryScheduleAPIArchivesNativeResultsAndRefreshesCredentialRevision(t *testing.T) {
	e, _, _ := discoveryScheduleEnv(t)
	p := createDiscoverySchedule(t, e)
	path := "/api/v1/assets/" + e.asset.ID + "/account-discovery"
	var receipt agentevents.Record
	require.Eventually(t, func() bool {
		page, err := e.d.AccountDiscovery.Collections(e.asset.ID, 0, 10)
		if err == nil && len(page.Results) == 1 {
			receipt = page.Results[0]
			return true
		}
		return false
	}, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, "succeeded", receipt.Receipt.State)
	assert.Equal(t, e.operator.Username, receipt.Collector.Name)
	assert.Equal(t, "ops", receipt.Source.Account)
	assert.NotContains(t, string(receipt.Receipt.Job), "synthetic-private-password")
	assert.Equal(t, 200, e.send(t, "GET", "/api/v1/ops/jobs/"+receipt.Receipt.JobID, nil, e.token, "192.0.2.3:4000").Code)
	assert.Equal(t, 200, e.send(t, "GET", "/api/v1/ops/runs/"+receipt.Receipt.RunID, nil, e.token, "192.0.2.3:4000").Code)
	assert.Equal(t, 400, e.send(t, "GET", path+"/collections?limit=101", nil, e.token, "192.0.2.3:4000").Code)
	r := e.send(t, "PUT", path+"/plans/"+p.ID, map[string]any{"enabled": false, "revision": p.ConfigRevision}, e.token, "192.0.2.3:4000")
	require.Equal(t, 200, r.Code, r.Body.String())
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &p))
	a := e.asset
	_, err := e.d.Assets.Update(a.ID, assets.Input{Name: a.Name, Host: a.Host, Port: a.Port, Username: a.Username, Password: "synthetic-rotated-password", HostKeyFingerprint: a.HostKeyFingerprint})
	require.NoError(t, err)
	r = e.send(t, "PUT", path+"/plans/"+p.ID, map[string]any{"enabled": true, "revision": p.ConfigRevision}, e.token, "192.0.2.3:4000")
	require.Equal(t, 200, r.Code, r.Body.String())
	require.Eventually(t, func() bool { page, _ := e.d.AccountDiscovery.Collections(a.ID, 0, 10); return len(page.Results) == 2 }, 5*time.Second, 10*time.Millisecond)
	page, err := e.d.AccountDiscovery.Collections(a.ID, 0, 10)
	require.NoError(t, err)
	var j struct {
		Discovery accountdiscovery.Operation `json:"account_discovery"`
	}
	require.NoError(t, json.Unmarshal(page.Results[0].Receipt.Job, &j))
	current, err := e.d.Assets.Get(a.ID)
	require.NoError(t, err)
	assert.Equal(t, databaseRouteBinding(e.d, current), j.Discovery.Binding)
	assert.EqualValues(t, 2, j.Discovery.Sequence)
	_, total, err := e.d.AccountDiscovery.Audit(a.ID, 0, 100)
	require.NoError(t, err)
	assert.Zero(t, total, "scheduled receipts must not consume human review history")
}

func TestDiscoveryScheduleAPIIndependentPermissionRevocationAndOwnedPause(t *testing.T) {
	e, h, binding := discoveryScheduleEnv(t)
	h.blocking.Store(true)
	p := createDiscoverySchedule(t, e)
	require.Eventually(t, h.entered.Load, 3*time.Second, time.Millisecond)
	_, err := e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, Revision: binding.Revision}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	require.Eventually(t, func() bool { v, _ := e.d.Operations.Plan(p.ID); return !v.Enabled && v.ErrorCode == "access_denied" }, 5*time.Second, 10*time.Millisecond)
	page, err := e.d.AccountDiscovery.Collections(e.asset.ID, 0, 10)
	require.NoError(t, err)
	if len(page.Results) == 0 {
		require.Eventually(t, func() bool {
			page, _ = e.d.AccountDiscovery.Collections(e.asset.ID, 0, 10)
			return len(page.Results) > 0
		}, 3*time.Second, 10*time.Millisecond)
	}
	assert.Equal(t, "failed", page.Results[0].Receipt.State)
	findings, err := e.d.AccountDiscovery.Findings(accountdiscovery.Source{AssetID: e.asset.ID, Binding: discoveryIdentity(e.asset), Account: "ops"}, 0, 10)
	require.NoError(t, err)
	assert.Empty(t, findings.Results)
	path := "/api/v1/assets/" + e.asset.ID + "/account-discovery/plans"
	assert.Equal(t, 403, e.send(t, "POST", path, map[string]any{"request_id": "denied"}, e.token, "192.0.2.3:4000").Code)
	current, _ := e.d.Operations.Plan(p.ID)
	assert.Equal(t, 403, e.send(t, "PUT", path+"/"+p.ID, map[string]any{"enabled": true, "revision": current.ConfigRevision}, e.token, "192.0.2.3:4000").Code)
	assert.Equal(t, 200, e.send(t, "PUT", path+"/"+p.ID, map[string]any{"enabled": false, "revision": current.ConfigRevision}, e.token, "192.0.2.3:4000").Code)
	assert.Equal(t, 200, e.send(t, "GET", path, nil, e.token, "192.0.2.3:4000").Code, "owner can inspect and pause after authority is removed")
	assert.Equal(t, 409, e.send(t, "PUT", path+"/"+p.ID, map[string]any{"enabled": false, "revision": 1}, e.token, "192.0.2.3:4000").Code)
}

func TestDiscoveryScheduleAPILoginApprovalIsScopedToOneRunAndPauseExpiresIt(t *testing.T) {
	e, h, _ := discoveryScheduleEnv(t)
	a := e.asset
	reviewRequired := true
	_, err := e.d.Assets.Update(a.ID, assets.Input{Name: a.Name, Host: a.Host, Port: a.Port, Username: a.Username, Password: "synthetic-private-password", HostKeyFingerprint: a.HostKeyFingerprint, LoginReviewRequired: &reviewRequired})
	require.NoError(t, err)
	manual, err := e.d.AccessReviews.Request(e.operator.ID, e.operator.Username, a.ID, a.Name, a.Username)
	require.NoError(t, err)
	require.NoError(t, e.d.AccessReviews.Resolve(manual.ID, e.admin.Username, true))
	p := createDiscoverySchedule(t, e)
	var first accessreviews.Review
	require.Eventually(t, func() bool {
		all, _ := e.d.AccessReviews.ListPending()
		if len(all) == 1 {
			first = all[0]
			return true
		}
		return false
	}, 3*time.Second, time.Millisecond)
	assert.Equal(t, accessreviews.ActionAccountDiscovery, first.Action)
	assert.Equal(t, p.ID+":1", first.RequestScope)
	assert.False(t, h.entered.Load())
	path := "/api/v1/assets/" + a.ID + "/account-discovery/plans/" + p.ID
	r := e.send(t, "PUT", path, map[string]any{"enabled": false, "revision": 1}, e.token, "192.0.2.3:4000")
	require.Equal(t, 200, r.Code, r.Body.String())
	expired, err := e.d.AccessReviews.Get(first.ID)
	require.NoError(t, err)
	assert.Equal(t, accessreviews.StateExpired, expired.State)
	r = e.send(t, "PUT", path, map[string]any{"enabled": true, "revision": 2}, e.token, "192.0.2.3:4000")
	require.Equal(t, 200, r.Code, r.Body.String())
	var second accessreviews.Review
	require.Eventually(t, func() bool {
		all, _ := e.d.AccessReviews.ListPending()
		if len(all) == 1 {
			second = all[0]
			return second.ID != first.ID
		}
		return false
	}, 3*time.Second, time.Millisecond)
	assert.Equal(t, p.ID+":"+strconv.Itoa(2), second.RequestScope)
	require.NoError(t, e.d.AccessReviews.Resolve(second.ID, e.admin.Username, true))
	require.Eventually(t, h.entered.Load, 4*time.Second, time.Millisecond)
	prior, err := e.d.AccessReviews.Get(manual.ID)
	require.NoError(t, err)
	assert.Equal(t, accessreviews.StateApproved, prior.State, "manual permit remains independent")
}
