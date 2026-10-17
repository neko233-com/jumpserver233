package api

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/agentbundle"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type remoteAccountTestHost struct {
	calls             atomic.Int32
	blocking, entered atomic.Bool
}

func (h *remoteAccountTestHost) Run(_ context.Context, command string) (sshclient.ExecResult, error) {
	if strings.Contains(command, "uname -s;") {
		return sshclient.ExecResult{ExitCode: 0, Stdout: "Linux\nx86_64\n0"}, nil
	}
	if strings.Contains(command, "account-admin-install") {
		b, e := agentbundle.Get("linux-amd64")
		if e != nil {
			return sshclient.ExecResult{}, e
		}
		raw, _ := json.Marshal(map[string]string{"format": hostagent.AccountAdminFormat, "path": hostagent.AccountAdminBinaryDirectory + "/agent-recovery-" + b.SHA256, "sha256": b.SHA256})
		return sshclient.ExecResult{ExitCode: 0, Stdout: string(raw)}, nil
	}
	if strings.Contains(command, "printf present;") {
		return sshclient.ExecResult{ExitCode: 0, Stdout: "present"}, nil
	}
	return sshclient.ExecResult{ExitCode: 0, Stdout: "ready"}, nil
}
func (h *remoteAccountTestHost) RunInput(ctx context.Context, _ string, raw []byte) (sshclient.ExecResult, error) {
	req, e := hostagent.DecodeAccountAdminRequest(raw)
	if e != nil {
		return sshclient.ExecResult{ExitCode: 1}, e
	}
	h.calls.Add(1)
	h.entered.Store(true)
	if h.blocking.Load() {
		<-ctx.Done()
		return sshclient.ExecResult{ExitCode: 1}, ctx.Err()
	}
	r := hostagent.AccountAdminResult{Format: hostagent.AccountAdminFormat, ID: req.Task.ID, Digest: req.Task.Digest(), Action: req.Task.Action, Username: req.Task.Username, UID: 1001, GID: 1001, Home: "/home/" + req.Task.Username, Shell: "/bin/sh", State: "applied", Stage: "ready"}
	if req.Mode == "cancel" {
		r.State = "cancelled"
		r.UID = 0
		r.Stage = "cancelled"
	}
	encoded, _ := json.Marshal(r)
	return sshclient.ExecResult{ExitCode: 0, Stdout: string(encoded)}, nil
}
func (*remoteAccountTestHost) Root() string { return "/root" }
func (*remoteAccountTestHost) Close() error { return nil }
func (*remoteAccountTestHost) Upload(context.Context, string, io.Reader) error {
	return hostplugins.ErrInvalid
}
func (*remoteAccountTestHost) DialLoopback(context.Context) (net.Conn, error) {
	return nil, hostplugins.ErrInvalid
}

func remoteAPIEnv(t *testing.T) (*policyTestEnv, *remoteAccountTestHost, rbac.Binding) {
	t.Helper()
	e := newPolicyEnv(t)
	e.d.Operations.Close()
	store, err := assets.OpenStore(filepath.Join(t.TempDir(), "assets.json"), make([]byte, 32))
	require.NoError(t, err)
	_, err = store.Create(e.asset, "synthetic-private-password")
	require.NoError(t, err)
	e.d.Assets = assets.NewServiceWithPasswordRotation(store, nil, nil, func(context.Context, sshclient.Target, sshclient.Credentials, time.Duration) error { return nil })
	e.d.AccessReviews, err = accessreviews.OpenStore(filepath.Join(t.TempDir(), "reviews.json"))
	require.NoError(t, err)
	h := &remoteAccountTestHost{}
	e.d.HostPlugins = hostplugins.New(func(context.Context, string) (hostplugins.Transport, error) { return h, nil }, nil)
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "remote-provisioner", Permissions: []string{"accounts.view", "accounts.manage", "accounts.remote.create"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	binding, err := e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	e.router = NewRouter("test", e.d)
	return e, h, binding
}
func remoteCreateInput(t *testing.T, e *policyTestEnv, id string) assets.RemoteAccountInput {
	t.Helper()
	parent, err := e.d.Assets.ManagedAccount(e.asset.ID, e.asset.ID)
	require.NoError(t, err)
	return assets.RemoteAccountInput{Action: "create", Username: "remoteqa_api", Shell: "/bin/sh", Version: parent.Version, RequestID: id}
}
func TestRemoteAccountAPIUsesIndependentAuthorityTypedJobsAndSafeReceipts(t *testing.T) {
	e, h, binding := remoteAPIEnv(t)
	path := "/api/v1/assets/" + e.asset.ID + "/remote-account-tasks"
	in := remoteCreateInput(t, e, "remote-create-api")
	_, err := e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, Revision: binding.Revision}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 403, e.send(t, "POST", path, in, e.token, "192.0.2.3:4000").Code)
	assert.Zero(t, h.calls.Load())
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: binding.RoleIDs, Revision: binding.Revision + 1}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	r := e.send(t, "POST", path, in, e.token, "192.0.2.3:4000")
	require.Equal(t, 201, r.Code, r.Body.String())
	var task assets.RemoteAccountTask
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &task))
	require.NotEmpty(t, task.JobID)
	require.Eventually(t, func() bool {
		v, err := e.d.Assets.RemoteAccountTask(e.asset.ID, task.Operation.Task.ID)
		return err == nil && v.State == "succeeded"
	}, 3*time.Second, time.Millisecond)
	a, err := e.d.Assets.ManagedAccount(e.asset.ID, task.Operation.AccountID)
	require.NoError(t, err)
	assert.True(t, a.Active)
	assert.True(t, a.KeyRotationEnabled)
	r = e.send(t, "POST", path, in, e.token, "192.0.2.3:4000")
	require.Equal(t, 201, r.Code, r.Body.String())
	assert.EqualValues(t, 1, h.calls.Load())
	assert.Equal(t, 400, e.send(t, "POST", "/api/v1/ops/jobs", map[string]any{"asset_id": e.asset.ID, "command": "forged", "remote_account": task.Operation}, e.token, "192.0.2.3:4000").Code)
	r = e.send(t, "GET", path+"?limit=1", nil, e.token, "192.0.2.3:4000")
	require.Equal(t, 200, r.Code)
	assert.NotContains(t, r.Body.String(), "PRIVATE KEY")
	assert.NotContains(t, r.Body.String(), "synthetic-private-password")
	assert.Equal(t, 400, e.send(t, "GET", path+"?limit=101", nil, e.token, "192.0.2.3:4000").Code)
	assert.Equal(t, 403, e.send(t, "POST", path, assets.RemoteAccountInput{Action: "delete", Username: a.Username, AccountID: a.ID, UID: 1001, Version: a.Version, RequestID: "independent-delete"}, e.token, "192.0.2.3:4000").Code)
}
func TestRemoteAccountAPIRevocationKeepsUncertainEndpointDisabledAndAdminCanReconcile(t *testing.T) {
	e, h, binding := remoteAPIEnv(t)
	h.blocking.Store(true)
	path := "/api/v1/assets/" + e.asset.ID + "/remote-account-tasks"
	r := e.send(t, "POST", path, remoteCreateInput(t, e, "remote-revoke-api"), e.token, "192.0.2.3:4000")
	require.Equal(t, 201, r.Code, r.Body.String())
	var task assets.RemoteAccountTask
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &task))
	require.Eventually(t, h.entered.Load, time.Second, time.Millisecond)
	_, err := e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, Revision: binding.Revision}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		v, _ := e.d.Jobs.Get(task.JobID)
		return v.State == "failed" && v.ErrorCode == "access_policy_denied"
	}, 3*time.Second, time.Millisecond)
	a, err := e.d.Assets.AccountAsset(e.asset.ID, task.Operation.AccountID)
	require.NoError(t, err)
	assert.True(t, a.AccountDisabled)
	assert.Equal(t, 404, e.send(t, "GET", path, nil, e.token, "192.0.2.3:4000").Code)
	current, err := e.d.Assets.RemoteAccountTask(e.asset.ID, task.Operation.Task.ID)
	require.NoError(t, err)
	h.blocking.Store(false)
	r = e.send(t, "POST", path+"/"+task.Operation.Task.ID+"/attempts", map[string]any{"revision": current.Revision, "mode": "inspect"}, e.adminToken, "192.0.2.3:4000")
	require.Equal(t, 201, r.Code, r.Body.String())
	require.Eventually(t, func() bool {
		v, _ := e.d.Assets.RemoteAccountTask(e.asset.ID, task.Operation.Task.ID)
		return v.State == "succeeded"
	}, 3*time.Second, time.Millisecond)
	a, err = e.d.Assets.Get(task.Operation.AccountID)
	require.NoError(t, err)
	assert.False(t, a.AccountDisabled)
}
func TestRemoteAccountAPILoginApprovalsArePerAttemptAndCancelledPreparationCannotUseOldPermit(t *testing.T) {
	e, h, _ := remoteAPIEnv(t)
	reviewRequired := true
	a := e.asset
	_, err := e.d.Assets.Update(a.ID, assets.Input{Name: a.Name, Host: a.Host, Port: a.Port, Username: a.Username, Password: "synthetic-private-password", HostKeyFingerprint: a.HostKeyFingerprint, LoginReviewRequired: &reviewRequired})
	require.NoError(t, err)
	path := "/api/v1/assets/" + a.ID + "/remote-account-tasks"
	r := e.send(t, "POST", path, remoteCreateInput(t, e, "remote-approve-api"), e.token, "192.0.2.3:4000")
	require.Equal(t, 202, r.Code, r.Body.String())
	var task assets.RemoteAccountTask
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &task))
	require.NotEmpty(t, task.ReviewID)
	assert.Zero(t, h.calls.Load())
	first, err := e.d.AccessReviews.Get(task.ReviewID)
	require.NoError(t, err)
	assert.Equal(t, accessreviews.ActionRemoteAccount, first.Action)
	assert.Equal(t, task.Operation.Task.ID+":1", first.RequestScope)
	r = e.send(t, "POST", path+"/"+task.Operation.Task.ID+"/attempts", map[string]any{"revision": task.Revision, "mode": "cancel"}, e.token, "192.0.2.3:4000")
	require.Equal(t, 202, r.Code, r.Body.String())
	var next assets.RemoteAccountTask
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &next))
	old, err := e.d.AccessReviews.Get(first.ID)
	require.NoError(t, err)
	assert.Equal(t, "expired", old.State)
	assert.NotEqual(t, first.ID, next.ReviewID)
	require.NoError(t, e.d.AccessReviews.Resolve(next.ReviewID, e.admin.Username, true))
	r = e.send(t, "POST", path+"/"+task.Operation.Task.ID+"/submit", nil, e.token, "192.0.2.3:4000")
	require.Equal(t, 201, r.Code, r.Body.String())
	require.Eventually(t, func() bool {
		v, _ := e.d.Assets.RemoteAccountTask(a.ID, task.Operation.Task.ID)
		return v.State == "cancelled"
	}, 3*time.Second, time.Millisecond)
	_, err = e.d.Assets.AccountAsset(a.ID, task.Operation.AccountID)
	assert.ErrorIs(t, err, assets.ErrNotFound)
	assert.EqualValues(t, 1, h.calls.Load())
}

func TestRemoteAccountCommandReviewUsesOriginalSourceAndCurrentAuthority(t *testing.T) {
	e, h, _ := remoteAPIEnv(t)
	_, err := e.d.CommandFilters.Create(commandfilters.Input{Name: "remote review", UserID: e.operator.ID, AssetID: e.asset.ID, Account: e.asset.Username, Match: "regex", Pattern: "^account-admin ", Action: "review"}, e.admin.ID)
	require.NoError(t, err)
	path := "/api/v1/assets/" + e.asset.ID + "/remote-account-tasks"
	r := e.send(t, "POST", path, remoteCreateInput(t, e, "remote-command-api"), e.token, "192.0.2.8:4000")
	require.Equal(t, 201, r.Code, r.Body.String())
	var task assets.RemoteAccountTask
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &task))
	job, err := e.d.Jobs.Get(task.JobID)
	require.NoError(t, err)
	assert.Equal(t, "pending_review", job.State)
	assert.Zero(t, h.calls.Load())
	rule := e.rule(t, accesspolicies.Asset, "exec", "192.0.2.0/24")
	assert.Equal(t, 403, e.send(t, "POST", "/api/v1/ops/jobs/"+task.JobID+"/review", map[string]bool{"approve": true}, e.adminToken, "127.0.0.1:4000").Code)
	assert.Zero(t, h.calls.Load())
	require.NoError(t, e.d.AccessPolicies.Delete(rule.ID, rule.Revision, e.admin.ID, nil))
	assert.Equal(t, 200, e.send(t, "POST", "/api/v1/ops/jobs/"+task.JobID+"/review", map[string]bool{"approve": true}, e.adminToken, "127.0.0.1:4000").Code)
	require.Eventually(t, func() bool {
		v, _ := e.d.Assets.RemoteAccountTask(e.asset.ID, task.Operation.Task.ID)
		return v.State == "succeeded"
	}, 3*time.Second, time.Millisecond)
	assert.EqualValues(t, 1, h.calls.Load())
}
