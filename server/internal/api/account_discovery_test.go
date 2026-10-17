package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/accountdiscovery"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type accountTestHost struct {
	blocking atomic.Bool
	entered  atomic.Bool
}

func (h *accountTestHost) Run(ctx context.Context, cmd string) (sshclient.ExecResult, error) {
	if strings.Contains(cmd, "uname -s;") {
		return sshclient.ExecResult{Stdout: "Linux\nx86_64", ExitCode: 0}, nil
	}
	if strings.Contains(cmd, "printf present;") {
		return sshclient.ExecResult{Stdout: "present", ExitCode: 0}, nil
	}
	if strings.Contains(cmd, " accounts --offset ") {
		h.entered.Store(true)
		if h.blocking.Load() {
			<-ctx.Done()
			return sshclient.ExecResult{ExitCode: 1}, ctx.Err()
		}
		rows := []hostagent.Account{{Username: "ops", UID: 1000, GID: 1000, Home: "/home/ops", Shell: "/bin/sh"}}
		raw, _ := json.Marshal(hostagent.AccountPage{Format: hostagent.AccountFormat, Digest: hostagent.AccountDigest(rows), Offset: 0, Total: 1, Accounts: rows})
		return sshclient.ExecResult{ExitCode: 0, Stdout: string(raw)}, nil
	}
	return sshclient.ExecResult{ExitCode: 0, Stdout: "ready"}, nil
}
func (*accountTestHost) Upload(context.Context, string, io.Reader) error {
	return errors.New("already-present helper must not upload")
}
func (*accountTestHost) Root() string { return "/home/ops" }
func (*accountTestHost) DialLoopback(context.Context) (net.Conn, error) {
	return nil, errors.New("no loopback access")
}
func (*accountTestHost) Close() error { return nil }
func TestAccountDiscoveryAPIRequiresIndependentAuthorityAndRevokesRunningCollection(t *testing.T) {
	e := newPolicyEnv(t)
	store, err := accountdiscovery.Open(filepath.Join(t.TempDir(), "accounts"), make([]byte, 32), nil)
	require.NoError(t, err)
	defer store.Close()
	e.d.AccountDiscovery = store
	var membershipDenied atomic.Bool
	e.d.OrganizationAllowed = func(u coreauth.User) bool { return u.ID != e.operator.ID || !membershipDenied.Load() }
	host := &accountTestHost{}
	var opens atomic.Int32
	e.d.HostPlugins = hostplugins.New(func(context.Context, string) (hostplugins.Transport, error) { opens.Add(1); return host, nil }, nil)
	e.router = NewRouter("test", e.d)
	path := "/api/v1/assets/" + e.asset.ID + "/account-discovery/jobs"
	records := "/api/v1/assets/" + e.asset.ID + "/discovered-accounts"
	assert.Equal(t, 403, e.send(t, "POST", path, map[string]any{"request_id": "first"}, e.token, "192.0.2.3:4000").Code)
	assert.Zero(t, opens.Load())
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "account-reviewer", Permissions: []string{"accounts.discover", "accounts.view", "accounts.review"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	binding, err := e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	r := e.send(t, "POST", path, map[string]any{"request_id": "first"}, e.token, "192.0.2.3:4000")
	require.Equal(t, 201, r.Code, r.Body.String())
	var j jobs.Job
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &j))
	require.NotNil(t, j.Discovery)
	require.Eventually(t, func() bool { x, err := e.d.Jobs.Get(j.ID); return err == nil && x.State == "succeeded" }, 3*time.Second, 10*time.Millisecond)
	r = e.send(t, "GET", records, nil, e.token, "192.0.2.3:4000")
	require.Equal(t, 200, r.Code)
	var page accountdiscovery.Page
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &page))
	require.Len(t, page.Results, 1)
	updated := map[string]any{"revision": page.Revision, "review": "ignored", "note": "known local account"}
	assert.Equal(t, 200, e.send(t, "PUT", records+"/"+page.Results[0].ID, updated, e.token, "192.0.2.3:4000").Code)
	assert.Equal(t, 409, e.send(t, "PUT", records+"/"+page.Results[0].ID, updated, e.token, "192.0.2.3:4000").Code)
	assert.Equal(t, 400, e.send(t, "POST", "/api/v1/ops/jobs", map[string]any{"asset_id": e.asset.ID, "command": "x", "account_discovery": map[string]string{"binding": "forged"}}, e.token, "192.0.2.3:4000").Code)
	duplicate := e.send(t, "POST", path, map[string]any{"request_id": "first"}, e.token, "192.0.2.3:4000")
	require.Equal(t, 201, duplicate.Code)
	var again jobs.Job
	require.NoError(t, json.Unmarshal(duplicate.Body.Bytes(), &again))
	assert.Equal(t, j.ID, again.ID)
	assert.EqualValues(t, 1, opens.Load())
	// Password revisions invalidate an in-flight operation, but preserve target findings.
	a := e.asset
	before := discoveryIdentity(a)
	a.CredentialRevision++
	assert.Equal(t, before, discoveryIdentity(a))
	assert.NotEqual(t, j.Discovery.Binding, databaseRouteBinding(e.d, a))
	host.entered.Store(false)
	host.blocking.Store(true)
	r = e.send(t, "POST", path, map[string]any{"request_id": "revoke-live"}, e.token, "192.0.2.3:4000")
	require.Equal(t, 201, r.Code)
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &j))
	require.Eventually(t, host.entered.Load, time.Second, time.Millisecond)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, Revision: binding.Revision}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		x, _ := e.d.Jobs.Get(j.ID)
		return x.State == "failed" && x.ErrorCode == "access_policy_denied"
	}, 3*time.Second, 10*time.Millisecond)
	assert.Equal(t, 404, e.send(t, "GET", records, nil, e.token, "192.0.2.3:4000").Code)
	binding, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}, Revision: binding.Revision + 1}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	host.entered.Store(false)
	r = e.send(t, "POST", path, map[string]any{"request_id": "revoke-membership"}, e.token, "192.0.2.3:4000")
	require.Equal(t, 201, r.Code)
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &j))
	require.Eventually(t, host.entered.Load, time.Second, time.Millisecond)
	membershipDenied.Store(true)
	require.Eventually(t, func() bool {
		x, _ := e.d.Jobs.Get(j.ID)
		return x.State == "failed" && x.ErrorCode == "access_policy_denied"
	}, 3*time.Second, 10*time.Millisecond)
	rows, total, err := store.Audit(e.asset.ID, 0, 100)
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, rows, 2, "revoked collection cannot publish findings")
}

func TestAccountDiscoveryTargetIdentityAndGatewayAccessPolicies(t *testing.T) {
	e := newPolicyEnv(t)
	target := e.asset
	original := discoveryIdentity(target)
	target.CredentialRevision++
	target.Username = "another-collector"
	assert.Equal(t, original, discoveryIdentity(target))
	target.HostKeyFingerprint = "different-pin"
	assert.NotEqual(t, original, discoveryIdentity(target))
	gateway, err := e.d.Assets.Create(assets.Input{Name: "inventory gateway", Host: "127.0.0.1", Port: 2201, Username: "gw", Password: "synthetic-gateway-password", HostKeyFingerprint: validTestFingerprint()})
	require.NoError(t, err)
	target = e.asset
	target.GatewayID = gateway.ID
	origin := accesspolicies.Origin{SourceIP: "192.0.2.3", Method: "exec"}
	assert.True(t, discoveryPoliciesAllowed(e.d, e.operator, target, origin))
	_, err = e.d.AccessPolicies.Save("", accesspolicies.Input{Name: "deny inventory gateway", Kind: accesspolicies.Asset, UserID: e.operator.ID, AssetID: gateway.ID, Action: "deny", Enabled: true, Priority: 50, Timezone: "UTC"}, e.admin.ID, nil)
	require.NoError(t, err)
	assert.False(t, discoveryPoliciesAllowed(e.d, e.operator, target, origin))
}
