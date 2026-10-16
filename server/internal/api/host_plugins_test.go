package api

import (
	"context"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHostPluginPermissionConnectReviewOwnershipAndRunningRevocation(t *testing.T) {
	dir := t.TempDir()
	auth, e := coreauth.OpenService(filepath.Join(dir, "users"))
	require.NoError(t, e)
	_, e = auth.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, e)
	owner, e := auth.CreateUser("plugin.operator", "synthetic-plugin-operator-password", coreauth.RoleOperator)
	require.NoError(t, e)
	_, e = auth.CreateUser("plugin.foreign", "synthetic-plugin-foreign-password", coreauth.RoleOperator)
	require.NoError(t, e)
	adminToken, e := auth.Authenticate("admin", bootstrapPassword)
	require.NoError(t, e)
	token, e := auth.Authenticate(owner.Username, "synthetic-plugin-operator-password")
	require.NoError(t, e)
	foreign, e := auth.Authenticate("plugin.foreign", "synthetic-plugin-foreign-password")
	require.NoError(t, e)
	roles, e := rbac.Open(filepath.Join(dir, "roles"), nil)
	require.NoError(t, e)
	role, e := roles.SaveRole("", rbac.RoleInput{Name: "plugin manager", Permissions: []string{"plugins.manage", "plugins.inspect"}}, "admin", "admin")
	require.NoError(t, e)
	_, e = roles.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: owner.ID, RoleIDs: []string{role.ID}}, "admin", "admin")
	require.NoError(t, e)
	as := testAssetService(t)
	review := true
	a, e := as.Create(assets.Input{Name: "plugin QA", Host: "127.0.0.1", Port: 22, Username: "ops", Password: "synthetic-plugin-remote-secret", HostKeyFingerprint: validTestFingerprint(), LoginReviewRequired: &review})
	require.NoError(t, e)
	gs, e := grants.OpenStore(filepath.Join(dir, "grants"))
	require.NoError(t, e)
	_, e = gs.Create(grants.Input{UserID: owner.ID, AssetID: a.ID, Account: a.Username, Actions: []string{"view"}}, "admin")
	require.NoError(t, e)
	reviews, e := accessreviews.OpenStore(filepath.Join(dir, "reviews"))
	require.NoError(t, e)
	filters, e := commandfilters.OpenStore(filepath.Join(dir, "filters"))
	require.NoError(t, e)
	_, e = filters.Create(commandfilters.Input{Name: "review plugins", UserID: owner.ID, AssetID: a.ID, Account: a.Username, Match: "regex", Pattern: "^host-plugin ", Action: "review"}, "admin")
	require.NoError(t, e)
	var calls atomic.Int32
	ps := hostplugins.New(func(ctx context.Context, _ string) (hostplugins.Transport, error) {
		calls.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}, nil)
	js, e := jobs.Open(filepath.Join(dir, "jobs"), make([]byte, 32), nil, func(context.Context, string, string) (sshclient.ExecResult, error) {
		t.Error("plugin fell through to shell executor")
		return sshclient.ExecResult{}, nil
	})
	require.NoError(t, e)
	defer js.Close()
	router := NewRouter("test", Dependencies{Auth: auth, Assets: as, Jobs: js, HostPlugins: ps, RBAC: roles, Grants: gs, AccessReviews: reviews, CommandFilters: filters})
	url := "/api/v1/assets/" + a.ID + "/host-plugins/banhack233/jobs"
	body := `{"action":"install","request_id":"plugin-stable"}`
	send := func(method, url, body, access string) int {
		return doJSONRequest(t, router, method, url, body, access, "127.0.0.1:12345").Code
	}
	require.Equal(t, 401, send("GET", "/api/v1/host-plugins", "", ""))
	require.Equal(t, 403, send("GET", "/api/v1/host-plugins", "", foreign.AccessToken))
	require.Equal(t, 200, send("GET", "/api/v1/host-plugins", "", token.AccessToken))
	require.Equal(t, 403, send("POST", url, body, token.AccessToken))
	connect, e := gs.Create(grants.Input{UserID: owner.ID, AssetID: a.ID, Account: a.Username, Actions: []string{"connect"}}, "admin")
	require.NoError(t, e)
	require.Equal(t, 403, send("POST", url, `{"action":"protection_apply","request_id":"no-protect-role","protection":{"mode":"audit"}}`, token.AccessToken))
	require.Equal(t, 403, send("POST", url, `{"action":"protection_rollback","request_id":"no-protect-rollback"}`, token.AccessToken))
	require.Equal(t, 400, send("POST", url, `{"action":"install","version":"latest","request_id":"no-latest"}`, adminToken.AccessToken))
	pending := doJSONRequest(t, router, "POST", url, body, token.AccessToken, "127.0.0.1:12345")
	require.Equal(t, 202, pending.Code, pending.Body.String())
	var access struct {
		ReviewID string `json:"review_id"`
	}
	require.NoError(t, json.Unmarshal(pending.Body.Bytes(), &access))
	require.NoError(t, reviews.Resolve(access.ReviewID, "admin", true))
	created := doJSONRequest(t, router, "POST", url, body, token.AccessToken, "127.0.0.1:12345")
	require.Equal(t, 201, created.Code, created.Body.String())
	var job jobs.Job
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &job))
	require.Equal(t, "pending_review", job.State)
	require.NotNil(t, job.Plugin)
	require.Contains(t, job.Command, "host-plugin banhack233 install")
	require.Equal(t, 400, send("POST", "/api/v1/ops/jobs", `{"asset_id":"`+a.ID+`","command":"id","plugin":{"plugin":"banhack233"}}`, token.AccessToken))
	require.Equal(t, 400, send("POST", url, `{"action":"exec","request_id":"bad"}`, token.AccessToken))
	require.Equal(t, 404, send("GET", "/api/v1/ops/jobs/"+job.ID, "", foreign.AccessToken))
	require.NoError(t, gs.Delete(connect.ID))
	require.Equal(t, 403, send("POST", "/api/v1/ops/jobs/"+job.ID+"/review", `{"approve":true}`, adminToken.AccessToken))
	require.Zero(t, calls.Load())
	connect, e = gs.Create(grants.Input{UserID: owner.ID, AssetID: a.ID, Account: a.Username, Actions: []string{"connect"}}, "admin")
	require.NoError(t, e)
	require.Equal(t, 200, send("POST", "/api/v1/ops/jobs/"+job.ID+"/review", `{"approve":true}`, adminToken.AccessToken))
	require.Eventually(t, func() bool { return calls.Load() == 1 }, time.Second, 10*time.Millisecond)
	require.NoError(t, gs.Delete(connect.ID))
	require.Eventually(t, func() bool {
		j, _ := js.Get(job.ID)
		return j.State == "failed" && j.ErrorCode == "access_policy_denied"
	}, 3*time.Second, 20*time.Millisecond)
	detail := doJSONRequest(t, router, "GET", "/api/v1/ops/jobs/"+job.ID, "", token.AccessToken, "127.0.0.1:12345")
	require.NotContains(t, detail.Body.String(), "synthetic-plugin-remote-secret")
	require.False(t, pluginJobAllowed(Dependencies{Assets: as, HostPlugins: ps, RBAC: roles}, owner, a.ID, &hostplugins.Operation{Plugin: "banhack233", Version: "0.2.3", Action: "install", Binding: strings.Repeat("0", 64)}))
}
