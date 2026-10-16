package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOperationsEnforceScopeTemplateRevisionAndReauthorizeDuePlans(t *testing.T) {
	dir := t.TempDir()
	identities, err := coreauth.OpenService(filepath.Join(dir, "users.json"))
	require.NoError(t, err)
	_, err = identities.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, err)
	owner, err := identities.CreateUser("owner", "synthetic-owner-password", coreauth.RoleOperator)
	require.NoError(t, err)
	_, err = identities.CreateUser("foreign", "synthetic-foreign-password", coreauth.RoleOperator)
	require.NoError(t, err)
	adminToken, err := identities.Authenticate("admin", bootstrapPassword)
	require.NoError(t, err)
	ownerToken, err := identities.Authenticate("owner", "synthetic-owner-password")
	require.NoError(t, err)
	foreignToken, err := identities.Authenticate("foreign", "synthetic-foreign-password")
	require.NoError(t, err)
	assets := testAssetService(t)
	asset, err := assets.Create(coreassets.Input{Name: "qa", Host: "127.0.0.1", Port: 22, Username: "ops", Password: "synthetic-only-secret", HostKeyFingerprint: validTestFingerprint()})
	require.NoError(t, err)
	gs, err := grants.OpenStore(filepath.Join(dir, "grants.json"))
	require.NoError(t, err)
	var calls atomic.Int32
	js, err := jobs.Open(filepath.Join(dir, "jobs.json"), make([]byte, 32), nil, func(context.Context, string, string) (sshclient.ExecResult, error) {
		calls.Add(1)
		return sshclient.ExecResult{ExitCode: 0}, nil
	})
	require.NoError(t, err)
	defer js.Close()
	ops, err := operations.Open(filepath.Join(dir, "operations.json"), make([]byte, 32), nil, js)
	require.NoError(t, err)
	defer ops.Close()
	router := NewRouter("test", Dependencies{Auth: identities, Assets: assets, Grants: gs, Jobs: js, Operations: ops})
	templateResponse := doJSONRequest(t, router, "POST", "/api/v1/ops/templates", `{"name":"private template","command":"whoami","timeout_seconds":15}`, ownerToken.AccessToken, "127.0.0.1:12345")
	require.Equal(t, 201, templateResponse.Code, templateResponse.Body.String())
	var template operations.Template
	require.NoError(t, json.Unmarshal(templateResponse.Body.Bytes(), &template))
	for _, token := range []string{foreignToken.AccessToken, adminToken.AccessToken} {
		r := doJSONRequest(t, router, "GET", "/api/v1/ops/templates", "", token, "127.0.0.1:12345")
		assert.Equal(t, "[]\n", r.Body.String())
	}
	foreign := doJSONRequest(t, router, "PUT", "/api/v1/ops/templates/"+template.ID, `{"name":"x","command":"pwd","revision":1}`, foreignToken.AccessToken, "127.0.0.1:12345")
	assert.Equal(t, 404, foreign.Code)
	conflict := doJSONRequest(t, router, "PUT", "/api/v1/ops/templates/"+template.ID, `{"name":"x","command":"pwd","revision":7}`, ownerToken.AccessToken, "127.0.0.1:12345")
	assert.Equal(t, 409, conflict.Code)
	body := fmt.Sprintf(`{"name":"revoked","asset_ids":[%q],"template_id":%q,"kind":"once","run_at":%q,"request_id":"revoked"}`, asset.ID, template.ID, time.Now().Add(2*time.Second).UTC().Format(time.RFC3339Nano))
	denied := doJSONRequest(t, router, "POST", "/api/v1/ops/plans", body, ownerToken.AccessToken, "127.0.0.1:12345")
	assert.Equal(t, 403, denied.Code)
	grant, err := gs.Create(grants.Input{UserID: owner.ID, AssetID: asset.ID, Account: "ops", Actions: []string{"connect"}}, "admin")
	require.NoError(t, err)
	created := doJSONRequest(t, router, "POST", "/api/v1/ops/plans", body, ownerToken.AccessToken, "127.0.0.1:12345")
	require.Equal(t, 201, created.Code, created.Body.String())
	var p operations.Plan
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &p))
	require.NoError(t, gs.Delete(grant.ID))
	updated := doJSONRequest(t, router, "PUT", "/api/v1/ops/templates/"+template.ID, `{"name":"changed","command":"pwd","revision":1}`, ownerToken.AccessToken, "127.0.0.1:12345")
	require.Equal(t, 200, updated.Code)
	require.Eventually(t, func() bool { runs, n := ops.Runs(owner.ID, 0, 50); return n == 1 && runs[0].State == "failed" }, 5*time.Second, 20*time.Millisecond)
	runs, _ := ops.Runs(owner.ID, 0, 50)
	assert.Equal(t, "whoami", runs[0].Command)
	assert.Equal(t, "access_denied", runs[0].Items[0].ErrorCode)
	assert.Zero(t, calls.Load())
	hidden := doJSONRequest(t, router, "GET", "/api/v1/ops/runs/"+runs[0].ID, "", foreignToken.AccessToken, "127.0.0.1:12345")
	assert.Equal(t, 404, hidden.Code)
	cancel := doJSONRequest(t, router, "POST", "/api/v1/ops/runs/"+runs[0].ID+"/cancel", "", foreignToken.AccessToken, "127.0.0.1:12345")
	assert.Equal(t, 404, cancel.Code)
	list := doJSONRequest(t, router, "GET", "/api/v1/ops/plans", "", foreignToken.AccessToken, "127.0.0.1:12345")
	assert.Equal(t, "[]\n", list.Body.String())
	admin := doJSONRequest(t, router, "GET", "/api/v1/ops/runs/"+runs[0].ID, "", adminToken.AccessToken, "127.0.0.1:12345")
	assert.Equal(t, 200, admin.Code)
	assert.NotContains(t, admin.Body.String(), "synthetic-only-secret")
	assert.Equal(t, "private, no-store", admin.Header().Get("Cache-Control"))
	invalid := doJSONRequest(t, router, "GET", "/api/v1/ops/runs?limit=101", "", adminToken.AccessToken, "127.0.0.1:12345")
	assert.Equal(t, 400, invalid.Code)
	unauth := doJSONRequest(t, router, "GET", "/api/v1/ops/templates", "", "", "192.0.2.1:12345")
	assert.Equal(t, 401, unauth.Code)
}

func TestScheduledDispatchSharesLoginAndCommandReviews(t *testing.T) {
	dir := t.TempDir()
	identities, err := coreauth.OpenService(filepath.Join(dir, "users.json"))
	require.NoError(t, err)
	_, err = identities.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, err)
	owner, err := identities.CreateUser("owner", "synthetic-owner-password", coreauth.RoleOperator)
	require.NoError(t, err)
	token, err := identities.Authenticate("owner", "synthetic-owner-password")
	require.NoError(t, err)
	admin, err := identities.Authenticate("admin", bootstrapPassword)
	require.NoError(t, err)
	assets := testAssetService(t)
	required := true
	asset, err := assets.Create(coreassets.Input{Name: "qa", Host: "127.0.0.1", Port: 22, Username: "ops", Password: "synthetic-only", HostKeyFingerprint: validTestFingerprint(), LoginReviewRequired: &required})
	require.NoError(t, err)
	gs, err := grants.OpenStore(filepath.Join(dir, "grants.json"))
	require.NoError(t, err)
	_, err = gs.Create(grants.Input{UserID: owner.ID, AssetID: asset.ID, Account: "ops", Actions: []string{"connect"}}, "admin")
	require.NoError(t, err)
	reviews, err := accessreviews.OpenStore(filepath.Join(dir, "reviews.json"))
	require.NoError(t, err)
	filters, err := commandfilters.OpenStore(filepath.Join(dir, "filters.json"))
	require.NoError(t, err)
	_, err = filters.Create(commandfilters.Input{Name: "review", UserID: owner.ID, AssetID: asset.ID, Account: "ops", Match: "exact", Pattern: "whoami", Action: "review"}, "admin")
	require.NoError(t, err)
	var calls atomic.Int32
	js, err := jobs.Open(filepath.Join(dir, "jobs.json"), make([]byte, 32), nil, func(context.Context, string, string) (sshclient.ExecResult, error) {
		calls.Add(1)
		return sshclient.ExecResult{ExitCode: 0}, nil
	})
	require.NoError(t, err)
	defer js.Close()
	ops, err := operations.Open(filepath.Join(dir, "operations.json"), make([]byte, 32), nil, js)
	require.NoError(t, err)
	defer ops.Close()
	router := NewRouter("test", Dependencies{Auth: identities, Assets: assets, Grants: gs, AccessReviews: reviews, CommandFilters: filters, Jobs: js, Operations: ops})
	makePlan := func(request string) operations.Run {
		t.Helper()
		body := fmt.Sprintf(`{"name":%q,"asset_ids":[%q],"command":"whoami","kind":"batch","request_id":%q}`, request, asset.ID, request)
		r := doJSONRequest(t, router, "POST", "/api/v1/ops/plans", body, token.AccessToken, "127.0.0.1:12345")
		require.Equal(t, 201, r.Code, r.Body.String())
		var p operations.Plan
		require.NoError(t, json.Unmarshal(r.Body.Bytes(), &p))
		var run operations.Run
		require.Eventually(t, func() bool {
			current, _ := ops.Plan(p.ID)
			run, _ = ops.Run(current.LastRunID)
			return len(run.Items) > 0 && run.Items[0].State == "waiting_review"
		}, 3*time.Second, 10*time.Millisecond)
		return run
	}
	run := makePlan("approved")
	require.NoError(t, reviews.Resolve(run.Items[0].ReviewID, "admin", true))
	require.Eventually(t, func() bool { run, _ = ops.Run(run.ID); return run.Items[0].State == "pending_review" }, 4*time.Second, 10*time.Millisecond)
	assert.Zero(t, calls.Load())
	approved := doJSONRequest(t, router, http.MethodPost, "/api/v1/ops/jobs/"+run.Items[0].JobID+"/review", `{"approve":true}`, admin.AccessToken, "127.0.0.1:12345")
	require.Equal(t, 200, approved.Code, approved.Body.String())
	require.Eventually(t, func() bool { r, _ := ops.Run(run.ID); return r.State == "succeeded" }, 3*time.Second, 10*time.Millisecond)
	assert.EqualValues(t, 1, calls.Load())
	denied := makePlan("denied")
	require.NoError(t, reviews.Resolve(denied.Items[0].ReviewID, "admin", false))
	require.Eventually(t, func() bool { r, _ := ops.Run(denied.ID); return r.State == "failed" && r.Items[0].State == "denied" }, 4*time.Second, 10*time.Millisecond)
	assert.EqualValues(t, 1, calls.Load())
}
