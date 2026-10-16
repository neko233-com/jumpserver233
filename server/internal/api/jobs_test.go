package api

import (
	"context"
	"encoding/json"
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJobsRequireConnectLoginReviewCommandReviewAndOwnerScope(t *testing.T) {
	dir := t.TempDir()
	identities, err := coreauth.OpenService(filepath.Join(dir, "users.json"))
	require.NoError(t, err)
	_, err = identities.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, err)
	owner, err := identities.CreateUser("operator", "an-operator-password-1234", coreauth.RoleOperator)
	require.NoError(t, err)
	_, err = identities.CreateUser("outsider", "an-outsider-password-1234", coreauth.RoleOperator)
	require.NoError(t, err)
	adminToken, err := identities.Authenticate("admin", bootstrapPassword)
	require.NoError(t, err)
	ownerToken, err := identities.Authenticate("operator", "an-operator-password-1234")
	require.NoError(t, err)
	otherToken, err := identities.Authenticate("outsider", "an-outsider-password-1234")
	require.NoError(t, err)
	assets := testAssetService(t)
	reviewRequired := true
	asset, err := assets.Create(coreassets.Input{Name: "qa", Host: "127.0.0.1", Port: 22, Username: "ops", Password: "ssh-secret-must-not-leak", HostKeyFingerprint: validTestFingerprint(), LoginReviewRequired: &reviewRequired})
	require.NoError(t, err)
	grantStore, err := grants.OpenStore(filepath.Join(dir, "grants.json"))
	require.NoError(t, err)
	_, err = grantStore.Create(grants.Input{UserID: owner.ID, AssetID: asset.ID, Account: "ops", Actions: []string{"view"}}, "admin")
	require.NoError(t, err)
	reviews, err := accessreviews.OpenStore(filepath.Join(dir, "reviews.json"))
	require.NoError(t, err)
	filters, err := commandfilters.OpenStore(filepath.Join(dir, "filters.json"))
	require.NoError(t, err)
	_, err = filters.Create(commandfilters.Input{Name: "review whoami", UserID: owner.ID, AssetID: asset.ID, Account: "ops", Match: "exact", Pattern: "whoami", Action: "review"}, "admin")
	require.NoError(t, err)
	var calls atomic.Int32
	service, err := jobs.Open(filepath.Join(dir, "jobs.json"), make([]byte, 32), nil, func(context.Context, string, string) (sshclient.ExecResult, error) {
		calls.Add(1)
		return sshclient.ExecResult{Stdout: "ops\n", ExitCode: 0}, nil
	})
	require.NoError(t, err)
	t.Cleanup(service.Close)
	router := NewRouter("test", Dependencies{Assets: assets, Auth: identities, Grants: grantStore, CommandFilters: filters, AccessReviews: reviews, Jobs: service})
	input := jobs.Input{AssetID: asset.ID, Command: "whoami", RequestID: "stable-request", TimeoutSeconds: 60}
	body, err := json.Marshal(input)
	require.NoError(t, err)
	denied := doJSONRequest(t, router, http.MethodPost, "/api/v1/ops/jobs", string(body), ownerToken.AccessToken, "127.0.0.1:12345")
	assert.Equal(t, 403, denied.Code)
	connect, err := grantStore.Create(grants.Input{UserID: owner.ID, AssetID: asset.ID, Account: "ops", Actions: []string{"connect"}}, "admin")
	require.NoError(t, err)
	pending := doJSONRequest(t, router, http.MethodPost, "/api/v1/ops/jobs", string(body), ownerToken.AccessToken, "127.0.0.1:12345")
	require.Equal(t, 202, pending.Code, pending.Body.String())
	var loginReview struct {
		ReviewID string `json:"review_id"`
	}
	require.NoError(t, json.Unmarshal(pending.Body.Bytes(), &loginReview))
	require.NoError(t, reviews.Resolve(loginReview.ReviewID, "admin", true))
	created := doJSONRequest(t, router, http.MethodPost, "/api/v1/ops/jobs", string(body), ownerToken.AccessToken, "127.0.0.1:12345")
	require.Equal(t, 201, created.Code, created.Body.String())
	var job jobs.Job
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &job))
	assert.Equal(t, "pending_review", job.State)
	assert.Zero(t, calls.Load())
	unauthorized := doJSONRequest(t, router, http.MethodPost, "/api/v1/ops/jobs/"+job.ID+"/review", `{"approve":true}`, ownerToken.AccessToken, "127.0.0.1:12345")
	assert.Equal(t, 403, unauthorized.Code)
	require.NoError(t, grantStore.Delete(connect.ID))
	changed := doJSONRequest(t, router, http.MethodPost, "/api/v1/ops/jobs/"+job.ID+"/review", `{"approve":true}`, adminToken.AccessToken, "127.0.0.1:12345")
	assert.Equal(t, 403, changed.Code)
	assert.Zero(t, calls.Load())
	_, err = grantStore.Create(grants.Input{UserID: owner.ID, AssetID: asset.ID, Account: "ops", Actions: []string{"connect"}}, "admin")
	require.NoError(t, err)
	approved := doJSONRequest(t, router, http.MethodPost, "/api/v1/ops/jobs/"+job.ID+"/review", `{"approve":true}`, adminToken.AccessToken, "127.0.0.1:12345")
	require.Equal(t, 200, approved.Code, approved.Body.String())
	require.Eventually(t, func() bool { j, _ := service.Get(job.ID); return j.State == "succeeded" }, time.Second, 5*time.Millisecond)
	again := doJSONRequest(t, router, http.MethodPost, "/api/v1/ops/jobs", string(body), ownerToken.AccessToken, "127.0.0.1:12345")
	require.Equal(t, 201, again.Code, again.Body.String())
	assert.Contains(t, again.Body.String(), job.ID)
	assert.EqualValues(t, 1, calls.Load())
	foreign := doJSONRequest(t, router, http.MethodGet, "/api/v1/ops/jobs/"+job.ID, "", otherToken.AccessToken, "127.0.0.1:12345")
	assert.Equal(t, 404, foreign.Code)
	list := doJSONRequest(t, router, http.MethodGet, "/api/v1/ops/jobs", "", otherToken.AccessToken, "127.0.0.1:12345")
	assert.Contains(t, list.Body.String(), `"total":0`)
	detail := doJSONRequest(t, router, http.MethodGet, "/api/v1/ops/jobs/"+job.ID, "", ownerToken.AccessToken, "127.0.0.1:12345")
	assert.Equal(t, 200, detail.Code)
	assert.NotContains(t, detail.Body.String(), "ssh-secret-must-not-leak")
	assert.Equal(t, "private, no-store", detail.Header().Get("Cache-Control"))
}
