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
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecutionDirectoryAPIRejectsUnverifiedPathsAndStaleCommandPolicy(t *testing.T) {
	dir := t.TempDir()
	auth, err := coreauth.OpenService(filepath.Join(dir, "users"))
	require.NoError(t, err)
	_, err = auth.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, err)
	login, err := auth.Authenticate("admin", bootstrapPassword)
	require.NoError(t, err)
	inventory := testAssetService(t)
	asset, err := inventory.Create(assets.Input{Name: "Host", Host: "127.0.0.1", Port: 1, Username: "ops", Password: "synthetic-only", HostKeyFingerprint: validTestFingerprint()})
	require.NoError(t, err)
	filters, err := commandfilters.OpenStore(filepath.Join(dir, "rules"))
	require.NoError(t, err)
	rule := commandfilters.Input{Name: "same reviewed name", AssetID: asset.ID, Account: "ops", Match: "exact", Pattern: "pwd", Action: "review"}
	createdRule, err := filters.Create(rule, "admin")
	require.NoError(t, err)
	var calls atomic.Int32
	service, err := jobs.Open(filepath.Join(dir, "jobs"), make([]byte, 32), nil, func(context.Context, string, string) (sshclient.ExecResult, error) {
		calls.Add(1)
		return sshclient.ExecResult{ExitCode: 0}, nil
	})
	require.NoError(t, err)
	defer service.Close()
	router := NewRouter("test", Dependencies{Assets: inventory, Auth: auth, CommandFilters: filters, Jobs: service})
	post := func(input jobs.Input) jobs.Job {
		raw, err := json.Marshal(input)
		require.NoError(t, err)
		res := doJSONRequest(t, router, http.MethodPost, "/api/v1/ops/jobs", string(raw), login.AccessToken, "127.0.0.1:12345")
		require.Equal(t, 201, res.Code, res.Body.String())
		var job jobs.Job
		require.NoError(t, json.Unmarshal(res.Body.Bytes(), &job))
		return job
	}
	input := jobs.Input{AssetID: asset.ID, Command: "pwd", RequestID: "policy-snapshot"}
	first := post(input)
	assert.Equal(t, "pending_review", first.State)
	require.NoError(t, filters.Delete(createdRule.ID))
	_, err = filters.Create(rule, "admin")
	require.NoError(t, err)
	approval := doJSONRequest(t, router, http.MethodPost, "/api/v1/ops/jobs/"+first.ID+"/review", `{"approve":true}`, login.AccessToken, "127.0.0.1:12345")
	assert.Equal(t, 403, approval.Code)
	assert.Zero(t, calls.Load())
	assert.Equal(t, first.ID, post(input).ID, "retry returns the original receipt without reauthorizing its command")
	input.RequestID = "fresh-policy"
	fresh := post(input)
	approval = doJSONRequest(t, router, http.MethodPost, "/api/v1/ops/jobs/"+fresh.ID+"/review", `{"approve":true}`, login.AccessToken, "127.0.0.1:12345")
	require.Equal(t, 200, approval.Code, approval.Body.String())
	require.Eventually(t, func() bool { j, _ := service.Get(fresh.ID); return j.State == "succeeded" }, time.Second, 5*time.Millisecond)
	assert.EqualValues(t, 1, calls.Load())
	input.RequestID = "unconfined-directory"
	input.WorkingDirectory = "/srv/work/app"
	raw, err := json.Marshal(input)
	require.NoError(t, err)
	invalid := doJSONRequest(t, router, http.MethodPost, "/api/v1/ops/jobs", string(raw), login.AccessToken, "127.0.0.1:12345")
	assert.Equal(t, 400, invalid.Code)
	assert.EqualValues(t, 1, calls.Load())
}
