package api

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
	"time"
)

func TestPlaybookAPIPublishingSourceSnapshotOutputsAndCurrentAuthorization(t *testing.T) {
	dir := t.TempDir()
	auth, e := coreauth.OpenService(filepath.Join(dir, "users.json"))
	require.NoError(t, e)
	_, e = auth.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, e)
	owner, e := auth.CreateUser("owner", "synthetic-playbook-password", coreauth.RoleOperator)
	require.NoError(t, e)
	_, e = auth.CreateUser("foreign", "synthetic-playbook-foreign", coreauth.RoleOperator)
	require.NoError(t, e)
	admin, e := auth.Authenticate("admin", bootstrapPassword)
	require.NoError(t, e)
	op, e := auth.Authenticate("owner", "synthetic-playbook-password")
	require.NoError(t, e)
	foreign, e := auth.Authenticate("foreign", "synthetic-playbook-foreign")
	require.NoError(t, e)
	assets := testAssetService(t)
	asset, e := assets.Create(coreassets.Input{Name: "native target", Host: "127.0.0.1", Port: 22, Username: "qa", Password: "synthetic-hidden", HostKeyFingerprint: validTestFingerprint()})
	require.NoError(t, e)
	gs, e := grants.OpenStore(filepath.Join(dir, "grants.json"))
	require.NoError(t, e)
	grant, e := gs.Create(grants.Input{UserID: owner.ID, AssetID: asset.ID, Account: "qa", Actions: []string{"connect"}}, "admin")
	require.NoError(t, e)
	js, e := jobs.Open(filepath.Join(dir, "jobs.json"), make([]byte, 32), nil, func(context.Context, string, string) (sshclient.ExecResult, error) {
		return sshclient.ExecResult{ExitCode: 0, Stdout: "remote\nJMS233_NATIVE_STATUS=changed\n"}, nil
	})
	require.NoError(t, e)
	defer js.Close()
	ops, e := operations.Open(filepath.Join(dir, "ops.json"), make([]byte, 32), nil, js)
	require.NoError(t, e)
	defer ops.Close()
	router := NewRouter("test", Dependencies{Auth: auth, Assets: assets, Grants: gs, Jobs: js, Operations: ops})
	call := func(method, path, token string, in any) (int, []byte) {
		t.Helper()
		body := ""
		if in != nil {
			raw, e := json.Marshal(in)
			require.NoError(t, e)
			body = string(raw)
		}
		r := doJSONRequest(t, router, method, path, body, token, "127.0.0.1:23456")
		return r.Code, r.Body.Bytes()
	}
	code, _ := call("GET", "/api/v1/ops/playbooks/capabilities", "", nil)
	assert.Equal(t, 401, code)
	code, raw := call("POST", "/api/v1/ops/playbooks/validate", op.AccessToken, map[string]any{"files": map[string]string{"main.yml": "- tasks: [{unsupported: secret-source}]"}})
	assert.Equal(t, 400, code)
	assert.Contains(t, string(raw), "field_unsupported")
	assert.NotContains(t, string(raw), "secret-source")
	in := operations.PlaybookInput{Name: "native API", Visibility: "organization", Files: map[string]string{"main.yml": "- tasks: [{command: {argv: [id]}}, {debug: {msg: local-private}}]"}}
	code, _ = call("POST", "/api/v1/ops/playbooks", op.AccessToken, in)
	assert.Equal(t, 403, code)
	in.Visibility = "private"
	code, raw = call("POST", "/api/v1/ops/playbooks", op.AccessToken, in)
	require.Equal(t, 201, code, string(raw))
	var book operations.PlaybookDetail
	require.NoError(t, json.Unmarshal(raw, &book))
	code, _ = call("GET", "/api/v1/ops/playbooks/"+book.ID, foreign.AccessToken, nil)
	assert.Equal(t, 404, code)
	in.Visibility = "organization"
	code, raw = call("POST", "/api/v1/ops/playbooks", admin.AccessToken, in)
	require.Equal(t, 201, code, string(raw))
	var shared operations.PlaybookDetail
	require.NoError(t, json.Unmarshal(raw, &shared))
	code, _ = call("GET", "/api/v1/ops/playbooks/"+shared.ID, op.AccessToken, nil)
	assert.Equal(t, 200, code)
	code, _ = call("PUT", "/api/v1/ops/playbooks/"+shared.ID, op.AccessToken, in)
	assert.Equal(t, 403, code)
	planBody := map[string]any{"name": "native API plan", "playbook_id": book.ID, "asset_ids": []string{asset.ID}, "kind": "batch", "request_id": "native-api-plan"}
	code, raw = call("POST", "/api/v1/ops/plans", op.AccessToken, planBody)
	require.Equal(t, 201, code, string(raw))
	var p operations.Plan
	require.NoError(t, json.Unmarshal(raw, &p))
	var run operations.Run
	require.Eventually(t, func() bool { p, _ = ops.Plan(p.ID); run, _ = ops.Run(p.LastRunID); return run.State == "succeeded" }, 8*time.Second, 20*time.Millisecond)
	code, raw = call("GET", "/api/v1/ops/runs/"+run.ID, op.AccessToken, nil)
	require.Equal(t, 200, code)
	assert.NotContains(t, string(raw), "local-private")
	assert.NotContains(t, string(raw), "pending_command")
	assert.NotContains(t, string(raw), "synthetic-hidden")
	step := run.Items[0].Steps[1]
	path := fmt.Sprintf("/api/v1/ops/runs/%s/steps/%s/%s", run.ID, asset.ID, step.ID)
	code, raw = call("GET", path, op.AccessToken, nil)
	assert.Equal(t, 200, code)
	assert.Contains(t, string(raw), "local-private")
	code, _ = call("GET", path, foreign.AccessToken, nil)
	assert.Equal(t, 404, code)
	code, _ = call("DELETE", fmt.Sprintf("/api/v1/ops/playbooks/%s?revision=1", book.ID), op.AccessToken, nil)
	assert.Equal(t, 204, code)
	code, raw = call("GET", "/api/v1/ops/runs/"+run.ID+"/program", op.AccessToken, nil)
	assert.Equal(t, 200, code)
	assert.Contains(t, string(raw), "local-private")
	require.NoError(t, gs.Delete(grant.ID))
	code, _ = call("POST", "/api/v1/ops/plans/"+p.ID+"/runs", op.AccessToken, map[string]string{"request_id": "revoked"})
	assert.Equal(t, 403, code)
	code, _ = call("POST", "/api/v1/ops/jobs", op.AccessToken, map[string]any{"asset_id": asset.ID, "command": "id\nprintf forged", "request_id": "forged", "playbook_step": map[string]string{"run_id": run.ID}})
	assert.Equal(t, 400, code)
}
