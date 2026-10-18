package api

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalendarAPIRevisionReplayOwnershipAndCurrentTargetRights(t *testing.T) {
	dir := t.TempDir()
	identities, e := coreauth.OpenService(filepath.Join(dir, "users.json"))
	require.NoError(t, e)
	_, e = identities.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, e)
	owner, e := identities.CreateUser("owner", "synthetic-calendar-owner", coreauth.RoleOperator)
	require.NoError(t, e)
	_, e = identities.CreateUser("foreign", "synthetic-calendar-foreign", coreauth.RoleOperator)
	require.NoError(t, e)
	admin, e := identities.Authenticate("admin", bootstrapPassword)
	require.NoError(t, e)
	token, e := identities.Authenticate("owner", "synthetic-calendar-owner")
	require.NoError(t, e)
	other, e := identities.Authenticate("foreign", "synthetic-calendar-foreign")
	require.NoError(t, e)
	assets := testAssetService(t)
	asset, e := assets.Create(coreassets.Input{Name: "calendar", Host: "127.0.0.1", Port: 22, Username: "ops", Password: "synthetic-calendar-only", HostKeyFingerprint: validTestFingerprint()})
	require.NoError(t, e)
	gs, e := grants.OpenStore(filepath.Join(dir, "grants.json"))
	require.NoError(t, e)
	grant, e := gs.Create(grants.Input{UserID: owner.ID, AssetID: asset.ID, Account: "ops", Actions: []string{"connect"}}, "admin")
	require.NoError(t, e)
	js, e := jobs.Open(filepath.Join(dir, "jobs.json"), make([]byte, 32), nil, func(context.Context, string, string) (sshclient.ExecResult, error) {
		t.Error("future calendar must not dispatch")
		return sshclient.ExecResult{}, nil
	})
	require.NoError(t, e)
	defer js.Close()
	ops, e := operations.Open(filepath.Join(dir, "ops.json"), make([]byte, 32), nil, js)
	require.NoError(t, e)
	defer ops.Close()
	router := NewRouter("calendar", Dependencies{Auth: identities, Assets: assets, Grants: gs, Jobs: js, Operations: ops})
	body := fmt.Sprintf(`{"name":"calendar","asset_ids":[%q],"command":"whoami","kind":"cron","cron_expression":"0 2 * * *","timezone":"Asia/Shanghai","request_id":"calendar-create","run_at":%q}`, asset.ID, time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339))
	created := doJSONRequest(t, router, "POST", "/api/v1/ops/plans", body, token.AccessToken, "127.0.0.1:11223")
	require.Equal(t, 201, created.Code, created.Body.String())
	var p operations.Plan
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &p))
	assert.Equal(t, 1, p.ConfigRevision)
	path := "/api/v1/ops/plans/" + p.ID
	for _, suffix := range []string{"", "/events"} {
		hidden := doJSONRequest(t, router, "GET", path+suffix, "", other.AccessToken, "127.0.0.1:11223")
		assert.Equal(t, 404, hidden.Code)
		view := doJSONRequest(t, router, "GET", path+suffix, "", admin.AccessToken, "127.0.0.1:11223")
		assert.Equal(t, 200, view.Code)
		assert.Equal(t, "private, no-store", view.Header().Get("Cache-Control"))
		assert.NotContains(t, view.Body.String(), "synthetic-calendar-only")
	}
	schedule := `{"revision":1,"kind":"cron","cron_expression":"0 9 * * MON-FRI","timezone":"UTC"}`
	hidden := doJSONRequest(t, router, "PUT", path+"/schedule", schedule, other.AccessToken, "127.0.0.1:11223")
	assert.Equal(t, 404, hidden.Code)
	updated := doJSONRequest(t, router, "PUT", path+"/schedule", schedule, token.AccessToken, "127.0.0.1:11223")
	require.Equal(t, 200, updated.Code, updated.Body.String())
	require.NoError(t, json.Unmarshal(updated.Body.Bytes(), &p))
	assert.Equal(t, 2, p.ConfigRevision)
	assert.Equal(t, "whoami", p.Command)
	stale := doJSONRequest(t, router, "PUT", path+"/schedule", schedule, token.AccessToken, "127.0.0.1:11223")
	assert.Equal(t, 409, stale.Code)
	replay := doJSONRequest(t, router, "POST", "/api/v1/ops/plans", body, token.AccessToken, "127.0.0.1:11223")
	require.Equal(t, 201, replay.Code, replay.Body.String())
	assert.Contains(t, replay.Body.String(), `"config_revision":2`)
	foreignOrigin := doJSONRequest(t, router, "POST", "/api/v1/ops/plans", body, token.AccessToken, "192.0.2.22:11223")
	assert.Equal(t, 409, foreignOrigin.Code)
	missingRevision := doJSONRequest(t, router, "PUT", path, `{"enabled":false}`, token.AccessToken, "127.0.0.1:11223")
	assert.Equal(t, 409, missingRevision.Code)
	pause := doJSONRequest(t, router, "PUT", path, `{"enabled":false,"revision":2}`, token.AccessToken, "127.0.0.1:11223")
	require.Equal(t, 200, pause.Code, pause.Body.String())
	require.NoError(t, gs.Delete(grant.ID))
	for _, tt := range []struct{ suffix, payload string }{
		{"", `{"enabled":true,"revision":3}`},
		{"/schedule", `{"revision":3,"kind":"cron","cron_expression":"* * * * *","timezone":"UTC"}`},
	} {
		denied := doJSONRequest(t, router, "PUT", path+tt.suffix, tt.payload, admin.AccessToken, "127.0.0.1:11223")
		assert.Equal(t, 403, denied.Code, denied.Body.String())
	}
	history := doJSONRequest(t, router, "GET", path+"/events?limit=2&offset=0", "", token.AccessToken, "127.0.0.1:11223")
	require.Equal(t, 200, history.Code)
	var events struct {
		Results []operations.ScheduleEvent `json:"results"`
		Total   int                        `json:"total"`
	}
	require.NoError(t, json.Unmarshal(history.Body.Bytes(), &events))
	assert.Equal(t, 3, events.Total)
	require.Len(t, events.Results, 2)
	assert.Equal(t, "paused", events.Results[0].Action)
	assert.Equal(t, owner.ID, events.Results[0].Actor.ID)
	assert.Equal(t, "updated", events.Results[1].Action)
	list := doJSONRequest(t, router, "GET", "/api/v1/ops/plans?offset=0&limit=1", "", token.AccessToken, "127.0.0.1:11223")
	assert.Equal(t, 200, list.Code)
	assert.Contains(t, list.Body.String(), `"total":1`)
	empty := doJSONRequest(t, router, "GET", "/api/v1/ops/plans?offset=0&limit=1", "", other.AccessToken, "127.0.0.1:11223")
	assert.Contains(t, empty.Body.String(), `"total":0`)
	for _, uri := range []string{path + "/events?limit=101", path + "/events?offset=-1", "/api/v1/ops/plans?offset=bad", "/api/v1/ops/plans?limit=0"} {
		bad := doJSONRequest(t, router, "GET", uri, "", token.AccessToken, "127.0.0.1:11223")
		assert.Equal(t, 400, bad.Code)
	}
}

func TestCalendarPreviewAPIIsAuthenticatedAndStateless(t *testing.T) {
	js, e := jobs.Open(filepath.Join(t.TempDir(), "jobs.json"), make([]byte, 32), nil, func(context.Context, string, string) (sshclient.ExecResult, error) {
		t.Error("preview dispatched a job")
		return sshclient.ExecResult{}, nil
	})
	require.NoError(t, e)
	defer js.Close()
	ops, e := operations.Open(filepath.Join(t.TempDir(), "ops.json"), make([]byte, 32), nil, js)
	require.NoError(t, e)
	defer ops.Close()
	identities, e := coreauth.OpenService(filepath.Join(t.TempDir(), "users.json"))
	require.NoError(t, e)
	router := NewRouter("calendar", Dependencies{AdminToken: "synthetic-calendar-token", Auth: identities, Assets: testAssetService(t), Jobs: js, Operations: ops})
	body := `{"kind":"cron","cron_expression":"30 1 * * *","timezone":"America/New_York","fold_policy":"both","after":"2026-11-01T04:00:00Z","limit":2}`
	denied := doJSONRequest(t, router, "POST", "/api/v1/ops/schedules/preview", body, "", "127.0.0.1:12345")
	assert.Equal(t, 401, denied.Code)
	good := doJSONRequest(t, router, "POST", "/api/v1/ops/schedules/preview", body, "synthetic-calendar-token", "127.0.0.1:12345")
	require.Equal(t, 200, good.Code, good.Body.String())
	var preview operations.SchedulePreview
	require.NoError(t, json.Unmarshal(good.Body.Bytes(), &preview))
	require.Len(t, preview.Occurrences, 2)
	assert.Equal(t, time.Hour, preview.Occurrences[1].At.Sub(preview.Occurrences[0].At))
	assert.Empty(t, ops.Plans(""))
	bad := doJSONRequest(t, router, "POST", "/api/v1/ops/schedules/preview", `{"kind":"cron","cron_expression":"@daily","timezone":"UTC"}`, "synthetic-calendar-token", "127.0.0.1:12345")
	assert.Equal(t, 400, bad.Code)
}
