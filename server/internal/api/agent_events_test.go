package api

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/agentevents"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
	"time"
)

func TestAgentEventReadAndCollectionRequireCurrentServerPermissions(t *testing.T) {
	dir := t.TempDir()
	auth, e := coreauth.OpenService(filepath.Join(dir, "users"))
	require.NoError(t, e)
	_, e = auth.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, e)
	owner, e := auth.CreateUser("agent.inspector", "synthetic-agent-inspector-password", coreauth.RoleOperator)
	require.NoError(t, e)
	admin, e := auth.Authenticate("admin", bootstrapPassword)
	require.NoError(t, e)
	token, e := auth.Authenticate(owner.Username, "synthetic-agent-inspector-password")
	require.NoError(t, e)
	roles, e := rbac.Open(filepath.Join(dir, "roles"), nil)
	require.NoError(t, e)
	role, e := roles.SaveRole("", rbac.RoleInput{Name: "agent inspector", Permissions: []string{"plugins.inspect"}}, "admin", "admin")
	require.NoError(t, e)
	_, e = roles.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: owner.ID, RoleIDs: []string{role.ID}}, "admin", "admin")
	require.NoError(t, e)
	as := testAssetService(t)
	a, e := as.Create(assets.Input{Name: "Agent QA", Host: "127.0.0.1", Port: 22, Username: "ops", Password: "synthetic-agent-secret", HostKeyFingerprint: validTestFingerprint()})
	require.NoError(t, e)
	gs, e := grants.OpenStore(filepath.Join(dir, "grants"))
	require.NoError(t, e)
	grant, e := gs.Create(grants.Input{UserID: owner.ID, AssetID: a.ID, Account: a.Username, Actions: []string{"view"}}, "admin")
	require.NoError(t, e)
	js, e := jobs.Open(filepath.Join(dir, "jobs"), make([]byte, 32), nil, func(context.Context, string, string) (sshclient.ExecResult, error) {
		t.Error("unexpected shell")
		return sshclient.ExecResult{}, nil
	})
	require.NoError(t, e)
	defer js.Close()
	ops, e := operations.Open(filepath.Join(dir, "operations"), make([]byte, 32), nil, js)
	require.NoError(t, e)
	defer ops.Close()
	events, e := agentevents.Open(filepath.Join(dir, "events"), make([]byte, 32), nil)
	require.NoError(t, e)
	defer events.Close()
	event := hostagent.Event{Sequence: 1, ID: fmt.Sprintf("%032x", 1), Attempt: fmt.Sprintf("%032x", 1), At: time.Now().UTC(), Kind: "repair_completed", Trigger: "supervisor", ConfigSHA: hostagent.SHA(nil), PreviousHash: hostagent.SHA(nil)}
	event.Hash = hostagent.EventHash(event)
	_, e = events.Import(agentevents.Source{AssetID: a.ID, AssetName: a.Name, Account: a.Username}, agentevents.Collector{ID: "collector", JobID: "job-qa"}, hostagent.EventCursor{}, hostagent.EventSnapshot{Format: hostagent.EventFormat, Stream: fmt.Sprintf("%032x", 1), FirstSequence: 1, LastSequence: 1, AnchorHash: hostagent.SHA(nil), Events: []hostagent.Event{event}})
	require.NoError(t, e)
	router := NewRouter("test", Dependencies{Auth: auth, Assets: as, Jobs: js, Operations: ops, HostPlugins: hostplugins.New(nil, nil), AgentEvents: events, RBAC: roles, Grants: gs})
	send := func(method, url, body, access string) int {
		return doJSONRequest(t, router, method, url, body, access, "127.0.0.1:12345").Code
	}
	base := "/api/v1/assets/" + a.ID + "/agent-events"
	require.Equal(t, 404, send("GET", base, "", token.AccessToken))
	require.Equal(t, 403, send("GET", "/api/v1/audit/agent-events", "", token.AccessToken))
	require.NoError(t, gs.Delete(grant.ID))
	_, e = gs.Create(grants.Input{UserID: owner.ID, AssetID: a.ID, Account: a.Username, Actions: []string{"view", "connect"}}, "admin")
	require.NoError(t, e)
	require.Equal(t, 200, send("GET", base, "", token.AccessToken))
	require.Equal(t, 403, send("POST", base+"/collection", `{"enabled":true,"request_id":"denied","interval_seconds":60}`, token.AccessToken))
	require.Equal(t, 201, send("POST", base+"/collection", `{"enabled":true,"request_id":"admin-collection","interval_seconds":60}`, admin.AccessToken))
	require.Equal(t, 400, send("POST", base+"/collection", `{"enabled":true,"request_id":"forged","host_plugin":{}}`, admin.AccessToken))
	require.Equal(t, 400, send("POST", "/api/v1/assets/"+a.ID+"/host-plugins/banhack233/jobs", `{"action":"events_collect","request_id":"forged"}`, admin.AccessToken))
	require.Equal(t, 200, send("GET", "/api/v1/audit/agent-events", "", admin.AccessToken))
	r := doJSONRequest(t, router, "GET", base, "", token.AccessToken, "127.0.0.1:12345")
	var page agentevents.Page
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &page))
	require.Len(t, page.Results, 1)
	require.Equal(t, "collector", page.Results[0].Collector.ID)
}
