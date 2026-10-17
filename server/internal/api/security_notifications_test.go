package api

import (
	"encoding/json"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	"github.com/neko233-com/jumpserver233/server/internal/core/accountrisks"
	"github.com/neko233-com/jumpserver233/server/internal/core/agentevents"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandalerts"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/notifications"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
	"time"
)

func securityNotificationEnv(t *testing.T) *policyTestEnv {
	t.Helper()
	e := newPolicyEnv(t)
	dir := t.TempDir()
	var err error
	e.d.AccessReviews, err = accessreviews.OpenStore(filepath.Join(dir, "reviews.json"))
	require.NoError(t, err)
	e.d.AgentEvents, err = agentevents.Open(filepath.Join(dir, "events"), make([]byte, 32), nil)
	require.NoError(t, err)
	e.d.AccountRisks, err = accountrisks.Open(filepath.Join(dir, "risks.json"), make([]byte, 32), nil)
	require.NoError(t, err)
	e.d.Notifications, err = notifications.Open(filepath.Join(dir, "notifications.json"), make([]byte, 32), nil)
	require.NoError(t, err)
	e.d.CommandAlerts, err = commandalerts.Open(filepath.Join(dir, "command-alerts.json"), make([]byte, 32), nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		e.d.Notifications.Close()
		e.d.Sessions.CloseAll()
		e.d.CommandAlerts.Close()
		e.d.AccountRisks.Close()
		e.d.AgentEvents.Close()
	})
	e.router = NewRouter("test", e.d)
	return e
}
func TestSecurityNotificationsCommandOwnerMetadataAndLateReviewerPermission(t *testing.T) {
	e := securityNotificationEnv(t)
	r := commandalerts.Record{ID: "command-event-owned", SessionID: "session-1", AssetID: e.asset.ID, AssetName: e.asset.Name, Account: e.asset.Username, OwnerID: e.admin.ID, ActorID: e.operator.ID, Actor: e.operator.Username, State: "command_denied", Rule: "Synthetic rule", At: time.Now().UTC()}
	require.NoError(t, e.d.CommandAlerts.Publish(r))
	e.d.Notifications.Tick()
	owner := e.send(t, "GET", "/api/v1/notifications/inbox?limit=100", nil, e.token, "192.0.2.1:4000")
	assert.Contains(t, owner.Body.String(), r.ID)
	meta := e.send(t, "GET", "/api/v1/notifications/sources/command-alerts/"+r.ID, nil, e.token, "192.0.2.1:4000")
	require.Equal(t, 200, meta.Code)
	assert.NotContains(t, meta.Body.String(), "command\"")
	assert.NotContains(t, meta.Body.String(), "session_id")
	assert.Contains(t, meta.Body.String(), r.Actor)
	// A snapshot must revisit an existing pending request after role assignment.
	review, err := e.d.AccessReviews.Request(e.admin.ID, e.admin.Username, e.asset.ID, e.asset.Name, e.asset.Username)
	require.NoError(t, err)
	e.d.Notifications.Tick()
	inbox := func() string {
		return e.send(t, "GET", "/api/v1/notifications/inbox?limit=100", nil, e.token, "192.0.2.1:4000").Body.String()
	}
	assert.NotContains(t, inbox(), review.ID)
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "late reviewer", Permissions: []string{"reviews.login.manage"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	e.d.Notifications.Tick()
	assert.Contains(t, inbox(), review.ID)
	_, err = e.d.RBAC.SaveRole(role.ID, rbac.RoleInput{Name: role.Name, Revision: role.Revision, Permissions: []string{"notifications.audit"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.NotContains(t, inbox(), review.ID)
	meta = e.send(t, "GET", "/api/v1/notifications/sources/access-reviews/"+review.ID, nil, e.token, "192.0.2.1:4000")
	assert.Equal(t, 404, meta.Code)
	e.d.OrganizationAllowed = func(coreauth.User) bool { return false }
	e.router = NewRouter("test", e.d)
	meta = e.send(t, "GET", "/api/v1/notifications/sources/command-alerts/"+r.ID, nil, e.token, "192.0.2.1:4000")
	assert.Equal(t, 403, meta.Code)
}
func TestSecurityNotificationsAssetReviewPendingAndCurrentApprovalAuthority(t *testing.T) {
	e := securityNotificationEnv(t)
	review, err := e.d.AccessReviews.Request(e.operator.ID, e.operator.Username, e.asset.ID, e.asset.Name, e.asset.Username)
	require.NoError(t, err)
	e.d.Notifications.Tick()
	get := func(token string) string {
		return e.send(t, "GET", "/api/v1/notifications/inbox?limit=100", nil, token, "192.0.2.1:4000").Body.String()
	}
	assert.Contains(t, get(e.adminToken), "asset_review_pending")
	assert.Contains(t, get(e.token), "asset_review_pending")
	mine := e.send(t, "GET", "/api/v1/notifications/sources/access-reviews/"+review.ID, nil, e.token, "192.0.2.1:4000")
	require.Equal(t, 200, mine.Code)
	var detail notificationSourceDetail
	require.NoError(t, json.Unmarshal(mine.Body.Bytes(), &detail))
	assert.False(t, detail.CanReview)
	assert.NotContains(t, mine.Body.String(), "permit")
	assert.NotContains(t, mine.Body.String(), "request_scope")
	assert.NotContains(t, mine.Body.String(), "synthetic-private-password")
	decided := e.send(t, "POST", "/api/v1/access-reviews/"+review.ID+"/approve", nil, e.adminToken, "192.0.2.1:4000")
	require.Equal(t, 204, decided.Code)
	e.d.Notifications.Tick()
	assert.NotContains(t, get(e.adminToken), "asset_review_pending")
	assert.Contains(t, get(e.token), "asset_review_approved")
}
func TestSecurityNotificationsDelegatedJobReviewerGetsOnlyPendingDetailsAndNoExternalCommand(t *testing.T) {
	e := securityNotificationEnv(t)
	user, err := e.d.Auth.CreateUser("security.reviewer", "synthetic-security-reviewer-password", coreauth.RoleOperator)
	require.NoError(t, err)
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "review only", Permissions: []string{"jobs.review"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: user.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	auth, err := e.d.Auth.Authenticate(user.Username, "synthetic-security-reviewer-password")
	require.NoError(t, err)
	j, err := e.d.Jobs.Submit(jobs.Input{AssetID: e.asset.ID, Command: "echo synthetic-sensitive-command", TimeoutSeconds: 30, RequestID: "security-review"}, e.operator.ID, e.operator.Username, e.asset.Name, e.asset.Username, "review", "Synthetic rule")
	require.NoError(t, err)
	e.d.Notifications.Tick()
	inbox := e.send(t, "GET", "/api/v1/notifications/inbox", nil, auth.AccessToken, "192.0.2.1:4000")
	require.Equal(t, 200, inbox.Code)
	assert.Contains(t, inbox.Body.String(), "job_review_pending")
	assert.NotContains(t, inbox.Body.String(), j.Command)
	meta := e.send(t, "GET", "/api/v1/notifications/sources/job-security/"+j.ID, nil, auth.AccessToken, "192.0.2.1:4000")
	require.Equal(t, 200, meta.Code)
	assert.Contains(t, meta.Body.String(), j.Command)
	assert.NotContains(t, meta.Body.String(), "stdout")
	assert.NotContains(t, meta.Body.String(), "plugin")
	assert.NotContains(t, meta.Body.String(), "binding")
	denied := e.send(t, "POST", "/api/v1/ops/jobs/"+j.ID+"/review", map[string]bool{"approve": false}, auth.AccessToken, "192.0.2.1:4000")
	require.Equal(t, 200, denied.Code)
	e.d.Notifications.Tick()
	meta = e.send(t, "GET", "/api/v1/notifications/sources/job-security/"+j.ID, nil, auth.AccessToken, "192.0.2.1:4000")
	assert.Equal(t, 404, meta.Code)
	owner := e.send(t, "GET", "/api/v1/notifications/inbox", nil, e.token, "192.0.2.1:4000")
	assert.Contains(t, owner.Body.String(), "job_review_denied")
	assert.NotContains(t, owner.Body.String(), j.Command)
}
func TestSecurityNotificationsAgentMetadataScopeAndNotificationRoleDoesNotGrantHostAccess(t *testing.T) {
	e := securityNotificationEnv(t)
	event := hostagent.Event{Sequence: 1, ID: fmt.Sprintf("%032x", 1), Attempt: fmt.Sprintf("%032x", 1), At: time.Now().UTC(), Kind: "repair_failed", Trigger: "supervisor", ConfigSHA: hostagent.SHA([]byte("synthetic-agent-private-configuration")), PreviousHash: hostagent.SHA(nil), ErrorCode: "kernel_unavailable"}
	event.Hash = hostagent.EventHash(event)
	page := hostagent.EventSnapshot{Format: hostagent.EventFormat, Stream: fmt.Sprintf("%032x", 1), FirstSequence: 1, LastSequence: 1, AnchorHash: event.PreviousHash, Events: []hostagent.Event{event}}
	_, err := e.d.AgentEvents.Import(agentevents.Source{AssetID: e.asset.ID, AssetName: e.asset.Name, Account: e.asset.Username}, agentevents.Collector{ID: e.admin.ID, Name: e.admin.Username, JobID: "synthetic-collect"}, page.Requested, page)
	require.NoError(t, err)
	e.d.Notifications.Tick()
	inbox := e.send(t, "GET", "/api/v1/notifications/inbox", nil, e.adminToken, "192.0.2.1:4000")
	assert.Contains(t, inbox.Body.String(), "agent_repair_failed")
	assert.NotContains(t, inbox.Body.String(), event.ConfigSHA)
	assert.NotContains(t, inbox.Body.String(), "kernel_unavailable")
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "notification only", Permissions: []string{"notifications.manage", "notifications.audit"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	meta := e.send(t, "GET", "/api/v1/notifications/sources/agent-events/agent-event-1", nil, e.token, "192.0.2.1:4000")
	assert.Equal(t, 404, meta.Code)
	meta = e.send(t, "GET", "/api/v1/notifications/sources/agent-events/agent-event-1", nil, e.adminToken, "192.0.2.1:4000")
	require.Equal(t, 200, meta.Code)
	assert.NotContains(t, meta.Body.String(), event.ConfigSHA)
}
