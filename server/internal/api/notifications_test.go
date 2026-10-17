package api

import (
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/core/notifications"
	"github.com/neko233-com/jumpserver233/server/internal/core/rotationplans"
	"github.com/neko233-com/jumpserver233/server/internal/core/tickets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
	"time"
)

func TestNotificationRotationCancellationMetadataAndPermissionBoundary(t *testing.T) {
	e := rotationAPIEnv(t)
	var err error
	e.d.Notifications, err = notifications.Open(filepath.Join(t.TempDir(), "notifications.json"), make([]byte, 32), nil)
	require.NoError(t, err)
	defer e.d.Notifications.Close()
	e.router = NewRouter("test", e.d)
	created := e.send(t, "POST", "/api/v1/accounts/rotation-plans", rotationplans.PlanInput{Name: "Synthetic notification rotation", Kind: "manual", Targets: []rotationplans.Selection{{AccountID: e.asset.ID}}}, e.adminToken, "192.0.2.1:4000")
	require.Equal(t, 201, created.Code, created.Body.String())
	var plan rotationplans.Plan
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &plan))
	submitted := e.send(t, "POST", "/api/v1/accounts/rotation-plans/"+plan.ID+"/runs", map[string]string{"request_id": "notification-cancel"}, e.adminToken, "192.0.2.1:4000")
	require.Equal(t, 202, submitted.Code, submitted.Body.String())
	var run rotationplans.Run
	require.NoError(t, json.Unmarshal(submitted.Body.Bytes(), &run))
	cancelled := e.send(t, "POST", "/api/v1/accounts/rotation-runs/"+run.ID+"/cancel", nil, e.adminToken, "192.0.2.1:4000")
	require.Equal(t, 204, cancelled.Code, cancelled.Body.String())
	e.d.Notifications.Tick()
	inbox := e.send(t, "GET", "/api/v1/notifications/inbox", nil, e.adminToken, "192.0.2.1:4000")
	assert.Contains(t, inbox.Body.String(), "rotation")
	assert.Contains(t, inbox.Body.String(), run.ID)
	assert.NotContains(t, inbox.Body.String(), e.asset.Host)
	assert.NotContains(t, inbox.Body.String(), "Binding")
	other := e.send(t, "GET", "/api/v1/notifications/inbox", nil, e.token, "192.0.2.1:4000")
	assert.NotContains(t, other.Body.String(), run.ID)
}

func TestNotificationAPIOrganizationPrincipalSecretsCASAndTicketRecipients(t *testing.T) {
	e := newPolicyEnv(t)
	var err error
	e.d.Notifications, err = notifications.Open(filepath.Join(t.TempDir(), "notifications.json"), make([]byte, 32), nil)
	require.NoError(t, err)
	defer e.d.Notifications.Close()
	e.d.Tickets, err = tickets.Open(filepath.Join(t.TempDir(), "tickets.json"), make([]byte, 32), nil)
	require.NoError(t, err)
	defer e.d.Tickets.Close()
	e.router = NewRouter("test", e.d)
	send := func(method, path string, body any, token string) int {
		r := e.send(t, method, "/api/v1/notifications"+path, body, token, "192.0.2.1:4000")
		return r.Code
	}
	assert.Equal(t, 401, send("GET", "/inbox", nil, ""))
	assert.Equal(t, 403, send("GET", "/settings", nil, e.token))
	assert.Equal(t, 403, send("GET", "/audit", nil, e.token))
	assert.Equal(t, 200, send("GET", "/preferences", nil, e.token))
	assert.Equal(t, 400, send("GET", "/inbox?limit=1000", nil, e.token))
	assert.Equal(t, 400, send("GET", "/inbox?unread=wrong", nil, e.token))
	cfg, err := e.d.Notifications.Settings(t.Context(), e.admin.ID)
	require.NoError(t, err)
	secret := "synthetic-setting-secret"
	updated := e.send(t, "PUT", "/api/v1/notifications/settings", notifications.SettingsInput{Revision: cfg.Revision, SMTP: cfg.SMTP, WebhookSecret: &secret}, e.adminToken, "192.0.2.1:4000")
	require.Equal(t, 200, updated.Code)
	assert.NotContains(t, updated.Body.String(), secret)
	assert.Equal(t, 409, send("PUT", "/settings", notifications.SettingsInput{Revision: cfg.Revision, SMTP: cfg.SMTP}, e.adminToken))
	assert.Equal(t, 400, send("POST", "/test", map[string]string{"request_id": "synthetic", "body": "forbidden"}, e.token))
	assert.Equal(t, 200, send("POST", "/test", map[string]string{"request_id": "synthetic"}, e.token))
	mine := e.send(t, "GET", "/api/v1/notifications/inbox", nil, e.token, "192.0.2.1:4000")
	assert.Contains(t, mine.Body.String(), "synthetic")
	other := e.send(t, "GET", "/api/v1/notifications/inbox", nil, e.adminToken, "192.0.2.1:4000")
	assert.NotContains(t, other.Body.String(), "synthetic")
	policyIn := tickets.PolicyInput{Name: "Synthetic notification scope", Enabled: true, AllMembers: true, MaxDurationMinutes: 60, ApprovalTTLMinutes: 60, Stages: []tickets.Stage{{Name: "Review", Subjects: []tickets.Subject{{Kind: "user", ID: e.admin.ID}}}}, Scopes: []tickets.Scope{{Kind: "asset", ID: e.asset.ID, Accounts: []string{e.asset.Username}, Actions: []string{"connect"}}}}
	created := e.send(t, "POST", "/api/v1/tickets/policies", policyIn, e.adminToken, "192.0.2.1:4000")
	require.Equal(t, 200, created.Code, created.Body.String())
	var policy tickets.Policy
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &policy))
	submitted := e.send(t, "POST", "/api/v1/tickets/requests", tickets.SubmitInput{PolicyID: policy.ID, PolicyRevision: policy.Revision, RequestID: "notification-ticket", Name: "Synthetic notification request", Reason: "Synthetic operation", Targets: []tickets.Target{{Kind: "asset", ID: e.asset.ID, Account: e.asset.Username, Actions: []string{"connect"}}}, EndsAt: time.Now().Add(30 * time.Minute)}, e.token, "192.0.2.1:4000")
	require.Equal(t, 200, submitted.Code, submitted.Body.String())
	e.d.Notifications.Tick()
	inbox := e.send(t, "GET", "/api/v1/notifications/inbox", nil, e.adminToken, "192.0.2.1:4000")
	assert.Contains(t, inbox.Body.String(), "approvals")
	assert.NotContains(t, inbox.Body.String(), e.asset.Host)
	var ticket tickets.Ticket
	require.NoError(t, json.Unmarshal(submitted.Body.Bytes(), &ticket))
	decision := e.send(t, "POST", "/api/v1/tickets/requests/"+ticket.ID+"/decisions", tickets.Decision{Revision: ticket.Revision, RequestID: "reject-notification", Action: "reject"}, e.adminToken, "192.0.2.1:4000")
	require.Equal(t, 200, decision.Code, decision.Body.String())
	e.d.Notifications.Tick()
	inbox = e.send(t, "GET", "/api/v1/notifications/inbox", nil, e.adminToken, "192.0.2.1:4000")
	assert.NotContains(t, inbox.Body.String(), "approvals")
	owner := e.send(t, "GET", "/api/v1/notifications/inbox", nil, e.token, "192.0.2.1:4000")
	assert.Contains(t, owner.Body.String(), "reject")
}
