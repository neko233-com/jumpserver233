package api

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/core/tickets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTicketAPIWorkflowMetadataCASAndNativeSessionAuthorization(t *testing.T) {
	e := newPolicyEnv(t)
	for _, g := range e.d.Grants.List() {
		require.NoError(t, e.d.Grants.Delete(g.ID))
	}
	var err error
	e.d.Tickets, err = tickets.Open(filepath.Join(t.TempDir(), "tickets.json"), make([]byte, 32), nil)
	require.NoError(t, err)
	t.Cleanup(e.d.Tickets.Close)
	e.router = NewRouter("test", e.d)
	send := func(method, path string, in any, token string) *responseTicket {
		r := e.send(t, method, "/api/v1/tickets"+path, in, token, "192.0.2.3:4000")
		return &responseTicket{Code: r.Code, Body: r.Body.Bytes()}
	}
	denied := send("GET", "/choices", nil, e.token)
	assert.Equal(t, 403, denied.Code)
	in := tickets.PolicyInput{Name: "Synthetic access", Enabled: true, AllMembers: true, MaxDurationMinutes: 120, ApprovalTTLMinutes: 60, Stages: []tickets.Stage{{Name: "Approval", Subjects: []tickets.Subject{{Kind: "user", ID: e.admin.ID}}}}, Scopes: []tickets.Scope{{Kind: "asset", ID: e.asset.ID, Accounts: []string{e.asset.Username}, Actions: []string{"connect"}}}}
	created := send("POST", "/policies", in, e.adminToken)
	require.Equal(t, 200, created.Code, string(created.Body))
	var policy tickets.Policy
	require.NoError(t, json.Unmarshal(created.Body, &policy))
	catalog := send("GET", "/policies/"+policy.ID+"/catalog", nil, e.token)
	require.Equal(t, 200, catalog.Code, string(catalog.Body))
	assert.NotContains(t, string(catalog.Body), e.asset.Host)
	assert.NotContains(t, string(catalog.Body), "host_key")
	assert.NotContains(t, string(catalog.Body), "Binding")
	req := tickets.SubmitInput{PolicyID: policy.ID, PolicyRevision: policy.Revision, RequestID: "synthetic-request", Name: "Temporary SSH", Reason: "Synthetic business request", Targets: []tickets.Target{{Kind: "asset", ID: e.asset.ID, Account: e.asset.Username, Actions: []string{"connect"}}}, EndsAt: time.Now().Add(time.Hour)}
	result := send("POST", "/requests", req, e.token)
	require.Equal(t, 200, result.Code, string(result.Body))
	var ticket tickets.Ticket
	require.NoError(t, json.Unmarshal(result.Body, &ticket))
	assert.False(t, e.d.Grants.Allows(e.operator.ID, e.asset.ID, e.asset.Username, "connect", time.Now()))
	own := send("POST", "/requests/"+ticket.ID+"/decisions", tickets.Decision{Revision: ticket.Revision, RequestID: "self", Action: "approve"}, e.token)
	assert.Equal(t, 403, own.Code)
	stale := send("POST", "/requests/"+ticket.ID+"/decisions", tickets.Decision{Revision: ticket.Revision + 1, RequestID: "stale", Action: "approve"}, e.adminToken)
	assert.Equal(t, 409, stale.Code)
	decision := tickets.Decision{Revision: ticket.Revision, RequestID: "synthetic-decision", Action: "approve"}
	result = send("POST", "/requests/"+ticket.ID+"/decisions", decision, e.adminToken)
	require.Equal(t, 200, result.Code, string(result.Body))
	require.NoError(t, json.Unmarshal(result.Body, &ticket))
	require.Equal(t, "approved", ticket.State)
	assert.True(t, e.d.Grants.Allows(e.operator.ID, e.asset.ID, e.asset.Username, "connect", time.Now()))
	assert.False(t, e.d.Grants.Allows(e.operator.ID, e.asset.ID, e.asset.Username, "sftp", time.Now()))
	require.Len(t, e.d.Grants.List(), 1)
	again := send("POST", "/requests/"+ticket.ID+"/decisions", decision, e.adminToken)
	require.Equal(t, 200, again.Code)
	require.Len(t, e.d.Grants.List(), 1)
	result = send("POST", "/requests/"+ticket.ID+"/cancel", map[string]int{"revision": ticket.Revision}, e.token)
	require.Equal(t, 200, result.Code, string(result.Body))
	assert.False(t, e.d.Grants.Allows(e.operator.ID, e.asset.ID, e.asset.Username, "connect", time.Now()))
	require.Empty(t, e.d.Grants.List())
	assert.NotContains(t, string(result.Body), "synthetic-private-password")
	// Review capability is granted independently of inventory administration.
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "review only", Permissions: []string{"tickets.review"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 403, send("POST", "/policies", in, e.token).Code)
	// A plain grant remains independent of ticket lifecycle.
	_, err = e.d.Grants.Create(grants.Input{UserID: e.operator.ID, AssetID: e.asset.ID, Account: e.asset.Username, Actions: []string{"connect"}}, e.admin.ID)
	require.NoError(t, err)
	assert.True(t, e.d.Grants.Allows(e.operator.ID, e.asset.ID, e.asset.Username, "connect", time.Now()))
}

type responseTicket struct {
	Code int
	Body []byte
}
