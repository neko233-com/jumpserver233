package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestTicketCLIUsesMetadataCASAndRejectsCredentialFields(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "Bearer synthetic-ticket-client", r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/api/v1/tickets/requests/ticket-test/decisions":
			var in sessionclient.TicketDecision
			require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
			assert.Equal(t, 3, in.Revision)
			assert.Equal(t, "stable-decision", in.RequestID)
			assert.Equal(t, "approve", in.Action)
			_ = json.NewEncoder(w).Encode(sessionclient.Ticket{ID: "ticket-test", State: "approved"})
		case "/api/v1/tickets/requests":
			var in sessionclient.TicketInput
			require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
			assert.Equal(t, "stable-create", in.RequestID)
			assert.Equal(t, "policy-test", in.PolicyID)
			_ = json.NewEncoder(w).Encode(sessionclient.Ticket{ID: "ticket-test", State: "pending"})
		case "/api/v1/tickets/requests/ticket-test":
			_ = json.NewEncoder(w).Encode(sessionclient.Ticket{ID: "ticket-test", State: "rejected"})
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	client, e := sessionclient.New(server.URL, "synthetic-ticket-client")
	require.NoError(t, e)
	var output bytes.Buffer
	for _, args := range [][]string{{}, {"approve", "ticket-test"}, {"list", "--limit", "101"}, {"wait", "ticket-test", "--timeout-seconds", "0"}, {"show"}, {"create"}} {
		assert.Error(t, executeTickets(context.Background(), client, args, &output))
	}
	assert.Zero(t, calls)
	file := filepath.Join(t.TempDir(), "request.json")
	require.NoError(t, os.WriteFile(file, []byte(`{"policy_id":"policy-test","request_id":"stable-create","password":"reject-me"}`), 0600))
	assert.Error(t, executeTickets(context.Background(), client, []string{"create", "--file", file}, &output))
	assert.Zero(t, calls)
	require.NoError(t, os.WriteFile(file, []byte(`{"policy_id":"policy-test","request_id":"stable-create"}`), 0600))
	require.NoError(t, executeTickets(context.Background(), client, []string{"create", "--file", file}, &output))
	require.NoError(t, executeTickets(context.Background(), client, []string{"approve", "ticket-test", "--revision", "3", "--request-id", "stable-decision"}, &output))
	assert.Contains(t, output.String(), "approved")
	output.Reset()
	assert.Error(t, executeTickets(context.Background(), client, []string{"wait", "ticket-test"}, &output))
	assert.Contains(t, output.String(), "rejected")
	assert.NotContains(t, output.String(), "synthetic-ticket-client")
}
