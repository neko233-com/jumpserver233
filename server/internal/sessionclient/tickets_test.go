package sessionclient

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTicketSDKPreservesOrganizationAndExcludesPrivateOrCredentialFields(t *testing.T) {
	for _, mode := range []string{"bearer", "access-key"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				assert.Equal(t, "00000000-0000-0000-0000-000000000002", r.Header.Get("X-JMS-ORG"))
				assert.NotEmpty(t, r.Header.Get("Authorization"))
				switch r.URL.Path {
				case "/api/v1/tickets/policies/policy-safe/catalog":
					assert.Equal(t, "host & node", r.URL.Query().Get("search"))
					_, _ = w.Write([]byte(`{"results":[{"id":"asset-safe","name":"Host","password":"must-never-decode","Binding":"private-binding"}],"total":1}`))
				case "/api/v1/tickets/requests/ticket-safe/decisions":
					var in TicketDecision
					require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
					assert.Equal(t, 7, in.Revision)
					assert.Equal(t, "stable-id", in.RequestID)
					_, _ = w.Write([]byte(`{"id":"ticket-safe","state":"approved","private_key":"must-never-decode","Digest":"private-digest"}`))
				default:
					w.WriteHeader(409)
					_, _ = w.Write([]byte(`{"error_code":"conflict","error":"private-error-must-not-print"}`))
				}
			}))
			defer server.Close()
			c, e := New(server.URL, "synthetic-ticket-token")
			if mode == "access-key" {
				c, e = NewWithAccessKey(server.URL, "ak-"+strings.Repeat("a", 32), "synthetic-ticket-signature")
			}
			require.NoError(t, e)
			c, e = c.WithOrganization("00000000-0000-0000-0000-000000000002")
			require.NoError(t, e)
			catalog, e := c.TicketCatalog(context.Background(), "policy-safe", "host & node", 0, 25)
			require.NoError(t, e)
			require.Len(t, catalog.Results, 1)
			approved, e := c.DecideTicket(context.Background(), "ticket-safe", TicketDecision{Revision: 7, RequestID: "stable-id", Action: "approve"})
			require.NoError(t, e)
			assert.Equal(t, "approved", approved.State)
			raw, e := json.Marshal([]any{catalog, approved})
			require.NoError(t, e)
			assert.NotContains(t, string(raw), "private-")
			assert.NotContains(t, string(raw), "must-never-decode")
			_, e = c.CancelTicket(context.Background(), "ticket-safe", 8)
			require.Error(t, e)
			assert.Contains(t, e.Error(), "conflict")
			assert.NotContains(t, e.Error(), "private-error")
			assert.Equal(t, 3, calls)
		})
	}
}
