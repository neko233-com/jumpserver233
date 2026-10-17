package sessionclient

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagedAccountSelectionPreservesOrganizationBearerAndSignedRequests(t *testing.T) {
	for _, mode := range []string{"bearer", "access-key"} {
		t.Run(mode, func(t *testing.T) {
			const parent = "asset-physical"
			endpoint := "account-" + parent + "-" + strings.Repeat("a", 32)
			calls := []string{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, r.Method+" "+r.URL.Path)
				assert.Equal(t, organizations.DefaultID, r.Header.Get("X-JMS-ORG"))
				if mode == "bearer" {
					assert.Equal(t, "Bearer synthetic-platform-token", r.Header.Get("Authorization"))
				} else {
					mac := hmac.New(sha256.New, []byte("synthetic-access-key-secret"))
					_, _ = fmt.Fprintf(mac, "(request-target): %s %s\naccept: application/json\ndate: %s", strings.ToLower(r.Method), r.URL.RequestURI(), r.Header.Get("Date"))
					assert.Contains(t, r.Header.Get("Authorization"), `signature="`+base64.StdEncoding.EncodeToString(mac.Sum(nil))+`"`)
				}
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/api/v1/assets/" + parent + "/accounts":
					assert.Equal(t, "operator", r.URL.Query().Get("username"))
					_ = json.NewEncoder(w).Encode(ManagedAccountPage{Total: 1, Results: []ManagedAccount{{ID: endpoint, AssetID: parent, Username: "operator", Active: true}}})
				case "/api/v1/ops/jobs":
					var in jobs.Input
					require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
					assert.Equal(t, endpoint, in.AssetID)
					_ = json.NewEncoder(w).Encode(jobs.Job{ID: "job-selected", State: "succeeded"})
				case "/api/v1/sessions":
					var in gateway.CreateRequest
					require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
					assert.Equal(t, endpoint, in.AssetID)
					w.WriteHeader(201)
					_ = json.NewEncoder(w).Encode(gateway.CreatedSession{SessionID: "test", Ticket: "one-shot", WebSocketURL: "/ws/api/v1/sessions/test/terminal"})
				case "/api/v1/assets/" + endpoint + "/host-plugins/node_exporter/jobs":
					_ = json.NewEncoder(w).Encode(jobs.Job{ID: "job-plugin"})
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			base, e := New(server.URL, "synthetic-platform-token")
			if mode == "access-key" {
				base, e = NewWithAccessKey(server.URL, "ak-"+strings.Repeat("a", 32), "synthetic-access-key-secret")
			}
			require.NoError(t, e)
			c, e := base.WithOrganization(organizations.DefaultID)
			require.NoError(t, e)
			c, e = c.WithManagedAccount("operator")
			require.NoError(t, e)
			assert.Empty(t, base.managedAccount)
			_, e = c.SubmitJob(context.Background(), jobs.Input{AssetID: parent, Command: "whoami"})
			require.NoError(t, e)
			_, e = c.CreateSession(context.Background(), gateway.CreateRequest{AssetID: parent})
			require.NoError(t, e)
			_, e = c.SubmitPlugin(context.Background(), parent, "node_exporter", PluginRequest{Action: "status"})
			require.NoError(t, e)
			assert.Len(t, calls, 6)
			_, e = c.CreateSession(context.Background(), gateway.CreateRequest{AssetID: parent, Protocol: "telnet"})
			require.Error(t, e)
			_, e = c.SubmitJob(context.Background(), jobs.Input{AssetID: parent, Command: ""})
			require.Error(t, e)
			assert.Len(t, calls, 6)
		})
	}
}

func TestManagedCredentialRequestsNeverFollowRedirectsOrEchoCredentialErrors(t *testing.T) {
	var leaked atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { leaked.Add(1); w.WriteHeader(200) }))
	defer sink.Close()
	for _, status := range []int{307, 403} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", sink.URL)
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(map[string]string{"detail": "synthetic-private-password"})
			}))
			defer server.Close()
			c, e := New(server.URL, "synthetic-token")
			require.NoError(t, e)
			_, e = c.CreateManagedAccount(context.Background(), "asset", ManagedAccountInput{Username: "operator", Password: "synthetic-private-password", Version: "known"})
			require.Error(t, e)
			assert.NotContains(t, e.Error(), "synthetic-private-password")
			assert.Contains(t, e.Error(), fmt.Sprint(status))
			assert.Zero(t, leaked.Load())
		})
	}
}

func TestManagedAccountResponsesDiscardUnexpectedSecretFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"named","asset_id":"asset","username":"operator","active":true,"password":"synthetic-forbidden-secret","private_key":"synthetic-forbidden-secret","ssh_key_rotation":{"state":"scheduled","private_key":"synthetic-forbidden-secret"}}`))
	}))
	defer server.Close()
	c, e := New(server.URL, "synthetic-token")
	require.NoError(t, e)
	a, e := c.ManagedAccount(context.Background(), "asset", "named")
	require.NoError(t, e)
	raw, e := json.Marshal(a)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "synthetic-forbidden-secret")
	for _, value := range []string{"user\nname", "user/name", "user?name", strings.Repeat("a", 129)} {
		_, e := c.WithManagedAccount(value)
		require.Error(t, e)
	}
}

func TestManagedAccountActivityDropsUnexpectedSecretFields(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/assets/asset/accounts/account/activity", r.URL.Path)
		_, _ = w.Write([]byte(`{"results":[{"action":"updated","username":"ops","actor":{"id":"user","name":"Operator","password":"synthetic-secret"},"private_key":"synthetic-secret"}],"total":1,"password":"synthetic-secret"}`))
	}))
	defer s.Close()
	c, e := New(s.URL, "synthetic-token")
	require.NoError(t, e)
	p, e := c.ManagedAccountActivity(context.Background(), "asset", "account", 0, 20)
	require.NoError(t, e)
	raw, e := json.Marshal(p)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "synthetic-secret")
	assert.Contains(t, string(raw), "Operator")
	assert.Equal(t, 1, p.Total)
}

func TestManagedAccountSelectionRejectsInactiveAndConflictingEndpoint(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(fmt.Sprint(active), func(t *testing.T) {
			const parent = "asset-host"
			selected := "account-" + parent + "-" + strings.Repeat("a", 32)
			explicit := "account-" + parent + "-" + strings.Repeat("b", 32)
			var posts atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					posts.Add(1)
					w.WriteHeader(500)
					return
				}
				assert.Equal(t, "operator", r.URL.Query().Get("username"))
				_ = json.NewEncoder(w).Encode(ManagedAccountPage{Results: []ManagedAccount{{ID: selected, AssetID: parent, Username: "operator", Active: active}}, Total: 1})
			}))
			defer s.Close()
			c, e := New(s.URL, "synthetic-token")
			require.NoError(t, e)
			c, e = c.WithManagedAccount("operator")
			require.NoError(t, e)
			_, e = c.SubmitJob(context.Background(), jobs.Input{AssetID: explicit, Command: "id -un"})
			require.Error(t, e)
			assert.Zero(t, posts.Load())
		})
	}
}
