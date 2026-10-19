package sessionclient

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSSHPasswordPolicySDKRetainsAuthenticationAndScope(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		require.Equal(t, "/api/v1/accounts/password-policy", r.URL.Path)
		require.Equal(t, "Bearer synthetic-platform", r.Header.Get("Authorization"))
		require.Equal(t, organizations.DefaultID, r.Header.Get("X-JMS-ORG"))
		_, _ = w.Write([]byte(`{"policy":{"revision":1}}`))
	}))
	defer server.Close()
	base, e := New(server.URL, "synthetic-platform")
	require.NoError(t, e)
	c, e := base.WithOrganization(organizations.DefaultID)
	require.NoError(t, e)
	_, e = c.SSHPasswordPolicy(context.Background())
	require.NoError(t, e)
	_, e = c.SaveSSHPasswordPolicy(context.Background(), SSHPasswordPolicyInput{RequestID: "test"})
	require.NoError(t, e)
	require.Equal(t, 2, calls)
}
