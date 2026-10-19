package sessionclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/core/servicemaintenance"
	"github.com/stretchr/testify/require"
)

func TestSupervisorLoopbackRejectsRemotePrefixAndCredentials(t *testing.T) {
	for _, url := range []string{"https://example.com", "http://192.0.2.1:8080", "http://localhost:8080", "http://127.0.0.1:8080/prefix", "http://user:synthetic@127.0.0.1:8080"} {
		c, e := New(url, "synthetic")
		require.NoError(t, e)
		_, e = c.LocalSupervisor()
		require.Error(t, e)
	}
	for _, url := range []string{"http://127.0.0.1:8080", "http://[::1]:8080/"} {
		c, e := New(url, "synthetic")
		require.NoError(t, e)
		c, e = c.LocalSupervisor()
		require.NoError(t, e)
		require.Nil(t, c.http.Transport.(*http.Transport).Proxy)
	}
}
func TestSupervisorStopUsesPlatformAuthenticationAndBoundInput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		require.Equal(t, maintenancePath+"/stop", r.URL.Path)
		require.Equal(t, "Bearer synthetic-platform-identity", r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"stopping":true,"pid":42,"instance":"instance"}`))
	}))
	defer server.Close()
	c, e := New(server.URL, "synthetic-platform-identity")
	require.NoError(t, e)
	c, e = c.LocalSupervisor()
	require.NoError(t, e)
	v, e := c.StopMaintenance(context.Background(), servicemaintenance.Input{Instance: "instance", Revision: 2, RequestID: "stop-request-01", Draining: true})
	require.NoError(t, e)
	require.True(t, v.Stopping)
}
