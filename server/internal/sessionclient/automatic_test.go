package sessionclient

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/releasebundle"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAutomaticSDKRetainsPlatformAuthentication(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		require.Equal(t, automaticPath, r.URL.Path)
		require.Equal(t, "Bearer synthetic-platform", r.Header.Get("Authorization"))
		require.Contains(t, []string{"GET", "PUT"}, r.Method)
		_, _ = w.Write([]byte(`{"policy":{"revision":1,"mode":"off"}}`))
	}))
	defer server.Close()
	c, e := New(server.URL, "synthetic-platform")
	require.NoError(t, e)
	_, e = c.AutomaticUpdateStatus(context.Background())
	require.NoError(t, e)
	_, e = c.SaveAutomaticUpdatePolicy(context.Background(), releasebundle.AutomaticPolicyInput{RequestID: "automatic-sdk-01"})
	require.NoError(t, e)
	require.Equal(t, 2, calls)
}
