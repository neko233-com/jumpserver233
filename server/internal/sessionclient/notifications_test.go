package sessionclient

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNotificationSourceSDKScopesValidatesAndDecodesOnlyDTO(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "00000000-0000-0000-0000-000000000002", r.Header.Get("X-JMS-ORG"))
		assert.Equal(t, "/api/v1/notifications/sources/command-alerts/command-event-safe", r.URL.Path)
		_, _ = w.Write([]byte(`{"id":"command-event-safe","kind":"command-alerts","state":"command_denied","password":"synthetic-extra-secret","stdout":"synthetic-extra-output"}`))
	}))
	defer srv.Close()
	c, e := New(srv.URL, "synthetic-token")
	require.NoError(t, e)
	c, e = c.WithOrganization("00000000-0000-0000-0000-000000000002")
	require.NoError(t, e)
	v, e := c.NotificationSource(context.Background(), "command-alerts", "command-event-safe")
	require.NoError(t, e)
	assert.Equal(t, "command_denied", v.State)
	raw, _ := json.Marshal(v)
	assert.NotContains(t, string(raw), "synthetic-extra")
	for _, pair := range [][2]string{{"unknown", "safe"}, {"command-alerts", "../safe"}, {"command-reviews", "x/y"}, {"access-reviews", ""}, {"agent-events", "?token=private"}} {
		_, e = c.NotificationSource(context.Background(), pair[0], pair[1])
		require.Error(t, e)
	}
	assert.Equal(t, 1, calls)
}
