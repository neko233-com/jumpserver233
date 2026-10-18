package sessionclient

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoginAuditSDKQueriesCSVAndIndependentNotificationClient(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		assert.Equal(t, "Bearer synthetic-token", r.Header.Get("Authorization"))
		if strings.HasSuffix(r.URL.Path, "export.csv") {
			assert.Equal(t, "all", r.URL.Query().Get("scope"))
			assert.Equal(t, "A & B", r.URL.Query().Get("q"))
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			_, _ = w.Write([]byte("id,outcome\na,succeeded\n"))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/login-safe") {
			_, _ = w.Write([]byte(`{"id":"login-safe","outcome":"succeeded","password":"synthetic-extra-secret"}`))
			return
		}
		_, _ = w.Write([]byte(`{"results":[],"total":0}`))
	}))
	defer srv.Close()
	c, e := New(srv.URL, "synthetic-token")
	require.NoError(t, e)
	var buf bytes.Buffer
	require.NoError(t, c.ExportLoginAudits(context.Background(), LoginAuditFilter{All: true, Query: "A & B"}, &buf))
	assert.Contains(t, buf.String(), "succeeded")
	row, e := c.LoginAuditEvent(context.Background(), "login-safe")
	require.NoError(t, e)
	raw, _ := json.Marshal(row)
	assert.NotContains(t, string(raw), "synthetic-extra-secret")
	_, e = c.LoginAuditEvent(context.Background(), "../escape")
	require.Error(t, e)
	global := c.WithPlatformNotifications()
	_, e = global.Notifications(context.Background(), false, 0, 20)
	require.NoError(t, e)
	_, e = c.Notifications(context.Background(), false, 0, 20)
	require.NoError(t, e)
	assert.Contains(t, paths, "/api/v1/platform-notifications/inbox")
	assert.Contains(t, paths, "/api/v1/notifications/inbox")
}
