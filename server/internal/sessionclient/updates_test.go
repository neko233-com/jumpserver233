package sessionclient

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/updates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUpdateSDKPreservesAuthenticationAndOrganizationHeaders(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "Bearer synthetic-update-session", r.Header.Get("Authorization"))
		assert.Equal(t, "00000000-0000-0000-0000-000000000002", r.Header.Get("X-JMS-ORG"))
		assert.Contains(t, r.URL.Path, updatesPath)
		if r.URL.Path == updatesPath+"/audit" {
			_, _ = w.Write([]byte(`[]`))
		} else {
			_, _ = w.Write([]byte(`{"settings":{"automatic":false,"interval_hours":24,"revision":1}}`))
		}
	}))
	defer server.Close()
	c, e := New(server.URL, "synthetic-update-session")
	require.NoError(t, e)
	c, e = c.WithOrganization("00000000-0000-0000-0000-000000000002")
	require.NoError(t, e)
	ctx := context.Background()
	_, e = c.UpdateStatus(ctx)
	require.NoError(t, e)
	_, e = c.SaveUpdateSettings(ctx, updates.Settings{IntervalHours: 24, Revision: 1})
	require.NoError(t, e)
	_, e = c.CheckUpdates(ctx, 1, "request-0001")
	require.NoError(t, e)
	_, e = c.UpdateAudit(ctx)
	require.NoError(t, e)
	assert.Equal(t, 4, calls)
}
