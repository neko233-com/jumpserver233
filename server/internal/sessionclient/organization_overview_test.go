package sessionclient

import (
	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOrganizationOverviewSDKKeepsExplicitSelectedHeaderOnGlobalRoute(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/organizations/overview", r.URL.Path)
		assert.Equal(t, "true", r.URL.Query().Get("include_archived"))
		assert.Equal(t, organizations.DefaultID, r.Header.Get("X-JMS-ORG"))
		_, _ = w.Write([]byte(`{"results":[{"id":"00000000-0000-0000-0000-000000000002","name":"Default","state":"ready","counts":{"assets":3,"protocols":{"ssh":3}}}],"totals":{"assets":3},"collected_organizations":1,"enabled_organizations":1,"partial":false}`))
	}))
	defer srv.Close()
	c, err := New(srv.URL, "synthetic-token")
	require.NoError(t, err)
	c, err = c.WithOrganization(organizations.DefaultID)
	require.NoError(t, err)
	out, err := c.OrganizationOverview(t.Context(), true)
	require.NoError(t, err)
	assert.Equal(t, 3, out.Totals.Assets)
	assert.False(t, out.Partial)
	assert.Equal(t, 3, out.Results[0].Counts.Protocols["ssh"])
}
