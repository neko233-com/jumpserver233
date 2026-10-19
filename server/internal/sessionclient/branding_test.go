package sessionclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/core/branding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBrandingClientScopesTypedDataAndPreservesExplicitImageClear(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "Bearer synthetic-branding-client", r.Header.Get("Authorization"))
		assert.Equal(t, "00000000-0000-0000-0000-000000000002", r.Header.Get("X-JMS-ORG"))
		if r.Method == "PUT" {
			var raw map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&raw))
			assert.Equal(t, "", raw["logo"])
			assert.NotContains(t, raw, "icon")
			_ = json.NewEncoder(w).Encode(branding.Defaults().Public())
			return
		}
		if r.URL.Path == "/api/v1/settings/branding/audit" {
			_, _ = w.Write([]byte(`{"results":[],"total":0}`))
			return
		}
		_, _ = w.Write([]byte(`{"settings":{"revision":1,"name_en":"Operations"},"themes":[],"password":"synthetic-extra-private-value"}`))
	}))
	defer srv.Close()
	c, e := New(srv.URL, "synthetic-branding-client")
	require.NoError(t, e)
	c, e = c.WithOrganization("00000000-0000-0000-0000-000000000002")
	require.NoError(t, e)
	_, e = c.SaveBranding(context.Background(), BrandingInput{})
	require.Error(t, e)
	_, e = c.BrandingAudit(context.Background(), -1, 25)
	require.Error(t, e)
	assert.Zero(t, calls)
	config, e := c.Branding(context.Background())
	require.NoError(t, e)
	raw, e := json.Marshal(config)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "synthetic-extra-private-value")
	d := branding.Defaults()
	empty := []byte{}
	_, e = c.SaveBranding(context.Background(), BrandingInput{Revision: 1, NameEN: d.NameEN, NameZH: d.NameZH, Theme: d.Theme, Accent: d.Accent, Logo: &empty})
	require.NoError(t, e)
	_, e = c.BrandingAudit(context.Background(), 0, 25)
	require.NoError(t, e)
	assert.Equal(t, 3, calls)
}
