package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/core/branding"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBrandingCLIValidatesAndEmitsOnlyTypedPublicMetadata(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method == "PUT" {
			var in map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
			assert.Equal(t, "", in["logo"])
			assert.NotContains(t, in, "icon")
			_ = json.NewEncoder(w).Encode(branding.Defaults().Public())
			return
		}
		_, _ = w.Write([]byte(`{"settings":{"revision":1,"name_en":"Operations"},"themes":[],"password":"synthetic-extra-private-value"}`))
	}))
	defer server.Close()
	client, e := sessionclient.New(server.URL, "synthetic-branding-client")
	require.NoError(t, e)
	var output bytes.Buffer
	for _, args := range [][]string{{}, {"save"}, {"show", "--file", "-"}, {"save", "--file", "-", "--logo", "a", "--clear-logo"}, {"audit", "--limit", "101"}, {"unknown"}} {
		assert.Error(t, executeBranding(context.Background(), client, args, strings.NewReader("{}"), &output))
	}
	assert.Zero(t, calls)
	require.NoError(t, executeBranding(context.Background(), client, []string{"show"}, strings.NewReader(""), &output))
	assert.Contains(t, output.String(), "Operations")
	assert.NotContains(t, output.String(), "synthetic-extra-private-value")
	d := branding.Defaults()
	input, e := json.Marshal(branding.Input{Revision: d.Revision, NameEN: d.NameEN, NameZH: d.NameZH, Theme: d.Theme, Accent: d.Accent})
	require.NoError(t, e)
	require.NoError(t, executeBranding(context.Background(), client, []string{"save", "--file", "-", "--clear-logo"}, bytes.NewReader(input), &output))
	assert.Equal(t, 2, calls)
	assert.Error(t, executeBranding(context.Background(), client, []string{"save", "--file", "-"}, strings.NewReader(`{"unknown":"field"}`), &output))
	assert.Equal(t, 2, calls)
}
