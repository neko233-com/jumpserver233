package main

import (
	"bytes"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPAMCLIReadsPrivateStdinAndReturnsOnlyReceipt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/assets/asset-pam/pam/import-preview", r.URL.Path)
		_, _ = w.Write([]byte(`{"request_id":"pam-cli","rows":[],"issues":[],"preview_token":"bound-preview"}`))
	}))
	defer server.Close()
	c, e := sessionclient.New(server.URL, "synthetic-platform-token")
	require.NoError(t, e)
	var output bytes.Buffer
	e = executePAM(t.Context(), c, []string{"preview", "asset-pam", "--file", "-"}, strings.NewReader(`{"password":"synthetic-private-enrollment","request_id":"pam-cli"}`), &output)
	require.NoError(t, e)
	assert.Contains(t, output.String(), "bound-preview")
	assert.NotContains(t, output.String(), "synthetic-private-enrollment")
	for _, args := range [][]string{{"discover", "asset-pam", "--password", "unsafe"}, {"reset", "asset-pam"}, {"commit", "../outside", "--file", "-"}} {
		assert.Error(t, executePAM(t.Context(), c, args, strings.NewReader(`{}`), &output))
	}
}
