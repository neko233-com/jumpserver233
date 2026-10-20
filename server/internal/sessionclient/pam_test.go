package sessionclient

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPAMSDKUsesPlatformAuthAndBoundPreviewCommit(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "Bearer synthetic-platform-token", r.Header.Get("Authorization"))
		assert.Equal(t, "00000000-0000-0000-0000-000000000002", r.Header.Get("X-JMS-ORG"))
		assert.Contains(t, r.URL.Path, "/api/v1/assets/asset-pam/pam/")
		if r.Method == "GET" {
			_, _ = w.Write([]byte(`{"asset_id":"asset-pam","version":"revision","platform":"windows","principals":[]}`))
			return
		}
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "pam-sdk-request", body["request_id"])
		if r.URL.Path == "/api/v1/assets/asset-pam/pam/import-commit" {
			assert.Equal(t, "bound-preview", body["preview_token"])
		}
		_, _ = w.Write([]byte(`{"request_id":"pam-sdk-request","rows":[],"issues":[],"preview_token":"bound-preview"}`))
	}))
	defer server.Close()
	c, e := New(server.URL, "synthetic-platform-token")
	require.NoError(t, e)
	c, e = c.WithOrganization("00000000-0000-0000-0000-000000000002")
	require.NoError(t, e)
	_, e = c.PAMPrincipals(t.Context(), "asset-pam")
	require.NoError(t, e)
	in := PAMImportInput{RequestID: "pam-sdk-request"}
	preview, e := c.PreviewPAMImport(t.Context(), "asset-pam", in)
	require.NoError(t, e)
	in.PreviewToken = preview.Token
	_, e = c.CommitPAMImport(t.Context(), "asset-pam", in)
	require.NoError(t, e)
	_, e = c.PAMPrincipals(t.Context(), "../outside")
	assert.Error(t, e)
	assert.Equal(t, 3, calls)
}
