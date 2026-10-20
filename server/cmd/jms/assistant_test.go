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

func TestAssistantCLIReadsStructuredInputAndDoesNotPrintProviderKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "PUT", r.Method)
		assert.Equal(t, "/api/v1/assistant/settings", r.URL.Path)
		_, _ = w.Write([]byte(`{"enabled":true,"configured":true,"revision":1,"model":"synthetic-model"}`))
	}))
	defer server.Close()
	c, e := sessionclient.New(server.URL, "synthetic-platform-token")
	require.NoError(t, e)
	var out bytes.Buffer
	e = executeAssistant(t.Context(), c, []string{"configure", "--file", "-"}, strings.NewReader(`{"endpoint":"https://provider.example/v1/chat/completions","model":"synthetic-model","max_completion_tokens":512,"secret":"synthetic-cli-provider-key","enabled":true,"revision":0,"request_id":"assistant-cli-settings"}`), &out)
	require.NoError(t, e)
	assert.NotContains(t, out.String(), "synthetic-cli-provider-key")
	assert.Contains(t, out.String(), "configured")
	assert.Error(t, executeAssistant(t.Context(), c, []string{"ask", "--unexpected"}, strings.NewReader(""), &out))
}
