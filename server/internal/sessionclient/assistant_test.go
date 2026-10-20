package sessionclient

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAssistantSDKAcceptsPendingReceiptsAndNeverRequiresTargetCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer synthetic-platform-token", r.Header.Get("Authorization"))
		assert.Equal(t, "/api/v1/assistant/turns", r.URL.Path)
		var input map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
		assert.NotContains(t, input, "password")
		assert.NotContains(t, input, "secret")
		w.WriteHeader(202)
		_, _ = w.Write([]byte(`{"conversation_id":"chat-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","revision":1,"turn":{"id":"turn-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","status":"pending"}}`))
	}))
	defer server.Close()
	c, e := New(server.URL, "synthetic-platform-token")
	require.NoError(t, e)
	r, e := c.AskAssistant(t.Context(), AssistantInput{Message: "Explain pwd", Locale: "en", Consent: true, RequestID: "assistant-sdk-question"})
	require.NoError(t, e)
	assert.Equal(t, "pending", r.Turn.Status)
	_, e = c.AssistantConversation(t.Context(), "../outside", false)
	assert.Error(t, e)
}
