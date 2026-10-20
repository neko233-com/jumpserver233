package aichat

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func provider(t *testing.T, h http.HandlerFunc) (Settings, *httptest.Server) {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	return Settings{Endpoint: s.URL + "/v1/chat/completions", Model: "synthetic-model", MaxTokens: 512, RootCAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}))}, s
}
func messages() []Message {
	return []Message{{Role: "system", Content: "Advisory only"}, {Role: "user", Content: "Explain pwd"}}
}
func TestAssistantConnectorUsesVerifiedTLSBoundedTextAndNoTools(t *testing.T) {
	var calls atomic.Int32
	config, _ := provider(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		assert.Equal(t, "Bearer synthetic-assistant-key", r.Header.Get("Authorization"))
		var v map[string]json.RawMessage
		require.NoError(t, json.NewDecoder(r.Body).Decode(&v))
		assert.JSONEq(t, "false", string(v["store"]))
		assert.JSONEq(t, "false", string(v["stream"]))
		assert.NotContains(t, v, "tools")
		assert.NotContains(t, v, "functions")
		assert.JSONEq(t, "512", string(v["max_completion_tokens"]))
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"pwd prints the directory"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":4}}`))
	})
	result, e := Complete(t.Context(), config, "synthetic-assistant-key", messages())
	require.NoError(t, e)
	assert.Equal(t, "pwd prints the directory", result.Text)
	assert.Equal(t, 5, result.PromptTokens)
	assert.EqualValues(t, 1, calls.Load())
	config.RootCAPEM = ""
	_, e = Complete(t.Context(), config, "synthetic-assistant-key", messages())
	assert.ErrorIs(t, e, ErrUnavailable)
	assert.EqualValues(t, 1, calls.Load())
}
func TestAssistantConnectorRejectsRedirectsToolCallsOversizeAndErrorBodies(t *testing.T) {
	for _, scenario := range []string{"redirect", "tool", "oversize", "error", "role", "negative-usage"} {
		t.Run(scenario, func(t *testing.T) {
			var calls atomic.Int32
			config, _ := provider(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				switch scenario {
				case "redirect":
					w.Header().Set("Location", "https://other.example/v1/chat/completions")
					w.WriteHeader(307)
				case "tool":
					_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"text","tool_calls":[{}]},"finish_reason":"stop"}]}`))
				case "oversize":
					_, _ = w.Write([]byte(strings.Repeat("x", 256*1024+1)))
				case "error":
					w.WriteHeader(429)
					_, _ = w.Write([]byte("private provider diagnostics"))
				case "role":
					_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"user","content":"wrong role"},"finish_reason":"stop"}]}`))
				case "negative-usage":
					_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"answer"},"finish_reason":"stop"}],"usage":{"prompt_tokens":-1}}`))
				}
			})
			_, e := Complete(t.Context(), config, "synthetic-assistant-key", messages())
			assert.ErrorIs(t, e, ErrUnavailable)
			assert.NotContains(t, e.Error(), "private provider diagnostics")
			assert.EqualValues(t, 1, calls.Load())
		})
	}
}
func TestAssistantConnectorValidatesConfigurationAndCancellation(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	config, _ := provider(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	for _, endpoint := range []string{"http://provider.example/v1/chat/completions", "https://user:secret@provider.example/v1/chat/completions", "https://provider.example/v1/chat/completions?key=private", "https://provider.example/v1/chat/completions#x"} {
		bad := config
		bad.Endpoint = endpoint
		assert.ErrorIs(t, Validate(bad), ErrInvalid)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	_, e := Complete(ctx, config, "synthetic-assistant-key", messages())
	assert.ErrorIs(t, e, ErrUnavailable)
}
