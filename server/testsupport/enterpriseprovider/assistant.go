package enterpriseprovider

import (
	"encoding/json"
	"io"
	"net/http"
)

const AssistantSecret = "synthetic-assistant-provider-key"

func (s *Server) serveAssistant(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/v1/chat/completions" {
		return false
	}
	if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer "+AssistantSecret {
		w.WriteHeader(401)
		return true
	}
	var in struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
		Store     bool `json:"store"`
		Stream    bool `json:"stream"`
		MaxTokens int  `json:"max_completion_tokens"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 140*1024)).Decode(&in) != nil || in.Model != "synthetic-assistant-model" || in.Store || in.Stream || in.MaxTokens < 64 || len(in.Messages) < 2 {
		w.WriteHeader(400)
		return true
	}
	s.AssistantCalls.Add(1)
	write(w, map[string]any{"choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": "Synthetic advisory reply: " + in.Messages[len(in.Messages)-1].Content + "\n<img src=x onerror=alert(1)>"}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 11, "completion_tokens": 7}})
	return true
}
