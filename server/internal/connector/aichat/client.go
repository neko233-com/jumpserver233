// Package aichat implements a bounded, text-only Chat Completions connector.
// It never executes tools, reads ambient credentials, retries or follows redirects.
package aichat

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrInvalid = errors.New("invalid assistant provider configuration")
var ErrUnavailable = errors.New("assistant provider unavailable")

type Settings struct {
	Endpoint  string `json:"endpoint"`
	Model     string `json:"model"`
	RootCAPEM string `json:"root_ca_pem,omitempty"`
	MaxTokens int    `json:"max_completion_tokens"`
}
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type Result struct {
	Text                           string
	PromptTokens, CompletionTokens int
}

func Text(v string, maxBytes int) bool {
	return v != "" && len(v) <= maxBytes && utf8.ValidString(v) && strings.IndexFunc(v, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }) < 0
}
func Validate(s Settings) error {
	u, e := url.Parse(s.Endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" || len(s.Endpoint) > 2048 || !strings.HasSuffix(u.Path, "/chat/completions") || strings.ContainsAny(s.Endpoint, "\r\n\x00\\") || !Text(s.Model, 128) || strings.ContainsAny(s.Model, "\n\t ") || s.MaxTokens < 64 || s.MaxTokens > 8192 || len(s.RootCAPEM) > 65536 {
		return ErrInvalid
	}
	if s.RootCAPEM != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(s.RootCAPEM)) {
		return ErrInvalid
	}
	return nil
}
func ValidSecret(v string) bool {
	return v != "" && len(v) <= 8192 && strings.IndexFunc(v, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) < 0
}
func Complete(ctx context.Context, s Settings, secret string, messages []Message) (Result, error) {
	if Validate(s) != nil || !ValidSecret(secret) || len(messages) < 2 || len(messages) > 65 {
		return Result{}, ErrInvalid
	}
	size := 0
	for _, m := range messages {
		size += len(m.Content)
		if !Text(m.Content, 32768) || (m.Role != "system" && m.Role != "user" && m.Role != "assistant") {
			return Result{}, ErrInvalid
		}
	}
	if size > 128<<10 {
		return Result{}, ErrInvalid
	}
	request := struct {
		Model     string    `json:"model"`
		Messages  []Message `json:"messages"`
		MaxTokens int       `json:"max_completion_tokens"`
		Store     bool      `json:"store"`
		Stream    bool      `json:"stream"`
	}{s.Model, messages, s.MaxTokens, false, false}
	raw, e := json.Marshal(request)
	if e != nil {
		return Result{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, s.Endpoint, bytes.NewReader(raw))
	if e != nil {
		return Result{}, ErrInvalid
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if s.RootCAPEM != "" {
		pool, e := x509.SystemCertPool()
		if e != nil {
			pool = x509.NewCertPool()
		}
		pool.AppendCertsFromPEM([]byte(s.RootCAPEM))
		config.RootCAs = pool
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: config, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 40 * time.Second, MaxResponseHeaderBytes: 32768, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, e := client.Do(req)
	if e != nil {
		return Result{}, ErrUnavailable
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return Result{}, ErrUnavailable
	}
	data, e := io.ReadAll(io.LimitReader(r.Body, 256*1024+1))
	if e != nil || len(data) > 256*1024 {
		return Result{}, ErrUnavailable
	}
	var response struct {
		Choices []struct {
			Message struct {
				Role         string            `json:"role"`
				Content      string            `json:"content"`
				ToolCalls    []json.RawMessage `json:"tool_calls"`
				FunctionCall json.RawMessage   `json:"function_call"`
			} `json:"message"`
			Reason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			Prompt     int `json:"prompt_tokens"`
			Completion int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(data, &response) != nil || len(response.Choices) != 1 {
		return Result{}, ErrUnavailable
	}
	c := response.Choices[0]
	if c.Message.Role != "assistant" || len(c.Message.ToolCalls) > 0 || len(c.Message.FunctionCall) > 0 && string(c.Message.FunctionCall) != "null" || (c.Reason != "stop" && c.Reason != "length") || !Text(c.Message.Content, 32768) || response.Usage.Prompt < 0 || response.Usage.Completion < 0 {
		return Result{}, ErrUnavailable
	}
	return Result{Text: c.Message.Content, PromptTokens: response.Usage.Prompt, CompletionTokens: response.Usage.Completion}, nil
}
