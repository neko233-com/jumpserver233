package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coder/websocket"
)

func TestHealthHandler(t *testing.T) {
	router := NewRouter("test")

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("status = %q, want ok", body.Status)
	}
	if body.Version != "test" {
		t.Errorf("version = %q, want test", body.Version)
	}
}

func TestCORSPreflight(t *testing.T) {
	router := NewRouter("test")

	req := httptest.NewRequest(http.MethodOptions, "/api/health", nil)
	req.Header.Set("Origin", "http://127.0.0.1:5173")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); got == "" || !strings.Contains(got, "X-JMS-SFTP-Session") || !strings.Contains(got, "X-JMS-Browser-Session") {
		t.Errorf("Access-Control-Allow-Headers = %q, want SFTP and browser session headers", got)
	}
}

func TestAccessLogAllowsWebSocketUpgrade(t *testing.T) {
	handler := WithAccessLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer connection.CloseNow()
		messageType, message, err := connection.Read(r.Context())
		if err == nil {
			_ = connection.Write(r.Context(), messageType, message)
		}
	}))
	server := httptest.NewServer(handler)
	defer server.Close()
	endpoint := "ws" + server.URL[len("http"):]
	connection, _, err := websocket.Dial(context.Background(), endpoint, nil)
	if err != nil {
		t.Fatalf("websocket upgrade through access log: %v", err)
	}
	defer connection.CloseNow()
	if err := connection.Write(context.Background(), websocket.MessageBinary, []byte("ok")); err != nil {
		t.Fatalf("write websocket message: %v", err)
	}
	messageType, message, err := connection.Read(context.Background())
	if err != nil {
		t.Fatalf("read websocket message: %v", err)
	}
	if messageType != websocket.MessageBinary || string(message) != "ok" {
		t.Fatalf("websocket echo = (%v, %q), want binary \"ok\"", messageType, message)
	}
}

func TestDevelopmentOriginsAreLoopbackOnly(t *testing.T) {
	for _, origin := range []string{"http://127.0.0.1:5173", "http://localhost:5173", "http://[::1]:5173", "http://127.0.0.1:5174", "http://localhost:5174", "http://127.0.0.1:5177", "http://localhost:5177"} {
		if !isAllowedOrigin(origin) {
			t.Errorf("isAllowedOrigin(%q) = false, want true", origin)
		}
	}
	for _, origin := range []string{"http://192.0.2.1:5173", "https://localhost:5173", "http://localhost:5175", "http://localhost:5178"} {
		if isAllowedOrigin(origin) {
			t.Errorf("isAllowedOrigin(%q) = true, want false", origin)
		}
	}
}
