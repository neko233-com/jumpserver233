package api

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequestLogPathRedactsWebSocketCapabilities(t *testing.T) {
	for _, tc := range []struct{ name, path, pattern, expected string }{
		{"legacy", "/ws/api/v1/sessions/synthetic-capability/terminal", "GET /ws/api/v1/sessions/{token}/terminal", "GET /ws/api/v1/sessions/{token}/terminal"},
		{"legacy-prefix", "/ws/api/v1/sessions/synthetic-capability/terminal", "/ws/api/v1/sessions/", "/ws/api/v1/sessions/"},
		{"unmatched", "/ws/api/v1/sessions/synthetic-capability/terminal", "", "/ws/[redacted]"},
		{"desktop", "/ws/desktop/synthetic-capability", "GET /ws/desktop/{id}", "GET /ws/desktop/{id}"},
		{"query", "/ws/terminal?token=synthetic-capability", "", "/ws/[redacted]"},
		{"ordinary-api", "/api/v1/assets?token=synthetic-capability", "", "/api/v1/assets"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tc.path, nil)
			r.Pattern = tc.pattern
			assert.Equal(t, tc.expected, requestLogPath(r))
			assert.NotContains(t, requestLogPath(r), "synthetic-capability")
		})
	}
}

type requestLogBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *requestLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}
func (b *requestLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

func TestAccessAndPanicLogsNeverContainWebSocketSessionCapability(t *testing.T) {
	for _, panicHandler := range []bool{false, true} {
		name := "access"
		if panicHandler {
			name = "panic"
		}
		t.Run(name, func(t *testing.T) {
			var output requestLogBuffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
			t.Cleanup(func() { slog.SetDefault(previous) })
			mux := http.NewServeMux()
			mux.HandleFunc("GET /ws/api/v1/sessions/{token}/terminal", func(w http.ResponseWriter, _ *http.Request) {
				if panicHandler {
					panic("synthetic handler panic")
				}
				w.WriteHeader(http.StatusNoContent)
			})
			secret := "synthetic-private-session-capability"
			r := httptest.NewRequest(http.MethodGet, "/ws/api/v1/sessions/"+secret+"/terminal?token="+secret, strings.NewReader(secret))
			r.Header.Set("Authorization", "Bearer "+secret)
			w := httptest.NewRecorder()
			WithAccessLog(WithRecover(mux)).ServeHTTP(w, r)
			expected := http.StatusNoContent
			if panicHandler {
				expected = http.StatusInternalServerError
			}
			assert.Equal(t, expected, w.Code)
			assert.Contains(t, output.String(), "{token}/terminal")
			assert.NotContains(t, output.String(), secret)
		})
	}
}
