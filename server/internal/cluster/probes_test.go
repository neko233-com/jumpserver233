package cluster

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeHandlerReportsLivenessAndReadiness(t *testing.T) {
	ready := false
	handler := ProbeHandler(func() bool { return ready })

	for _, tc := range []struct {
		name       string
		path       string
		wantStatus int
	}{
		{name: "live while standby", path: "/livez", wantStatus: http.StatusOK},
		{name: "not ready while standby", path: "/readyz", wantStatus: http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if recorder.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, tc.wantStatus)
			}
			if recorder.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", recorder.Header().Get("Cache-Control"))
			}
		})
	}

	ready = true
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("ready status = %d, want %d", recorder.Code, http.StatusOK)
	}
}
