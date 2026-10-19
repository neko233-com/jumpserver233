package main

import (
	"net/http"
	"sync/atomic"
)

type activationResponse struct{ http.ResponseWriter }

func (w activationResponse) WriteHeader(code int) {
	w.Header().Set("Cache-Control", "no-store")
	w.ResponseWriter.WriteHeader(code)
}
func (w activationResponse) Write(body []byte) (int, error) {
	w.Header().Set("Cache-Control", "no-store")
	return w.ResponseWriter.Write(body)
}

func gatedStartup(next http.Handler, attempt string, ready *atomic.Bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" && r.Method == http.MethodGet || !ready.Load() && r.Method == http.MethodGet && r.URL.Path == "/" {
			w.Header().Set("X-JMS-Activation", attempt)
			phase := "trial"
			if ready.Load() {
				phase = "active"
			}
			w.Header().Set("X-JMS-Activation-Phase", phase)
			w.Header().Set("Cache-Control", "no-store")
			next.ServeHTTP(activationResponse{w}, r)
			return
		} else if !ready.Load() {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Retry-After", "1")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"code":"upgrade_activation_pending"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}
