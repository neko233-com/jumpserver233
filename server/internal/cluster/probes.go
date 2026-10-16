package cluster

import "net/http"

// ProbeHandler serves unauthenticated process liveness and leader readiness
// probes. Readiness stays false on standby nodes so a load balancer cannot
// route application traffic to them.
func ProbeHandler(isReady func() bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if isReady == nil || !isReady() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return mux
}
