package api

import (
	"encoding/json"
	"net/http"
	"time"
)

type healthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	Time    string `json:"time"`
}

// HealthHandler reports process liveness. Mirrors JumpServer's /api/health/.
func HealthHandler(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, healthResponse{
			Status:  "ok",
			Version: version,
			Time:    time.Now().UTC().Format(time.RFC3339),
		})
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
