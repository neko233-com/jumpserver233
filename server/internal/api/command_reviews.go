package api

import (
	"errors"
	"net/http"

	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
)

func registerCommandReviewRoutes(mux *http.ServeMux, broker *gateway.Broker, identities *coreauth.Service, adminToken string) {
	protect := func(handler http.HandlerFunc) http.Handler {
		return protectAdminAPI(handler, adminToken, identities)
	}
	mux.Handle("GET /api/v1/command-reviews", protect(func(w http.ResponseWriter, _ *http.Request) {
		setNoStore(w)
		reviews := broker.ListPendingCommandReviews()
		writeJSON(w, http.StatusOK, map[string]any{"results": reviews, "total": len(reviews)})
	}))
	resolve := func(approve bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			principal, _ := PrincipalFromContext(r.Context())
			err := broker.ResolveCommandReview(r.PathValue("reviewID"), principal.Username, approve)
			if err != nil {
				switch {
				case errors.Is(err, gateway.ErrCommandReviewNotFound):
					writeJSON(w, http.StatusNotFound, map[string]string{"detail": "command review not found"})
				case errors.Is(err, gateway.ErrCommandReviewInProgress), errors.Is(err, gateway.ErrCommandReviewExpired):
					writeJSON(w, http.StatusConflict, map[string]string{"detail": "command review is no longer pending"})
				default:
					writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "command review resolution failed"})
				}
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}
	}
	mux.Handle("POST /api/v1/command-reviews/{reviewID}/approve", protect(resolve(true)))
	mux.Handle("POST /api/v1/command-reviews/{reviewID}/deny", protect(resolve(false)))
}
