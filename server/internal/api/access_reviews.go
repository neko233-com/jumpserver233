package api

import (
	"errors"
	"net/http"

	coreaccessreviews "github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
)

func registerAccessReviewRoutes(mux *http.ServeMux, reviews *coreaccessreviews.Store, identities *coreauth.Service, adminToken string) {
	mux.Handle("GET /api/v1/access-reviews", protectAdminAPI(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		setNoStore(w)
		items, err := reviews.ListPending()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "could not read access reviews"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"results": items, "total": len(items)})
	}), adminToken, identities))

	mux.Handle("GET /api/v1/access-reviews/{reviewID}", protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := PrincipalFromContext(r.Context())
		item, err := reviews.Get(r.PathValue("reviewID"))
		if errors.Is(err, coreaccessreviews.ErrNotFound) || err == nil && !hasPermission(r, "reviews.login.manage") && principal.ID != item.UserID {
			writeJSON(w, http.StatusNotFound, map[string]string{"detail": "access review not found"})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "could not read access review"})
			return
		}
		setNoStore(w)
		writeJSON(w, http.StatusOK, item)
	}), adminToken, identities))

	resolve := func(approve bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			principal, _ := PrincipalFromContext(r.Context())
			if err := reviews.Resolve(r.PathValue("reviewID"), principal.Username, approve); err != nil {
				switch {
				case errors.Is(err, coreaccessreviews.ErrNotFound):
					writeJSON(w, http.StatusNotFound, map[string]string{"detail": "access review not found"})
				case errors.Is(err, coreaccessreviews.ErrNotPending):
					writeJSON(w, http.StatusConflict, map[string]string{"detail": "access review is no longer pending"})
				default:
					writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "access review resolution failed"})
				}
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}
	}
	mux.Handle("POST /api/v1/access-reviews/{reviewID}/approve", protectAdminAPI(resolve(true), adminToken, identities))
	mux.Handle("POST /api/v1/access-reviews/{reviewID}/deny", protectAdminAPI(resolve(false), adminToken, identities))
}
