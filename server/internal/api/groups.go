package api

import (
	"errors"
	"net/http"
	"sync"

	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	corecommandfilters "github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	coregrants "github.com/neko233-com/jumpserver233/server/internal/core/grants"
	coregroups "github.com/neko233-com/jumpserver233/server/internal/core/groups"
)

func registerGroupRoutes(mux *http.ServeMux, groups *coregroups.Store, identities *coreauth.Service, grants *coregrants.Store, commandFilters *corecommandfilters.Store, adminToken string, accessMu *sync.RWMutex) {
	protect := func(handler http.HandlerFunc) http.Handler {
		return protectAdminAPI(handler, adminToken, identities)
	}
	mux.Handle("GET /api/v1/user-groups", protect(func(w http.ResponseWriter, _ *http.Request) {
		setNoStore(w)
		writeJSON(w, http.StatusOK, groups.List())
	}))
	mux.Handle("POST /api/v1/user-groups", protect(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		if err := decodeRequestJSON(w, r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid user group payload"})
			return
		}
		group, err := groups.Create(input.Name, input.Description)
		if err != nil {
			writeGroupError(w, err)
			return
		}
		setNoStore(w)
		writeJSON(w, http.StatusCreated, group)
	}))
	mux.Handle("PUT /api/v1/user-groups/{groupID}/members/{userID}", protect(func(w http.ResponseWriter, r *http.Request) {
		accessMu.Lock()
		defer accessMu.Unlock()
		groupID := r.PathValue("groupID")
		if !globalGroupMutationAllowed(w, r, groupID) {
			return
		}
		userID := r.PathValue("userID")
		user, exists := identities.UserByID(userID)
		if !exists || !organizationSubjectAllowed(r, userID) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "group member does not exist"})
			return
		}
		if user.Role != coreauth.RoleOperator {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "only operator users can be added to access groups"})
			return
		}
		group, err := groups.AddMember(groupID, userID)
		if err != nil {
			writeGroupError(w, err)
			return
		}
		setNoStore(w)
		writeJSON(w, http.StatusOK, group)
	}))
	mux.Handle("DELETE /api/v1/user-groups/{groupID}/members/{userID}", protect(func(w http.ResponseWriter, r *http.Request) {
		accessMu.Lock()
		defer accessMu.Unlock()
		if !globalGroupMutationAllowed(w, r, r.PathValue("groupID")) {
			return
		}
		group, err := groups.RemoveMember(r.PathValue("groupID"), r.PathValue("userID"))
		if err != nil {
			writeGroupError(w, err)
			return
		}
		setNoStore(w)
		writeJSON(w, http.StatusOK, group)
	}))
	mux.Handle("DELETE /api/v1/user-groups/{groupID}", protect(func(w http.ResponseWriter, r *http.Request) {
		accessMu.Lock()
		defer accessMu.Unlock()
		groupID := r.PathValue("groupID")
		if !globalGroupMutationAllowed(w, r, groupID) {
			return
		}
		if grants != nil && grants.ReferencesGroup(groupID) {
			writeJSON(w, http.StatusConflict, map[string]string{"detail": "remove the group's grants before deleting it"})
			return
		}
		if commandFilters != nil && commandFilters.ReferencesGroup(groupID) {
			writeJSON(w, http.StatusConflict, map[string]string{"detail": "remove the group's command filters before deleting it"})
			return
		}
		if err := groups.Delete(groupID); err != nil {
			writeGroupError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
}

func writeGroupError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, coregroups.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "user group not found"})
	case errors.Is(err, coregroups.ErrGroupExists):
		writeJSON(w, http.StatusConflict, map[string]string{"detail": "user group name already exists"})
	case errors.Is(err, coregroups.ErrInvalidInput):
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid user group input"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "user group operation failed"})
	}
}
