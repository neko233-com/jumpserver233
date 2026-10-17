package api

import (
	"errors"
	"net/http"
	"strings"
	"sync"

	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	coregrants "github.com/neko233-com/jumpserver233/server/internal/core/grants"
	coregroups "github.com/neko233-com/jumpserver233/server/internal/core/groups"
	corenodes "github.com/neko233-com/jumpserver233/server/internal/core/nodes"
)

func registerGrantRoutes(mux *http.ServeMux, grants *coregrants.Store, groups *coregroups.Store, nodes *corenodes.Store, assets *coreassets.Service, identities *coreauth.Service, adminToken string, accessMu *sync.RWMutex) {
	protect := func(handler http.HandlerFunc) http.Handler {
		return protectAdminAPI(handler, adminToken, identities)
	}
	mux.Handle("GET /api/v1/grants", protect(func(w http.ResponseWriter, _ *http.Request) {
		setNoStore(w)
		writeJSON(w, http.StatusOK, grants.List())
	}))
	mux.Handle("POST /api/v1/grants", protect(func(w http.ResponseWriter, r *http.Request) {
		accessMu.Lock()
		defer accessMu.Unlock()
		var input coregrants.Input
		if err := decodeRequestJSON(w, r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid grant payload"})
			return
		}
		input.UserID = strings.TrimSpace(input.UserID)
		input.GroupID = strings.TrimSpace(input.GroupID)
		input.AssetID = strings.TrimSpace(input.AssetID)
		input.NodeID = strings.TrimSpace(input.NodeID)
		if (input.UserID == "") == (input.GroupID == "") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "exactly one user_id or group_id is required"})
			return
		}
		if (input.AssetID == "") == (input.NodeID == "") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "exactly one asset_id or node_id is required"})
			return
		}
		if input.UserID != "" {
			if _, exists := identities.UserByID(input.UserID); !exists || !organizationSubjectAllowed(r, input.UserID) {
				writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "grant user does not exist"})
				return
			}
		} else {
			if groups == nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "grant group does not exist"})
				return
			}
			if _, err := groups.Get(input.GroupID); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "grant group does not exist"})
				return
			}
		}
		if input.AssetID != "" {
			asset, err := assets.Get(input.AssetID)
			if errors.Is(err, coreassets.ErrAccountDisabled) {
				asset, err = assets.AccountAsset(input.AssetID, input.AssetID)
			}
			if err != nil {
				writeAssetError(w, err)
				return
			}
			match := strings.TrimSpace(input.Account) == asset.Username
			if coreassets.IsSSH(asset) && asset.ParentAssetID == "" {
				accounts, e := assets.ManagedAccounts(asset.ID)
				if e != nil {
					writeAssetError(w, e)
					return
				}
				for _, a := range accounts {
					match = match || strings.TrimSpace(input.Account) == a.Username
				}
			}
			if !match {
				writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "grant account must match the configured SSH asset account"})
				return
			}
			input.AssetID = coreassets.ResourceID(asset)
		}
		if input.NodeID != "" {
			if nodes == nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "grant node does not exist"})
				return
			}
			if _, err := nodes.Get(input.NodeID); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "grant node does not exist"})
				return
			}
		}
		principal, _ := PrincipalFromContext(r.Context())
		grant, err := grants.Create(input, principal.Username)
		if errors.Is(err, coregrants.ErrInvalidInput) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": err.Error()})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "grant operation failed"})
			return
		}
		setNoStore(w)
		writeJSON(w, http.StatusCreated, grant)
	}))
	mux.Handle("DELETE /api/v1/grants/{grantID}", protect(func(w http.ResponseWriter, r *http.Request) {
		accessMu.Lock()
		defer accessMu.Unlock()
		if err := grants.Delete(r.PathValue("grantID")); err != nil {
			if errors.Is(err, coregrants.ErrNotFound) {
				writeJSON(w, http.StatusNotFound, map[string]string{"detail": "grant not found"})
			} else {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "grant operation failed"})
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
}
