package api

import (
	"errors"
	"net/http"
	"strings"
	"sync"

	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	corecommandfilters "github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	coregroups "github.com/neko233-com/jumpserver233/server/internal/core/groups"
	corenodes "github.com/neko233-com/jumpserver233/server/internal/core/nodes"
)

func registerCommandFilterRoutes(mux *http.ServeMux, filters *corecommandfilters.Store, groups *coregroups.Store, nodes *corenodes.Store, assets *coreassets.Service, identities *coreauth.Service, adminToken string, accessMu *sync.RWMutex) {
	protect := func(handler http.HandlerFunc) http.Handler {
		return protectAdminAPI(handler, adminToken, identities)
	}
	mux.Handle("GET /api/v1/command-filters", protect(func(w http.ResponseWriter, _ *http.Request) {
		setNoStore(w)
		writeJSON(w, http.StatusOK, filters.List())
	}))
	mux.Handle("POST /api/v1/command-filters", protect(func(w http.ResponseWriter, r *http.Request) {
		accessMu.Lock()
		defer accessMu.Unlock()
		var input corecommandfilters.Input
		if err := decodeRequestJSON(w, r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid command filter payload"})
			return
		}
		input.UserID = strings.TrimSpace(input.UserID)
		input.GroupID = strings.TrimSpace(input.GroupID)
		input.AssetID = strings.TrimSpace(input.AssetID)
		input.NodeID = strings.TrimSpace(input.NodeID)
		input.Account = strings.TrimSpace(input.Account)
		if input.UserID != "" {
			if _, exists := identities.UserByID(input.UserID); !exists || !organizationSubjectAllowed(r, input.UserID) {
				writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "filter user does not exist"})
				return
			}
		}
		if input.GroupID != "" {
			if groups == nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "filter group does not exist"})
				return
			}
			if _, err := groups.Get(input.GroupID); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "filter group does not exist"})
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
			match := input.Account == "*" || input.Account == asset.Username
			if coreassets.IsSSH(asset) && asset.ParentAssetID == "" {
				accounts, e := assets.ManagedAccounts(asset.ID)
				if e != nil {
					writeAssetError(w, e)
					return
				}
				for _, a := range accounts {
					match = match || input.Account == a.Username
				}
			}
			if !match {
				writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "filter account must match the configured SSH asset account"})
				return
			}
			input.AssetID = coreassets.ResourceID(asset)
		}
		if input.NodeID != "" {
			if nodes == nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "filter node does not exist"})
				return
			}
			if _, err := nodes.Get(input.NodeID); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "filter node does not exist"})
				return
			}
		}
		principal, _ := PrincipalFromContext(r.Context())
		filter, err := filters.Create(input, principal.Username)
		if err != nil {
			if errors.Is(err, corecommandfilters.ErrInvalidInput) {
				writeJSON(w, http.StatusBadRequest, map[string]string{"detail": err.Error()})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "command filter operation failed"})
			return
		}
		setNoStore(w)
		writeJSON(w, http.StatusCreated, filter)
	}))
	mux.Handle("DELETE /api/v1/command-filters/{filterID}", protect(func(w http.ResponseWriter, r *http.Request) {
		accessMu.Lock()
		defer accessMu.Unlock()
		if err := filters.Delete(r.PathValue("filterID")); err != nil {
			if errors.Is(err, corecommandfilters.ErrNotFound) {
				writeJSON(w, http.StatusNotFound, map[string]string{"detail": "command filter not found"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "command filter operation failed"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
}
