package api

import (
	"errors"
	"net/http"
	"sync"
	"time"

	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	corecommandfilters "github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	coregrants "github.com/neko233-com/jumpserver233/server/internal/core/grants"
	coregroups "github.com/neko233-com/jumpserver233/server/internal/core/groups"
	corenodes "github.com/neko233-com/jumpserver233/server/internal/core/nodes"
)

func registerAssetNodeRoutes(mux *http.ServeMux, nodes *corenodes.Store, assets *coreassets.Service, groups *coregroups.Store, grants *coregrants.Store, commandFilters *corecommandfilters.Store, identities *coreauth.Service, adminToken string, accessMu *sync.RWMutex) {
	protectAdmin := func(handler http.HandlerFunc) http.Handler {
		return protectAdminAPI(handler, adminToken, identities)
	}
	mux.Handle("GET /api/v1/assets/nodes", protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := PrincipalFromContext(r.Context())
		accessMu.RLock()
		defer accessMu.RUnlock()
		allNodes := nodes.List()
		if !hasPermission(r, "assets.view_all") && !hasPermission(r, "assets.manage") && !hasPermission(r, "nodes.manage") && !hasPermission(r, "assets.connect_all") && !hasPermission(r, "assets.sftp_all") {
			visibleNodeIDs := make(map[string]struct{})
			var groupIDs []string
			if groups != nil {
				groupIDs = groups.GroupIDsForUser(principal.ID)
			}
			if grants != nil {
				for _, item := range assets.List() {
					ancestors := nodes.AncestorIDs(item.NodeID)
					permissions := grants.ActionsForScopes(principal.ID, groupIDs, item.ID, ancestors, item.Username, time.Now().UTC())
					if !hasAction(permissions, "view") {
						continue
					}
					for _, nodeID := range ancestors {
						visibleNodeIDs[nodeID] = struct{}{}
					}
				}
			}
			filtered := make([]corenodes.Node, 0, len(visibleNodeIDs))
			for _, node := range allNodes {
				if _, visible := visibleNodeIDs[node.ID]; visible {
					filtered = append(filtered, node)
				}
			}
			allNodes = filtered
		}
		setNoStore(w)
		writeJSON(w, http.StatusOK, allNodes)
	}), adminToken, identities))
	mux.Handle("POST /api/v1/assets/nodes", protectAdmin(func(w http.ResponseWriter, r *http.Request) {
		accessMu.Lock()
		defer accessMu.Unlock()
		var input struct {
			Name     string `json:"name"`
			ParentID string `json:"parent_id"`
		}
		if err := decodeRequestJSON(w, r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid asset node payload"})
			return
		}
		node, err := nodes.Create(input.Name, input.ParentID)
		if err != nil {
			writeAssetNodeError(w, err)
			return
		}
		setNoStore(w)
		writeJSON(w, http.StatusCreated, node)
	}))
	mux.Handle("PUT /api/v1/assets/nodes/{nodeID}", protectAdmin(func(w http.ResponseWriter, r *http.Request) {
		accessMu.Lock()
		defer accessMu.Unlock()
		var input struct {
			Name     string `json:"name"`
			ParentID string `json:"parent_id"`
		}
		if err := decodeRequestJSON(w, r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid asset node payload"})
			return
		}
		node, err := nodes.Update(r.PathValue("nodeID"), input.Name, input.ParentID)
		if err != nil {
			writeAssetNodeError(w, err)
			return
		}
		setNoStore(w)
		writeJSON(w, http.StatusOK, node)
	}))
	mux.Handle("DELETE /api/v1/assets/nodes/{nodeID}", protectAdmin(func(w http.ResponseWriter, r *http.Request) {
		accessMu.Lock()
		defer accessMu.Unlock()
		nodeID := r.PathValue("nodeID")
		if grants != nil && grants.ReferencesNode(nodeID) {
			writeJSON(w, http.StatusConflict, map[string]string{"detail": "remove node grants before deleting the node"})
			return
		}
		if commandFilters != nil && commandFilters.ReferencesNode(nodeID) {
			writeJSON(w, http.StatusConflict, map[string]string{"detail": "remove node command filters before deleting the node"})
			return
		}
		for _, asset := range assets.List() {
			if asset.NodeID == nodeID {
				writeJSON(w, http.StatusConflict, map[string]string{"detail": "move assets out of the node before deleting it"})
				return
			}
		}
		if err := nodes.Delete(nodeID); err != nil {
			writeAssetNodeError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
}

func writeAssetNodeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, corenodes.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "asset node not found"})
	case errors.Is(err, corenodes.ErrNodeExists):
		writeJSON(w, http.StatusConflict, map[string]string{"detail": "a sibling node already has this name"})
	case errors.Is(err, corenodes.ErrHasChildren):
		writeJSON(w, http.StatusConflict, map[string]string{"detail": "move child nodes before deleting the node"})
	case errors.Is(err, corenodes.ErrInvalidParent):
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid node parent or parent cycle"})
	case errors.Is(err, corenodes.ErrInvalidInput):
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "node name must contain 1 to 64 characters"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "asset node operation failed"})
	}
}
