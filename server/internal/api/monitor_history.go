package api

import (
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/monitorhistory"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
)

func registerMonitorHistoryRoutes(mux *http.ServeMux, d Dependencies, mu *sync.RWMutex) {
	if d.Assets == nil || d.Auth == nil {
		return
	}
	mux.Handle("GET /api/v1/assets/{assetID}/monitor-history", protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		global := d.GlobalAccessMu
		if global != nil && global != mu {
			global.RLock()
			defer global.RUnlock()
		}
		mu.RLock()
		defer mu.RUnlock()
		u, _ := PrincipalFromContext(r.Context())
		fresh, status := resolvePrincipal(r, d.AdminToken, d.Auth)
		if status != http.StatusOK || fresh.ID != u.ID {
			writeJSON(w, 401, map[string]string{"error_code": "authentication_required"})
			return
		}
		u = fresh
		if !enforceLoginPolicy(w, r, u) {
			return
		}
		id := r.PathValue("assetID")
		a, e := d.Assets.AccountAsset(id, id)
		if e != nil || !assets.IsSSH(a) || a.ParentAssetID != "" || !historyVisible(d, u, permissionsForRequest(r, u), a) {
			writeJSON(w, 404, map[string]string{"error_code": "not_found"})
			return
		}
		query := r.URL.Query()
		if len(query["from"]) != 1 || len(query["to"]) != 1 || len(query["step"]) > 1 {
			writeJSON(w, 400, map[string]string{"error_code": "invalid_history_range"})
			return
		}
		from, e1 := time.Parse(time.RFC3339Nano, r.URL.Query().Get("from"))
		to, e2 := time.Parse(time.RFC3339Nano, r.URL.Query().Get("to"))
		step, e3 := strconv.Atoi(defaultQuery(r, "step", "60"))
		if e1 != nil || e2 != nil || e3 != nil {
			writeJSON(w, 400, map[string]string{"error_code": "invalid_history_range"})
			return
		}
		page, e := d.Assets.MonitorHistoryContext(r.Context(), id, from, to, step)
		if e != nil {
			status, code := 503, "history_unavailable"
			if errors.Is(e, monitorhistory.ErrInvalid) {
				status, code = 400, "invalid_history_range"
			}
			if errors.Is(e, assets.ErrNotFound) {
				status, code = 404, "not_found"
			}
			writeJSON(w, status, map[string]string{"error_code": code})
			return
		}
		writeJSON(w, 200, page)
	}), d.AdminToken, d.Auth))
}

func historyVisible(d Dependencies, u coreauth.User, p rbac.Snapshot, a assets.Asset) bool {
	var groups, nodes []string
	if d.Groups != nil {
		groups = d.Groups.GroupIDsForUser(u.ID)
	}
	if d.Nodes != nil {
		nodes = d.Nodes.AncestorIDs(a.NodeID)
	}
	if hasAction(scopedAssetActions(u.ID, a, p, d.Grants, groups, nodes), "view") {
		return true
	}
	accounts, e := d.Assets.ManagedAccounts(a.ID)
	if e != nil {
		return false
	}
	for _, account := range accounts {
		bound, e := d.Assets.AccountAsset(a.ID, account.ID)
		if e == nil && hasAction(scopedAssetActions(u.ID, bound, p, d.Grants, groups, nodes), "view") {
			return true
		}
	}
	return false
}
