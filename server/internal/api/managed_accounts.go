package api

import (
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/accountdiscovery"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coregrants "github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
)

func scopedAssetActions(userID string, a assets.Asset, p rbac.Snapshot, grants *coregrants.Store, groups, nodes []string) []string {
	actions := []string{}
	if grants != nil {
		actions = grants.ActionsForScopes(userID, groups, assets.ResourceID(a), nodes, a.Username, time.Now().UTC())
	}
	for action, permission := range map[string]string{"view": "assets.view_all", "manage": "assets.manage", "connect": "assets.connect_all", "sftp": "assets.sftp_all", "probe": "assets.probe", "rotate": "assets.rotate", "backups": "assets.backups"} {
		if p.Allows(permission) {
			if !hasAction(actions, action) {
				actions = append(actions, action)
			}
			if (action == "manage" || action == "connect" || action == "sftp") && !hasAction(actions, "view") {
				actions = append(actions, "view")
			}
		}
	}
	if a.AccountDisabled {
		actions = slices.DeleteFunc(actions, func(v string) bool { return v == "connect" || v == "sftp" })
	}
	sort.Strings(actions)
	return actions
}

func visibleAccountChoices(userID, parentID string, choices []assets.AccountChoice, p rbac.Snapshot, grants *coregrants.Store, groups, nodes []string) []assets.AccountChoice {
	rows := append([]assets.AccountChoice(nil), choices...)
	visibleParent := false
	for i := range rows {
		a := assets.Asset{ID: parentID, Username: rows[i].Username, AccountDisabled: !rows[i].Active}
		rows[i].Permissions = scopedAssetActions(userID, a, p, grants, groups, nodes)
		visibleParent = visibleParent || hasAction(rows[i].Permissions, "view")
	}
	if !visibleParent {
		return []assets.AccountChoice{}
	}
	inspect := p.Allows("accounts.manage") || p.Allows("accounts.view")
	visible := []assets.AccountChoice{}
	for _, a := range rows {
		if inspect || hasAction(a.Permissions, "view") {
			if !hasAction(a.Permissions, "view") {
				a.Permissions = append(a.Permissions, "view")
			}
			visible = append(visible, a)
		}
	}
	return visible
}

func registerManagedAccountRoutes(mux *http.ServeMux, d Dependencies, mu *sync.RWMutex) {
	redact := func(r *http.Request, a assets.ManagedAccount) assets.ManagedAccount {
		if !hasPermission(r, "assets.manage") && !hasPermission(r, "assets.rotate") && !hasPermission(r, "assets.backups") {
			a.PasswordRotation, a.SSHKeyRotation = nil, nil
		}
		return a
	}
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	choices := func(r *http.Request) []assets.AccountChoice {
		u, _ := PrincipalFromContext(r.Context())
		id := r.PathValue("assetID")
		parent, e := d.Assets.AccountAsset(id, id)
		if e != nil {
			return nil
		}
		var groups, nodes []string
		if d.Groups != nil {
			groups = d.Groups.GroupIDsForUser(u.ID)
		}
		if d.Nodes != nil {
			nodes = d.Nodes.AncestorIDs(parent.NodeID)
		}
		return visibleAccountChoices(u.ID, id, d.Assets.AccountChoices()[id], permissionsForRequest(r, u), d.Grants, groups, nodes)
	}
	actor := func(r *http.Request) assets.AccountActor {
		u, _ := PrincipalFromContext(r.Context())
		return assets.AccountActor{ID: u.ID, Name: u.Username}
	}
	writeAllowed := func(w http.ResponseWriter, r *http.Request) bool {
		if !hasPermission(r, "accounts.manage") {
			writeJSON(w, 403, map[string]string{"detail": "account management permission required"})
			return false
		}
		if len(choices(r)) == 0 {
			writeAssetError(w, assets.ErrNotFound)
			return false
		}
		return true
	}
	visible := func(r *http.Request, id string) ([]string, bool) {
		for _, a := range choices(r) {
			if a.ID == id {
				return a.Permissions, true
			}
		}
		return nil, false
	}
	policyAllowed := func(w http.ResponseWriter, r *http.Request, in assets.AccountInput, previous *assets.ManagedAccount) bool {
		changed := in.KeyRotationEnabled != nil && *in.KeyRotationEnabled
		if previous != nil {
			changed = in.KeyRotationEnabled != nil && *in.KeyRotationEnabled != previous.KeyRotationEnabled
		}
		if in.PasswordRotationEnabled != nil {
			was := true
			if previous != nil {
				was = previous.PasswordRotationEnabled
			}
			changed = changed || *in.PasswordRotationEnabled != was
		}
		if changed && !hasPermission(r, "assets.rotate") {
			writeJSON(w, 403, map[string]string{"detail": "credential rotation permission required"})
			return false
		}
		return true
	}
	mux.Handle("GET /api/v1/assets/{assetID}/accounts", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		mu.RLock()
		defer mu.RUnlock()
		allowed := choices(r)
		if len(allowed) == 0 {
			writeAssetError(w, assets.ErrNotFound)
			return
		}
		offset, e := strconv.Atoi(defaultQuery(r, "offset", "0"))
		limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "100"))
		q, username := r.URL.Query().Get("q"), r.URL.Query().Get("username")
		if e != nil || e2 != nil || offset < 0 || limit < 1 || limit > 100 || len(q) > 128 || len(username) > 128 {
			writeAssetError(w, assets.ErrInvalidInput)
			return
		}
		matched := []assets.AccountChoice{}
		for _, a := range allowed {
			if username != "" && a.Username != username || q != "" && !strings.Contains(strings.ToLower(a.Username+" "+a.Name), strings.ToLower(q)) {
				continue
			}
			matched = append(matched, a)
		}
		total := len(matched)
		if offset >= total {
			matched = nil
		} else {
			matched = matched[offset:min(offset+limit, total)]
		}
		rows := []assets.ManagedAccount{}
		for _, a := range matched {
			row, e := d.Assets.ManagedAccount(r.PathValue("assetID"), a.ID)
			if e != nil {
				writeAssetError(w, e)
				return
			}
			row.Permissions = a.Permissions
			rows = append(rows, redact(r, row))
		}
		parent, e := d.Assets.ManagedAccount(r.PathValue("assetID"), r.PathValue("assetID"))
		if e != nil {
			writeAssetError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": total, "version": parent.Version})
	}))
	mux.Handle("GET /api/v1/assets/{assetID}/accounts/{accountID}", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		mu.RLock()
		defer mu.RUnlock()
		actions, ok := visible(r, r.PathValue("accountID"))
		if !ok {
			writeAssetError(w, assets.ErrNotFound)
			return
		}
		a, e := d.Assets.ManagedAccount(r.PathValue("assetID"), r.PathValue("accountID"))
		if e != nil {
			writeAssetError(w, e)
			return
		}
		a.Permissions = actions
		writeJSON(w, 200, redact(r, a))
	}))
	mux.Handle("GET /api/v1/assets/{assetID}/accounts/{accountID}/activity", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		mu.RLock()
		defer mu.RUnlock()
		_, ok := visible(r, r.PathValue("accountID"))
		if !ok || !hasPermission(r, "accounts.view") && !hasPermission(r, "accounts.manage") {
			writeAssetError(w, assets.ErrNotFound)
			return
		}
		offset, e := strconv.Atoi(defaultQuery(r, "offset", "0"))
		limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "20"))
		if e != nil || e2 != nil {
			writeAssetError(w, assets.ErrInvalidInput)
			return
		}
		rows, total, e := d.Assets.AccountActivity(r.PathValue("assetID"), r.PathValue("accountID"), offset, limit)
		if e != nil {
			writeAssetError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": total})
	}))
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		path := method + " /api/v1/assets/{assetID}/accounts"
		if method != "POST" {
			path += "/{accountID}"
		}
		mux.Handle(path, protect(func(w http.ResponseWriter, r *http.Request) {
			setNoStore(w)
			mu.Lock()
			defer mu.Unlock()
			if !writeAllowed(w, r) {
				return
			}
			if method == "DELETE" {
				var in struct {
					Version string `json:"version"`
				}
				if decodeRequestJSON(w, r, &in) != nil {
					writeAssetError(w, assets.ErrInvalidInput)
					return
				}
				if e := d.Assets.DeleteManagedAccount(r.PathValue("assetID"), r.PathValue("accountID"), in.Version, actor(r)); e != nil {
					writeAssetError(w, e)
					return
				}
				w.WriteHeader(204)
				return
			}
			var in assets.AccountInput
			if decodeRequestJSON(w, r, &in) != nil {
				writeAssetError(w, assets.ErrInvalidInput)
				return
			}
			var a assets.ManagedAccount
			var e error
			if in.DiscoveryID != nil && *in.DiscoveryID != "" {
				if !hasPermission(r, "accounts.view") || d.AccountDiscovery == nil {
					writeJSON(w, 403, map[string]string{"detail": "account discovery permission required"})
					return
				}
				parent, err := d.Assets.AccountAsset(r.PathValue("assetID"), r.PathValue("assetID"))
				if err != nil {
					writeAssetError(w, err)
					return
				}
				username := in.Username
				if method == "PUT" {
					previous, err := d.Assets.AccountAsset(parent.ID, r.PathValue("accountID"))
					if err != nil {
						writeAssetError(w, err)
						return
					}
					username = previous.Username
				}
				finding, err := d.AccountDiscovery.Finding(accountdiscovery.Source{AssetID: parent.ID, Binding: discoveryIdentity(parent), Account: parent.Username}, *in.DiscoveryID)
				if err != nil || finding.Username != username {
					writeAssetError(w, assets.ErrInvalidInput)
					return
				}
			}
			if method == "POST" {
				if !policyAllowed(w, r, in, nil) {
					return
				}
				a, e = d.Assets.CreateManagedAccount(r.PathValue("assetID"), in, actor(r))
			} else {
				previous, err := d.Assets.ManagedAccount(r.PathValue("assetID"), r.PathValue("accountID"))
				if err != nil {
					writeAssetError(w, err)
					return
				}
				if !policyAllowed(w, r, in, &previous) {
					return
				}
				a, e = d.Assets.UpdateManagedAccount(r.PathValue("assetID"), r.PathValue("accountID"), in, actor(r))
			}
			if e != nil {
				writeAssetError(w, e)
				return
			}
			a, e = d.Assets.ManagedAccount(r.PathValue("assetID"), a.ID)
			if e != nil {
				writeAssetError(w, e)
				return
			}
			a.Permissions, _ = visible(r, a.ID)
			status := 200
			if method == "POST" {
				status = 201
			}
			writeJSON(w, status, redact(r, a))
		}))
	}
}
