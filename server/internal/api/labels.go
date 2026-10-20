package api

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"sync"

	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/labels"
	corenodes "github.com/neko233-com/jumpserver233/server/internal/core/nodes"
)

func labelError(w http.ResponseWriter, e error) {
	status, code := 503, "labels_unavailable"
	switch {
	case errors.Is(e, labels.ErrInvalid):
		status, code = 400, "labels_invalid"
	case errors.Is(e, labels.ErrNotFound):
		status, code = 404, "labels_not_found"
	case errors.Is(e, labels.ErrConflict):
		status, code = 409, "labels_conflict"
	case errors.Is(e, labels.ErrInUse):
		status, code = 409, "labels_in_use"
	case errors.Is(e, labels.ErrCapacity):
		status, code = 507, "labels_capacity"
	}
	setNoStore(w)
	writeJSON(w, status, map[string]string{"error_code": code})
}
func assetLabelResources(a coreassets.Asset, nodes *corenodes.Store) []labels.Resource {
	return nodeLabelResources(labels.Resource{Type: "asset", ID: coreassets.ResourceID(a)}, a.NodeID, nodes)
}
func nodeLabelResources(first labels.Resource, nodeID string, nodes *corenodes.Store) []labels.Resource {
	out := []labels.Resource{first}
	seen := map[string]bool{}
	for nodes != nil && nodeID != "" && !seen[nodeID] {
		seen[nodeID] = true
		n, e := nodes.Get(nodeID)
		if e != nil {
			break
		}
		r := labels.Resource{Type: "node", ID: n.ID}
		if r != first {
			out = append(out, r)
		}
		nodeID = n.ParentID
	}
	return out
}
func labelTarget(d Dependencies, r *http.Request, write bool) (labels.Resource, []labels.Resource, bool) {
	resource := labels.Resource{Type: r.PathValue("resourceType"), ID: r.PathValue("resourceID")}
	if !labels.ValidResource(resource) {
		return resource, nil, false
	}
	u, _ := PrincipalFromContext(r.Context())
	p := permissionsForRequest(r, u)
	if write && !p.Allows("labels.assign") {
		return resource, nil, false
	}
	if resource.Type == "asset" {
		if d.Assets == nil {
			return resource, nil, false
		}
		a, e := d.Assets.Get(resource.ID)
		if e != nil {
			return resource, nil, false
		}
		resource.ID = coreassets.ResourceID(a)
		if a.ParentAssetID != "" {
			a, e = d.Assets.Get(resource.ID)
			if e != nil {
				return resource, nil, false
			}
		}
		if !historyVisible(d, u, p, a) {
			return resource, nil, false
		}
		return resource, assetLabelResources(a, d.Nodes), true
	}
	if d.Nodes == nil {
		return resource, nil, false
	}
	n, e := d.Nodes.Get(resource.ID)
	if e != nil {
		return resource, nil, false
	}
	if write && !p.Allows("nodes.manage") {
		return resource, nil, false
	}
	if p.Allows("nodes.manage") || p.Allows("assets.view_all") || p.Allows("assets.manage") {
		return resource, nodeLabelResources(resource, n.ParentID, d.Nodes), true
	}
	if d.Assets != nil {
		for _, a := range d.Assets.List() {
			if slices.Contains(d.Nodes.AncestorIDs(a.NodeID), n.ID) && historyVisible(d, u, p, a.Asset) {
				return resource, nodeLabelResources(resource, n.ParentID, d.Nodes), true
			}
		}
	}
	return resource, nil, false
}
func labelResourceExists(d Dependencies, r labels.Resource) bool {
	switch r.Type {
	case "asset":
		if d.Assets == nil {
			return true
		}
		_, e := d.Assets.Get(r.ID)
		return !errors.Is(e, coreassets.ErrNotFound)
	case "node":
		if d.Nodes == nil {
			return true
		}
		_, e := d.Nodes.Get(r.ID)
		return !errors.Is(e, corenodes.ErrNotFound)
	}
	return true
}
func registerLabelRoutes(mux *http.ServeMux, d Dependencies, mu *sync.RWMutex) {
	if d.Labels == nil {
		return
	}
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	require := func(w http.ResponseWriter, r *http.Request, p string) (coreauth.User, bool) {
		u, _ := PrincipalFromContext(r.Context())
		if !hasPermission(r, p) {
			writeJSON(w, 403, map[string]string{"error_code": "permission_denied"})
			return u, false
		}
		return u, true
	}
	page := func(w http.ResponseWriter, r *http.Request) (int, int, bool) {
		offset, e := strconv.Atoi(defaultQuery(r, "offset", "0"))
		limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "50"))
		if e != nil || e2 != nil || offset < 0 || limit < 1 || limit > 100 {
			labelError(w, labels.ErrInvalid)
			return 0, 0, false
		}
		return offset, limit, true
	}
	list := func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		offset, limit, ok := page(w, r)
		if !ok {
			return
		}
		rows, total, e := d.Labels.Page(r.URL.Query().Get("search"), offset, limit)
		if e != nil {
			labelError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": total})
	}
	save := func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		mu.RLock()
		defer mu.RUnlock()
		u, ok := require(w, r, "labels.manage")
		if !ok {
			return
		}
		var in labels.Input
		if decodeRequestJSON(w, r, &in) != nil {
			labelError(w, labels.ErrInvalid)
			return
		}
		value, e := d.Labels.Save(r.PathValue("labelID"), u.ID, in)
		if e != nil {
			labelError(w, e)
			return
		}
		status := 200
		if r.Method == "POST" {
			status = 201
		}
		writeJSON(w, status, value)
	}
	remove := func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		mu.RLock()
		defer mu.RUnlock()
		u, ok := require(w, r, "labels.manage")
		if !ok {
			return
		}
		var in struct {
			Revision  int    `json:"revision"`
			RequestID string `json:"request_id"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			labelError(w, labels.ErrInvalid)
			return
		}
		e := d.Labels.Delete(r.PathValue("labelID"), u.ID, in.Revision, in.RequestID, func(resource labels.Resource) bool { return labelResourceExists(d, resource) })
		if e != nil {
			labelError(w, e)
			return
		}
		w.WriteHeader(204)
	}
	for _, suffix := range []string{"", "/{$}"} {
		mux.Handle("GET /api/v1/labels/labels"+suffix, protect(list))
		mux.Handle("POST /api/v1/labels/labels"+suffix, protect(save))
		mux.Handle("PUT /api/v1/labels/labels/{labelID}"+suffix, protect(save))
		mux.Handle("DELETE /api/v1/labels/labels/{labelID}"+suffix, protect(remove))
	}
	mux.Handle("GET /api/v1/labels/choices", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		rows, e := d.Labels.Choices()
		if e != nil {
			labelError(w, e)
			return
		}
		writeJSON(w, 200, rows)
	}))
	mux.Handle("GET /api/v1/labels/audit", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if _, ok := require(w, r, "labels.audit"); !ok {
			return
		}
		offset, limit, ok := page(w, r)
		if !ok {
			return
		}
		rows, total, e := d.Labels.Audit(offset, limit)
		if e != nil {
			labelError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": total})
	}))
	readBinding := func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		mu.RLock()
		defer mu.RUnlock()
		resource, chain, ok := labelTarget(d, r, false)
		if !ok {
			labelError(w, labels.ErrNotFound)
			return
		}
		binding, effective, e := d.Labels.View(chain)
		if e != nil {
			labelError(w, e)
			return
		}
		canAssign := hasPermission(r, "labels.assign") && (resource.Type == "asset" || hasPermission(r, "nodes.manage"))
		writeJSON(w, 200, map[string]any{"binding": binding, "effective": effective, "assignable": canAssign})
	}
	writeBinding := func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		mu.RLock()
		defer mu.RUnlock()
		resource, _, ok := labelTarget(d, r, true)
		if !ok {
			labelError(w, labels.ErrNotFound)
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		var in labels.BindingInput
		if decodeRequestJSON(w, r, &in) != nil {
			labelError(w, labels.ErrInvalid)
			return
		}
		binding, e := d.Labels.Bind(resource, u.ID, in)
		if e != nil {
			labelError(w, e)
			return
		}
		writeJSON(w, 200, binding)
	}
	mux.Handle("GET /api/v1/labels/bindings/{resourceType}/{resourceID}", protect(readBinding))
	mux.Handle("PUT /api/v1/labels/bindings/{resourceType}/{resourceID}", protect(writeBinding))
}

type labeledAsset struct {
	coreassets.ListItem
	Labels []labels.Applied `json:"labels"`
}

func writeLabeledAssets(w http.ResponseWriter, r *http.Request, items []coreassets.ListItem, store *labels.Store, nodes *corenodes.Store) {
	wanted := r.URL.Query()["label"]
	if len(wanted) > 64 {
		labelError(w, labels.ErrInvalid)
		return
	}
	for _, id := range wanted {
		if !labels.ValidID(id) {
			labelError(w, labels.ErrInvalid)
			return
		}
	}
	if store == nil {
		if len(wanted) > 0 {
			labelError(w, labels.ErrClosed)
			return
		}
		writeJSON(w, 200, items)
		return
	}
	out := []labeledAsset{}
	for _, a := range items {
		applied, e := store.Effective(assetLabelResources(a.Asset, nodes))
		if e != nil {
			labelError(w, e)
			return
		}
		matches := true
		for _, id := range wanted {
			found := false
			for _, l := range applied {
				if l.ID == id {
					found = true
					break
				}
			}
			matches = matches && found
		}
		if matches {
			out = append(out, labeledAsset{ListItem: a, Labels: applied})
		}
	}
	writeJSON(w, 200, out)
}
