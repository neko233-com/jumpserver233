package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"

	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
)

type accountImportRequest struct {
	Format       string `json:"format"`
	Content      []byte `json:"content"`
	RequestID    string `json:"request_id"`
	PreviewToken string `json:"preview_token,omitempty"`
}

func accountImportError(w http.ResponseWriter, e error) {
	status, code := 503, "unavailable"
	switch {
	case errors.Is(e, assets.ErrInvalidInput), errors.Is(e, assets.ErrAccountImportFormat):
		status, code = 400, "invalid"
	case errors.Is(e, assets.ErrAccountImportConflict):
		status, code = 409, "conflict"
	case errors.Is(e, assets.ErrAccountImportExpired):
		status, code = 409, "expired"
	case errors.Is(e, assets.ErrAccountImportCapacity):
		status, code = 429, "capacity"
	}
	writeJSON(w, status, map[string]string{"error_code": code})
}
func registerAccountImportRoutes(mux *http.ServeMux, d Dependencies, mu *sync.RWMutex) {
	if d.Assets == nil || d.Auth == nil {
		return
	}
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	scope := d.OrganizationID
	if scope == "" {
		scope = organizations.DefaultID
	}
	current := func(w http.ResponseWriter, r *http.Request) (coreauth.User, rbac.Snapshot, bool) {
		u, ok := PrincipalFromContext(r.Context())
		if !ok {
			writeJSON(w, 401, map[string]string{"error_code": "denied"})
			return u, rbac.Snapshot{}, false
		}
		u, ok = jobOwner(d, u.ID)
		if !ok || d.OrganizationAllowed != nil && !d.OrganizationAllowed(u) {
			writeJSON(w, 403, map[string]string{"error_code": "denied"})
			return u, rbac.Snapshot{}, false
		}
		p := effectivePermissions(u, d.RBAC, d.Groups)
		if !p.Allows("accounts.import") || !p.Allows("accounts.manage") {
			writeJSON(w, 403, map[string]string{"error_code": "denied"})
			return u, p, false
		}
		return u, p, true
	}
	visible := func(u coreauth.User, p rbac.Snapshot) func(string) bool {
		choices := d.Assets.AccountChoices()
		cache := map[string]bool{}
		seen := map[string]bool{}
		var groups []string
		if d.Groups != nil {
			groups = d.Groups.GroupIDsForUser(u.ID)
		}
		return func(id string) bool {
			if seen[id] {
				return cache[id]
			}
			seen[id] = true
			parent, e := d.Assets.AccountAsset(id, id)
			if e != nil {
				return false
			}
			var nodes []string
			if d.Nodes != nil {
				nodes = d.Nodes.AncestorIDs(parent.NodeID)
			}
			allowed := len(visibleAccountChoices(u.ID, id, choices[id], p, d.Grants, groups, nodes)) > 0
			cache[id] = allowed
			return allowed
		}
	}
	authorized := func(u coreauth.User, p rbac.Snapshot, rows []assets.AccountImportRow) []assets.AccountImportIssue {
		canSee := visible(u, p)
		issues := []assets.AccountImportIssue{}
		for _, row := range rows {
			if !canSee(row.AssetID) {
				issues = append(issues, assets.AccountImportIssue{Line: row.Line, Field: "asset_id", Code: "asset_unavailable"})
				continue
			}
			if p.Allows("assets.rotate") {
				continue
			}
			in := row.Input
			pw, key := true, false
			if row.Action == "update" {
				choices, _ := d.Assets.ManagedAccounts(row.AssetID)
				for _, a := range choices {
					if a.Username == in.Username {
						pw, key = a.PasswordRotationEnabled, a.KeyRotationEnabled
						break
					}
				}
			}
			if in.PasswordRotationEnabled != nil && *in.PasswordRotationEnabled != pw || in.KeyRotationEnabled != nil && *in.KeyRotationEnabled != key {
				issues = append(issues, assets.AccountImportIssue{Line: row.Line, Field: "password_rotation_enabled", Code: "rotation_denied"})
			}
		}
		return issues
	}
	decode := func(w http.ResponseWriter, r *http.Request) (accountImportRequest, []assets.AccountImportRow, []assets.AccountImportIssue, bool) {
		var in accountImportRequest
		r.Body = http.MaxBytesReader(w, r.Body, (14<<20)+4096)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF {
			accountImportError(w, assets.ErrInvalidInput)
			return in, nil, nil, false
		}
		rows, issues := assets.ParseAccountImport(in.Format, in.Content)
		return in, rows, issues, true
	}
	gate := func(w http.ResponseWriter, r *http.Request) bool {
		mu.RLock()
		defer mu.RUnlock()
		_, _, ok := current(w, r)
		return ok
	}
	mux.Handle("GET /api/v1/accounts/imports/template", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		mu.RLock()
		defer mu.RUnlock()
		if _, _, ok := current(w, r); !ok {
			return
		}
		format := r.URL.Query().Get("format")
		data, e := assets.AccountImportTemplate(format)
		if e != nil {
			accountImportError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"format": format, "content": data})
	}))
	mux.Handle("POST /api/v1/accounts/imports/preview", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !gate(w, r) {
			return
		}
		in, rows, issues, ok := decode(w, r)
		if !ok {
			return
		}
		mu.RLock()
		defer mu.RUnlock()
		u, p, ok := current(w, r)
		if !ok {
			return
		}
		if len(issues) == 0 {
			issues = authorized(u, p, rows)
		}
		if len(issues) > 0 {
			writeJSON(w, 200, assets.AccountImportPreview{RequestID: in.RequestID, Rows: []assets.AccountImportSummary{}, Issues: issues})
			return
		}
		out, e := d.Assets.PreviewAccountImport(r.Context(), rows, assets.AccountActor{ID: u.ID, Name: u.Username}, scope, in.RequestID)
		if e != nil {
			accountImportError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("POST /api/v1/accounts/imports", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !gate(w, r) {
			return
		}
		in, rows, issues, ok := decode(w, r)
		if !ok {
			return
		}
		mu.RLock()
		defer mu.RUnlock()
		u, p, ok := current(w, r)
		if !ok {
			return
		}
		if len(issues) > 0 {
			accountImportError(w, assets.ErrAccountImportFormat)
			return
		}
		if len(authorized(u, p, rows)) > 0 {
			writeJSON(w, 403, map[string]string{"error_code": "denied"})
			return
		}
		out, e := d.Assets.CommitAccountImport(r.Context(), rows, assets.AccountActor{ID: u.ID, Name: u.Username}, scope, in.RequestID, in.PreviewToken)
		if e != nil {
			accountImportError(w, e)
			return
		}
		writeJSON(w, 201, out)
	}))
	mux.Handle("GET /api/v1/accounts/imports", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		mu.RLock()
		defer mu.RUnlock()
		u, p, ok := current(w, r)
		if !ok {
			return
		}
		offset, e := strconv.Atoi(defaultQuery(r, "offset", "0"))
		limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "20"))
		if e != nil || e2 != nil || offset < 0 || limit < 1 || limit > 100 {
			accountImportError(w, assets.ErrInvalidInput)
			return
		}
		owner := u.ID
		if p.Allows("assets.manage") {
			owner = ""
		}
		canSee := visible(u, p)
		rows := []assets.AccountImportHistory{}
		for _, h := range d.Assets.AccountImportHistory(owner) {
			allowed := true
			for _, id := range h.AssetIDs {
				if !p.Allows("assets.manage") && !canSee(id) {
					allowed = false
					break
				}
			}
			if allowed {
				rows = append(rows, h)
			}
		}
		total := len(rows)
		offset = min(offset, total)
		writeJSON(w, 200, map[string]any{"results": rows[offset:min(total, offset+limit)], "total": total})
	}))
	mux.Handle("GET /api/v1/accounts/imports/{requestID}", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		mu.RLock()
		defer mu.RUnlock()
		u, p, ok := current(w, r)
		if !ok {
			return
		}
		owner := r.URL.Query().Get("actor_id")
		if owner == "" {
			owner = u.ID
		}
		if owner != u.ID && !p.Allows("assets.manage") {
			writeJSON(w, 404, map[string]string{"error_code": "not_found"})
			return
		}
		receipt, found := d.Assets.AccountImportReceipt(owner, r.PathValue("requestID"))
		canSee := visible(u, p)
		for _, row := range receipt.Rows {
			if !p.Allows("assets.manage") && !canSee(row.AssetID) {
				found = false
				break
			}
		}
		if !found {
			writeJSON(w, 404, map[string]string{"error_code": "not_found"})
			return
		}
		writeJSON(w, 200, receipt)
	}))
}
