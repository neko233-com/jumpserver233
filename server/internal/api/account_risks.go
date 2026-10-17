package api

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/accountrisks"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
)

func accountRiskError(w http.ResponseWriter, e error) {
	status, code := 503, "unavailable"
	switch {
	case errors.Is(e, accountrisks.ErrInvalid):
		status, code = 400, "invalid"
	case errors.Is(e, accountrisks.ErrConflict):
		status, code = 409, "conflict"
	case errors.Is(e, accountrisks.ErrNotFound):
		status, code = 404, "not_found"
	case errors.Is(e, accountrisks.ErrDenied):
		status, code = 403, "denied"
	case errors.Is(e, accountrisks.ErrBusy):
		status, code = 409, "busy"
	case errors.Is(e, accountrisks.ErrCapacity):
		status, code = 429, "capacity"
	}
	writeJSON(w, status, map[string]string{"error_code": code})
}
func registerAccountRiskRoutes(mux *http.ServeMux, d Dependencies, mu *sync.RWMutex) {
	if d.AccountRisks == nil || d.Assets == nil || d.Auth == nil {
		return
	}
	service := d.AccountRisks
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	current := func(id string, permission string) (coreauth.User, rbac.Snapshot, error) {
		u, ok := jobOwner(d, id)
		if !ok || d.OrganizationAllowed != nil && !d.OrganizationAllowed(u) {
			return u, rbac.Snapshot{}, accountrisks.ErrDenied
		}
		p := effectivePermissions(u, d.RBAC, d.Groups)
		if !p.Allows(permission) {
			return u, p, accountrisks.ErrDenied
		}
		return u, p, nil
	}
	requestUser := func(w http.ResponseWriter, r *http.Request, permission string) (coreauth.User, rbac.Snapshot, bool) {
		principal, ok := PrincipalFromContext(r.Context())
		if !ok {
			accountRiskError(w, accountrisks.ErrDenied)
			return principal, rbac.Snapshot{}, false
		}
		u, p, e := current(principal.ID, permission)
		if e != nil {
			accountRiskError(w, e)
			return u, p, false
		}
		return u, p, true
	}
	service.SetRunner(func(ctx context.Context, actor accountrisks.Actor, p accountrisks.Policy, now time.Time, commit func(accountrisks.Snapshot) error) error {
		versions := d.Assets.AccountRiskVersions()
		wanted := map[string]bool{}
		for id := range versions {
			wanted[id] = true
		}
		used := map[string]time.Time{}
		merge := func(values map[string]time.Time) {
			for id, at := range values {
				if at.After(used[id]) {
					used[id] = at
				}
			}
		}
		if d.Sessions != nil {
			v, e := d.Sessions.AccountUsage(ctx, wanted)
			if e != nil {
				return e
			}
			merge(v)
		}
		if d.Jobs != nil {
			merge(d.Jobs.AccountUsage(wanted))
		}
		if d.Files != nil {
			v, e := d.Files.AccountUsage(ctx, wanted)
			if e != nil {
				return e
			}
			merge(v)
		}
		return d.Assets.CollectAccountRisks(ctx, p, now, used, service.KnownUsage(), func(snapshot accountrisks.Snapshot) error {
			_, perms, e := current(actor.ID, "accounts.risks.scan")
			if e != nil || !perms.Allows("assets.manage") {
				return accountrisks.ErrDenied
			}
			return commit(snapshot)
		})
	}, func(actor accountrisks.Actor) (func(), error) {
		global := d.GlobalAccessMu
		if global != nil && global != mu {
			global.RLock()
		}
		mu.RLock()
		_, p, e := current(actor.ID, "accounts.risks.scan")
		if e != nil || !p.Allows("assets.manage") {
			mu.RUnlock()
			if global != nil && global != mu {
				global.RUnlock()
			}
			return nil, accountrisks.ErrDenied
		}
		return func() {
			mu.RUnlock()
			if global != nil && global != mu {
				global.RUnlock()
			}
		}, nil
	})
	visibility := func(u coreauth.User, p rbac.Snapshot) (func(accountrisks.Ref) bool, func(accountrisks.Finding) bool) {
		versions := d.Assets.AccountRiskVersions()
		allowed := map[string]bool{}
		if p.Allows("assets.view_all") || p.Allows("assets.manage") {
			return func(accountrisks.Ref) bool { return true }, func(f accountrisks.Finding) bool { return versions[f.AccountID] == f.SourceVersion }
		}
		var groups []string
		if d.Groups != nil {
			groups = d.Groups.GroupIDsForUser(u.ID)
		}
		for parent, choices := range d.Assets.AccountChoices() {
			a, e := d.Assets.AccountAsset(parent, parent)
			if e != nil {
				continue
			}
			var nodes []string
			if d.Nodes != nil {
				nodes = d.Nodes.AncestorIDs(a.NodeID)
			}
			for _, c := range visibleAccountChoices(u.ID, parent, choices, p, d.Grants, groups, nodes) {
				allowed[c.ID] = true
			}
		}
		return func(r accountrisks.Ref) bool { return allowed[r.AccountID] }, func(f accountrisks.Finding) bool { return versions[f.AccountID] == f.SourceVersion }
	}
	query := func(r *http.Request) (accountrisks.Query, error) {
		offset, e := strconv.Atoi(defaultQuery(r, "offset", "0"))
		limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "50"))
		if e != nil || e2 != nil {
			return accountrisks.Query{}, accountrisks.ErrInvalid
		}
		return accountrisks.Query{Offset: offset, Limit: limit, State: r.URL.Query().Get("state"), Kind: r.URL.Query().Get("kind"), AssetID: r.URL.Query().Get("asset_id"), Search: r.URL.Query().Get("q")}, nil
	}
	mux.Handle("GET /api/v1/accounts/risks", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		mu.RLock()
		defer mu.RUnlock()
		u, p, ok := requestUser(w, r, "accounts.risks.view")
		if !ok {
			return
		}
		q, e := query(r)
		if e != nil {
			accountRiskError(w, e)
			return
		}
		visible, fresh := visibility(u, p)
		out, e := service.List(q, visible, fresh)
		if e != nil {
			accountRiskError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("GET /api/v1/accounts/risks/policy", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		mu.RLock()
		defer mu.RUnlock()
		if _, _, ok := requestUser(w, r, "accounts.risks.view"); !ok {
			return
		}
		writeJSON(w, 200, service.Policy())
	}))
	mux.Handle("PUT /api/v1/accounts/risks/policy", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		var in accountrisks.Policy
		if decodeRequestJSON(w, r, &in) != nil {
			accountRiskError(w, accountrisks.ErrInvalid)
			return
		}
		mu.RLock()
		defer mu.RUnlock()
		u, p, ok := requestUser(w, r, "accounts.risks.manage")
		if !ok {
			return
		}
		if !p.Allows("assets.manage") || in.Enabled && !p.Allows("accounts.risks.scan") {
			accountRiskError(w, accountrisks.ErrDenied)
			return
		}
		out, e := service.Configure(in, accountrisks.Actor{ID: u.ID, Name: u.Username})
		if e != nil {
			accountRiskError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("POST /api/v1/accounts/risks/scans", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		var in struct {
			Revision  int    `json:"revision"`
			RequestID string `json:"request_id"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			accountRiskError(w, accountrisks.ErrInvalid)
			return
		}
		mu.RLock()
		u, p, ok := requestUser(w, r, "accounts.risks.scan")
		mu.RUnlock()
		if !ok {
			return
		}
		if !p.Allows("assets.manage") {
			accountRiskError(w, accountrisks.ErrDenied)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		out, e := service.Scan(ctx, accountrisks.Actor{ID: u.ID, Name: u.Username}, in.RequestID, in.Revision, false)
		if e != nil {
			accountRiskError(w, e)
			return
		}
		writeJSON(w, 201, out)
	}))
	mux.Handle("GET /api/v1/accounts/risks/scans", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		mu.RLock()
		defer mu.RUnlock()
		_, p, ok := requestUser(w, r, "accounts.risks.view")
		if !ok {
			return
		}
		if !p.Allows("assets.view_all") && !p.Allows("assets.manage") {
			accountRiskError(w, accountrisks.ErrDenied)
			return
		}
		q, e := query(r)
		if e != nil {
			accountRiskError(w, e)
			return
		}
		rows, total, e := service.Scans(q.Offset, q.Limit)
		if e != nil {
			accountRiskError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": total})
	}))
	mux.Handle("DELETE /api/v1/accounts/risks/scans/{id}", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		mu.RLock()
		defer mu.RUnlock()
		u, p, ok := requestUser(w, r, "accounts.risks.scan")
		if !ok {
			return
		}
		run, found := service.ScanRecord(r.PathValue("id"))
		if !found || run.Actor.ID != u.ID && !p.Allows("accounts.risks.manage") {
			accountRiskError(w, accountrisks.ErrNotFound)
			return
		}
		if !p.Allows("assets.manage") {
			accountRiskError(w, accountrisks.ErrDenied)
			return
		}
		if e := service.Cancel(run.ID); e != nil {
			accountRiskError(w, e)
			return
		}
		w.WriteHeader(204)
	}))
	mux.Handle("POST /api/v1/accounts/risks/{id}/review", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		var in struct {
			Revision int    `json:"revision"`
			Action   string `json:"action"`
			Note     string `json:"note"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			accountRiskError(w, accountrisks.ErrInvalid)
			return
		}
		mu.RLock()
		defer mu.RUnlock()
		u, p, ok := requestUser(w, r, "accounts.risks.manage")
		if !ok {
			return
		}
		visible, fresh := visibility(u, p)
		f, found := service.VisibleFind(r.PathValue("id"), visible, fresh)
		if !found || !p.Allows("accounts.risks.view") {
			accountRiskError(w, accountrisks.ErrNotFound)
			return
		}
		if !fresh(f) {
			accountRiskError(w, accountrisks.ErrConflict)
			return
		}
		var out accountrisks.Finding
		e := d.Assets.WithAccountRiskVersion(f.AccountID, f.SourceVersion, func() error {
			var err error
			out, err = service.Review(f.ID, in.Revision, in.Action, in.Note, accountrisks.Actor{ID: u.ID, Name: u.Username})
			return err
		})
		if e != nil {
			accountRiskError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("GET /api/v1/accounts/risks/audit", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		mu.RLock()
		defer mu.RUnlock()
		_, p, ok := requestUser(w, r, "accounts.risks.view")
		if !ok {
			return
		}
		if !p.Allows("assets.view_all") && !p.Allows("assets.manage") {
			accountRiskError(w, accountrisks.ErrDenied)
			return
		}
		q, e := query(r)
		if e != nil {
			accountRiskError(w, e)
			return
		}
		rows, total, e := service.Audit(q.Offset, q.Limit)
		if e != nil {
			accountRiskError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": total})
	}))
	mux.Handle("GET /api/v1/accounts/risks/export", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		mu.RLock()
		defer mu.RUnlock()
		u, p, ok := requestUser(w, r, "accounts.risks.export")
		if !ok {
			return
		}
		if !p.Allows("accounts.risks.view") {
			accountRiskError(w, accountrisks.ErrDenied)
			return
		}
		q, e := query(r)
		if e != nil {
			accountRiskError(w, e)
			return
		}
		visible, fresh := visibility(u, p)
		page, e := service.Export(q, visible, fresh)
		if e != nil {
			accountRiskError(w, e)
			return
		}
		var b bytes.Buffer
		b.WriteString("\xef\xbb\xbf")
		writer := csv.NewWriter(&b)
		_ = writer.Write([]string{"finding_id", "asset_id", "account_id", "asset_name", "username", "risk", "severity", "state", "first_seen", "last_seen", "rotated_at", "last_used_at", "related_accounts", "outdated", "note"})
		for _, f := range page.Results {
			lastUsed := ""
			if !f.LastUsedAt.IsZero() {
				lastUsed = f.LastUsedAt.Format(time.RFC3339)
			}
			row := []string{f.ID, f.AssetID, f.AccountID, f.AssetName, f.Username, f.Kind, f.Severity, f.State, f.FirstSeen.Format(time.RFC3339), f.LastSeen.Format(time.RFC3339), f.RotatedAt.Format(time.RFC3339), lastUsed, strconv.Itoa(f.PeerCount), strconv.FormatBool(f.Outdated), f.Note}
			for i, v := range row {
				trim := strings.TrimLeft(v, " \t\r\n")
				if trim != "" && strings.ContainsRune("=+-@", rune(trim[0])) {
					row[i] = "'" + v
				}
			}
			_ = writer.Write(row)
		}
		writer.Flush()
		if writer.Error() != nil {
			accountRiskError(w, accountrisks.ErrBusy)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="account-risks.csv"`)
		w.Write(b.Bytes())
	}))
}
