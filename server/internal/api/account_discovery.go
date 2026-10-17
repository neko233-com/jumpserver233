package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/accountdiscovery"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/databasequery"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
)

func discoveryIdentity(a assets.Asset) string {
	return databasequery.Binding(struct {
		Host string
		Port int
		Pin  string
	}{a.Host, a.Port, a.HostKeyFingerprint})
}
func discoveryPoliciesAllowed(d Dependencies, u coreauth.User, a assets.Asset, origin accesspolicies.Origin) bool {
	for hops := 0; ; hops++ {
		if hops > 3 {
			return false
		}
		decision, e := checkAccessPolicies(d, u, a, origin, false)
		if e != nil || !decision.Allowed {
			return false
		}
		if a.GatewayID == "" {
			return true
		}
		a, e = d.Assets.Get(a.GatewayID)
		if e != nil || !assets.IsSSH(a) {
			return false
		}
	}
}
func discoveryJobAllowed(d Dependencies, u coreauth.User, id string, o *accountdiscovery.Operation, origin accesspolicies.Origin) bool {
	if o == nil {
		return true
	}
	if d.AccountDiscovery == nil || d.HostPlugins == nil || o.Validate() != nil || !effectivePermissions(u, d.RBAC, d.Groups).Allows("accounts.discover") {
		return false
	}
	a, e := d.Assets.Get(id)
	return e == nil && assets.IsSSH(a) && o.Binding == databaseRouteBinding(d, a) && o.Target == discoveryIdentity(a) && discoveryPoliciesAllowed(d, u, a, origin)
}
func discoverySource(d Dependencies, r *http.Request) (accountdiscovery.Source, bool) {
	u, _ := PrincipalFromContext(r.Context())
	p := effectivePermissions(u, d.RBAC, d.Groups)
	if !p.Allows("accounts.view") {
		return accountdiscovery.Source{}, false
	}
	a, e := d.Assets.Get(r.PathValue("assetID"))
	if e != nil || !assets.IsSSH(a) {
		return accountdiscovery.Source{}, false
	}
	visible := p.Allows("assets.view_all") || p.Allows("assets.manage") || p.Allows("assets.connect_all") || p.Allows("assets.sftp_all")
	if !visible {
		var groups, nodes []string
		if d.Groups != nil {
			groups = d.Groups.GroupIDsForUser(u.ID)
		}
		if d.Nodes != nil {
			nodes = d.Nodes.AncestorIDs(a.NodeID)
		}
		visible = d.Grants != nil && d.Grants.AllowsForScopes(u.ID, groups, a.ID, nodes, a.Username, "view", time.Now().UTC())
	}
	if !visible || !discoveryPoliciesAllowed(d, u, a, accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "exec"}) {
		return accountdiscovery.Source{}, false
	}
	return accountdiscovery.Source{AssetID: a.ID, Binding: discoveryIdentity(a), Account: a.Username}, true
}
func writeDiscoveryError(w http.ResponseWriter, e error) {
	status := 503
	switch {
	case errors.Is(e, accountdiscovery.ErrInvalid):
		status = 400
	case errors.Is(e, accountdiscovery.ErrConflict):
		status = 409
	case errors.Is(e, accountdiscovery.ErrCapacity):
		status = 429
	}
	writeJSON(w, status, map[string]string{"detail": "account discovery is unavailable"})
}
func discoveryFailure(e error) (sshclient.ExecResult, error) {
	code := "unavailable"
	switch {
	case errors.Is(e, hostplugins.ErrUnsupported):
		code = "unsupported_platform"
	case errors.Is(e, hostplugins.ErrIntegrity):
		code = "integrity_failed"
	case errors.Is(e, hostplugins.ErrConflict):
		code = "inventory_changed"
	case errors.Is(e, accountdiscovery.ErrCapacity):
		code = "storage_full"
	case errors.Is(e, jobs.ErrAccessDenied):
		code = "access_denied"
	}
	raw, _ := json.Marshal(map[string]string{"error_code": code})
	return sshclient.ExecResult{ExitCode: 1, Stdout: string(raw)}, e
}
func registerAccountDiscoveryRoutes(mux *http.ServeMux, d Dependencies, submit func(coreauth.User, jobs.Input, string) (operations.Submission, error), mu *sync.RWMutex, guard, guardLocked func(jobs.Job) error) {
	if d.AccountDiscovery == nil {
		return
	}
	d.Jobs.SetDiscoveryExecutor(func(ctx context.Context, j jobs.Job) (sshclient.ExecResult, error) {
		rows, digest, e := d.HostPlugins.DiscoverAccounts(ctx, j.AssetID, j.ID, func() error {
			if e := ctx.Err(); e != nil {
				return e
			}
			return guard(j)
		})
		if e != nil {
			return discoveryFailure(e)
		}
		mu.RLock()
		defer mu.RUnlock()
		if e = ctx.Err(); e != nil {
			return discoveryFailure(e)
		}
		if e = guardLocked(j); e != nil {
			return discoveryFailure(e)
		}
		summary, e := d.AccountDiscovery.Import(accountdiscovery.Source{AssetID: j.AssetID, Binding: j.Discovery.Target, Account: j.Account}, accountdiscovery.Actor{ID: j.OperatorID, Name: j.Operator}, j.ID, digest, rows)
		if e != nil {
			return discoveryFailure(e)
		}
		raw, _ := json.Marshal(summary)
		return sshclient.ExecResult{ExitCode: 0, Stdout: string(raw)}, nil
	})
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	mux.Handle("POST /api/v1/assets/{assetID}/account-discovery/jobs", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		var in struct {
			RequestID string `json:"request_id"`
			ReviewID  string `json:"review_id"`
			Timeout   int    `json:"timeout_seconds"`
		}
		if decodeRequestJSON(w, r, &in) != nil || in.RequestID == "" {
			writeJobError(w, jobs.ErrInvalid)
			return
		}
		if in.Timeout == 0 {
			in.Timeout = 180
		}
		u, _ := PrincipalFromContext(r.Context())
		a, e := d.Assets.Get(r.PathValue("assetID"))
		if e != nil {
			writeJobError(w, jobs.ErrNotFound)
			return
		}
		op := accountdiscovery.Operation{Binding: databaseRouteBinding(d, a), Target: discoveryIdentity(a)}
		result, e := submit(u, jobs.Input{Discovery: &op, AssetID: a.ID, Command: op.Command(), TimeoutSeconds: in.Timeout, RequestID: in.RequestID, Origin: accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "exec"}}, in.ReviewID)
		if e != nil {
			writeJobError(w, e)
			return
		}
		if result.ReviewID != "" {
			writeJSON(w, 202, map[string]string{"review_id": result.ReviewID, "state": "pending"})
			return
		}
		writeJSON(w, 201, result.Job)
	}))
	read := func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		mu.RLock()
		defer mu.RUnlock()
		src, ok := discoverySource(d, r)
		if !ok {
			writeJobError(w, jobs.ErrNotFound)
			return
		}
		offset, e := strconv.Atoi(defaultQuery(r, "offset", "0"))
		limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "50"))
		if e != nil || e2 != nil {
			writeDiscoveryError(w, accountdiscovery.ErrInvalid)
			return
		}
		if r.PathValue("kind") == "audit" {
			rows, total, e := d.AccountDiscovery.Audit(src.AssetID, offset, limit)
			if e != nil {
				writeDiscoveryError(w, e)
				return
			}
			writeJSON(w, 200, map[string]any{"results": rows, "total": total})
			return
		}
		page, e := d.AccountDiscovery.Findings(src, offset, limit)
		if e != nil {
			writeDiscoveryError(w, e)
			return
		}
		writeJSON(w, 200, page)
	}
	mux.Handle("GET /api/v1/assets/{assetID}/discovered-accounts", protect(read))
	mux.Handle("GET /api/v1/assets/{assetID}/discovered-accounts/{kind}", protect(func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("kind") != "audit" {
			writeJobError(w, jobs.ErrNotFound)
			return
		}
		read(w, r)
	}))
	mux.Handle("PUT /api/v1/assets/{assetID}/discovered-accounts/{findingID}", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		mu.RLock()
		defer mu.RUnlock()
		src, ok := discoverySource(d, r)
		if !ok || !hasPermission(r, "accounts.review") {
			writeJobError(w, jobs.ErrNotFound)
			return
		}
		var in struct {
			Review   string `json:"review"`
			Note     string `json:"note"`
			Revision int    `json:"revision"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			writeDiscoveryError(w, accountdiscovery.ErrInvalid)
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		row, e := d.AccountDiscovery.Review(src, accountdiscovery.Actor{ID: u.ID, Name: u.Username}, r.PathValue("findingID"), in.Review, in.Note, in.Revision)
		if e != nil {
			writeDiscoveryError(w, e)
			return
		}
		writeJSON(w, 200, row)
	}))
}
