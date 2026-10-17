package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
)

func remoteAccountJobAllowed(d Dependencies, u coreauth.User, collector string, op *hostagent.AccountOperation, origin accesspolicies.Origin) bool {
	if op == nil {
		return true
	}
	p := effectivePermissions(u, d.RBAC, d.Groups)
	if d.HostPlugins == nil || op.Validate() != nil || !p.Allows("accounts.manage") || !p.Allows("accounts.remote."+op.Task.Action) || !d.Assets.RemoteAccountOperationAllowed(u.ID, collector, op) {
		return false
	}
	a, e := d.Assets.Get(collector)
	return e == nil && !a.AccountDisabled && assets.IsSSH(a) && a.Username == op.CollectorAccount && assets.ResourceID(a) == op.ParentAssetID && op.Target == discoveryIdentity(a) && op.Binding == databaseRouteBinding(d, a) && discoveryPoliciesAllowed(d, u, a, origin)
}
func writeRemoteAccountError(w http.ResponseWriter, e error) {
	status, code := 503, "unavailable"
	switch {
	case errors.Is(e, assets.ErrInvalidInput), errors.Is(e, hostagent.ErrAccountAdmin):
		status, code = 400, "invalid"
	case errors.Is(e, assets.ErrNotFound):
		status, code = 404, "not_found"
	case errors.Is(e, assets.ErrRemoteAccountPending):
		status, code = 409, "pending"
	case errors.Is(e, assets.ErrRemoteAccountShared), errors.Is(e, assets.ErrGatewayInUse):
		status, code = 409, "referenced"
	case errors.Is(e, assets.ErrRemoteAccountConflict), errors.Is(e, assets.ErrCredentialChanged), errors.Is(e, assets.ErrAccountDuplicate):
		status, code = 409, "conflict"
	case errors.Is(e, assets.ErrAccountCapacity), errors.Is(e, jobs.ErrBusy):
		status, code = 429, "capacity"
	case errors.Is(e, operations.ErrDenied), errors.Is(e, jobs.ErrAccessDenied):
		status, code = 403, "denied"
	}
	writeJSON(w, status, map[string]string{"error_code": code})
}

func registerRemoteAccountRoutes(mux *http.ServeMux, d Dependencies, submit func(coreauth.User, jobs.Input, string) (operations.Submission, error), mu *sync.RWMutex, guard, guardLocked func(jobs.Job) error) {
	if d.HostPlugins == nil || d.Assets == nil || d.Jobs == nil {
		return
	}
	d.Jobs.SetRemoteAccountExecutor(func(ctx context.Context, j jobs.Job) (sshclient.ExecResult, error) {
		op := j.RemoteAccount
		if op == nil {
			return sshclient.ExecResult{ExitCode: 1}, jobs.ErrInvalid
		}
		result, e := d.Assets.ExecuteRemoteAccount(ctx, *op, j.ID, d.HostPlugins.ExecuteAccountAdmin, func() error {
			if e := ctx.Err(); e != nil {
				return e
			}
			return guard(j)
		})
		if e == nil {
			mu.RLock()
			if current := guardLocked(j); current != nil {
				e = current
			} else {
				_, e = d.Assets.CommitRemoteAccount(*op, result)
			}
			mu.RUnlock()
		}
		if result.Format != "" {
			raw, _ := json.Marshal(result)
			code := 0
			if e != nil {
				code = 1
			}
			return sshclient.ExecResult{ExitCode: code, Stdout: string(raw)}, e
		}
		raw, _ := json.Marshal(map[string]string{"error_code": "remote_unavailable"})
		return sshclient.ExecResult{ExitCode: 1, Stdout: string(raw)}, e
	})
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	readParent := func(r *http.Request) (string, bool) {
		u, _ := PrincipalFromContext(r.Context())
		p := effectivePermissions(u, d.RBAC, d.Groups)
		if !p.Allows("accounts.view") && !p.Allows("accounts.manage") {
			return "", false
		}
		a, e := d.Assets.Get(r.PathValue("assetID"))
		if e != nil || !assets.IsSSH(a) {
			return "", false
		}
		var groups, nodes []string
		if d.Groups != nil {
			groups = d.Groups.GroupIDsForUser(u.ID)
		}
		if d.Nodes != nil {
			nodes = d.Nodes.AncestorIDs(a.NodeID)
		}
		if !hasAction(scopedAssetActions(u.ID, a, p, d.Grants, groups, nodes), "view") || !discoveryPoliciesAllowed(d, u, a, accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "exec"}) {
			return "", false
		}
		return assets.ResourceID(a), true
	}
	authorize := func(r *http.Request, action, collector string) (coreauth.User, assets.Asset, accesspolicies.Origin, error) {
		u, _ := PrincipalFromContext(r.Context())
		origin := accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "exec"}
		if !hasPermission(r, "accounts.manage") || !hasPermission(r, "accounts.remote."+action) {
			return u, assets.Asset{}, origin, operations.ErrDenied
		}
		a, e := authorizeTerminalAsset(d, u, collector, assets.ProtocolSSH, origin, false)
		if e != nil || !discoveryPoliciesAllowed(d, u, a, origin) {
			return u, assets.Asset{}, origin, operations.ErrDenied
		}
		return u, a, origin, nil
	}
	respondSubmission := func(w http.ResponseWriter, u coreauth.User, t assets.RemoteAccountTask) {
		if t.State == "succeeded" || t.State == "cancelled" {
			writeJSON(w, 201, t)
			return
		}
		if t.OwnerID != u.ID {
			writeRemoteAccountError(w, operations.ErrDenied)
			return
		}
		if t.RetiredReviewID != "" {
			if d.AccessReviews == nil {
				writeRemoteAccountError(w, errors.New("review store unavailable"))
				return
			}
			if e := d.AccessReviews.CancelOwned(t.RetiredReviewID, t.RetiredReviewOwner); e != nil {
				writeRemoteAccountError(w, e)
				return
			}
			updated, e := d.Assets.AcknowledgeRemoteAccountReview(t.Operation.ParentAssetID, t.Operation.Task.ID, t.RetiredReviewID)
			if e != nil {
				writeRemoteAccountError(w, e)
				return
			}
			t = updated
		}
		if t.JobID != "" {
			if j, e := d.Jobs.Get(t.JobID); e == nil {
				if j.State == "running" || j.State == "pending_review" {
					writeJSON(w, 201, t)
					return
				}
				writeJSON(w, 200, t)
				return
			}
		}
		op := t.Operation
		in := jobs.Input{RemoteAccount: &op, AssetID: t.CollectorID, Command: op.Command(), TimeoutSeconds: 180, RequestID: "remote-account-" + op.Task.ID + "-" + strconv.FormatUint(op.Attempt, 10), Origin: t.Origin}
		out, e := submit(u, in, t.ReviewID)
		if e != nil {
			writeRemoteAccountError(w, e)
			return
		}
		t, e = d.Assets.BindRemoteAccountSubmission(op, out.Job.ID, out.ReviewID)
		if e != nil {
			writeRemoteAccountError(w, e)
			return
		}
		status := 201
		if out.ReviewID != "" {
			status = 202
		}
		writeJSON(w, status, t)
	}
	mux.Handle("GET /api/v1/assets/{assetID}/remote-account-tasks", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		mu.RLock()
		defer mu.RUnlock()
		parent, ok := readParent(r)
		if !ok {
			writeRemoteAccountError(w, assets.ErrNotFound)
			return
		}
		offset, e := strconv.Atoi(defaultQuery(r, "offset", "0"))
		limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "20"))
		if e != nil || e2 != nil || offset < 0 || limit < 1 || limit > 100 {
			writeRemoteAccountError(w, assets.ErrInvalidInput)
			return
		}
		all, e := d.Assets.RemoteAccountTasks(parent)
		if e != nil {
			writeRemoteAccountError(w, e)
			return
		}
		end := min(len(all), offset+limit)
		rows := []assets.RemoteAccountTask{}
		if offset < len(all) {
			rows = all[offset:end]
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": len(all)})
	}))
	mux.Handle("POST /api/v1/assets/{assetID}/remote-account-tasks", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		var in assets.RemoteAccountInput
		if decodeRequestJSON(w, r, &in) != nil {
			writeRemoteAccountError(w, assets.ErrInvalidInput)
			return
		}
		if in.Action == "create" && in.Shell == "" {
			in.Shell = "/bin/bash"
		}
		mu.Lock()
		u, a, origin, e := authorize(r, in.Action, r.PathValue("assetID"))
		if e != nil {
			mu.Unlock()
			writeRemoteAccountError(w, e)
			return
		}
		t, e := d.Assets.PrepareRemoteAccount(a.ID, in, databaseRouteBinding(d, a), discoveryIdentity(a), assets.AccountActor{ID: u.ID, Name: u.Username}, origin)
		mu.Unlock()
		if e != nil {
			writeRemoteAccountError(w, e)
			return
		}
		respondSubmission(w, u, t)
	}))
	mux.Handle("POST /api/v1/assets/{assetID}/remote-account-tasks/{taskID}/submit", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		mu.RLock()
		parent, ok := readParent(r)
		if !ok {
			mu.RUnlock()
			writeRemoteAccountError(w, assets.ErrNotFound)
			return
		}
		t, e := d.Assets.RemoteAccountTask(parent, r.PathValue("taskID"))
		if e != nil {
			mu.RUnlock()
			writeRemoteAccountError(w, e)
			return
		}
		u, _, _, e := authorize(r, t.Operation.Task.Action, t.CollectorID)
		mu.RUnlock()
		if e != nil {
			writeRemoteAccountError(w, e)
			return
		}
		respondSubmission(w, u, t)
	}))
	mux.Handle("POST /api/v1/assets/{assetID}/remote-account-tasks/{taskID}/attempts", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		var in struct {
			Revision int    `json:"revision"`
			Mode     string `json:"mode"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			writeRemoteAccountError(w, assets.ErrInvalidInput)
			return
		}
		mu.Lock()
		parent, ok := readParent(r)
		if !ok {
			mu.Unlock()
			writeRemoteAccountError(w, assets.ErrNotFound)
			return
		}
		t, e := d.Assets.RemoteAccountTask(parent, r.PathValue("taskID"))
		if e != nil {
			mu.Unlock()
			writeRemoteAccountError(w, e)
			return
		}
		u, a, origin, e := authorize(r, t.Operation.Task.Action, t.CollectorID)
		if e != nil || a.Username != t.Operation.CollectorAccount || discoveryIdentity(a) != t.Operation.Target {
			mu.Unlock()
			writeRemoteAccountError(w, operations.ErrDenied)
			return
		}
		if t.JobID != "" {
			if j, e := d.Jobs.Get(t.JobID); e == nil && (j.State == "running" || j.State == "pending_review") {
				mu.Unlock()
				writeRemoteAccountError(w, assets.ErrRemoteAccountPending)
				return
			}
		}
		t, e = d.Assets.ResumeRemoteAccount(parent, t.Operation.Task.ID, in.Revision, in.Mode, databaseRouteBinding(d, a), assets.AccountActor{ID: u.ID, Name: u.Username}, origin)
		mu.Unlock()
		if e != nil {
			writeRemoteAccountError(w, e)
			return
		}
		respondSubmission(w, u, t)
	}))
}
