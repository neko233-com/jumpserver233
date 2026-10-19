package api

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/agentevents"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
)

func registerJobRoutes(mux *http.ServeMux, d Dependencies, accessMu *sync.RWMutex) {
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	// Re-evaluate authorization at submission and at command-review approval.
	authorize := func(user coreauth.User, assetID, command string, origin accesspolicies.Origin) (string, string, commandfilters.Decision, int) {
		if origin.Method == "" {
			origin.Method = "exec"
		}
		if origin.Method != "exec" && origin.Method != "scheduled_exec" {
			return "", "", commandfilters.Decision{}, http.StatusForbidden
		}
		asset, err := d.Assets.Get(assetID)
		if err != nil {
			return "", "", commandfilters.Decision{}, http.StatusNotFound
		}
		if !assets.IsSSH(asset) {
			return "", "", commandfilters.Decision{}, http.StatusBadRequest
		}
		var groupIDs, nodeIDs []string
		if d.Groups != nil {
			groupIDs = d.Groups.GroupIDsForUser(user.ID)
		}
		if d.Nodes != nil {
			nodeIDs = d.Nodes.AncestorIDs(asset.NodeID)
		}
		if !effectivePermissions(user, d.RBAC, d.Groups).Allows("assets.connect_all") && (d.Grants == nil || !d.Grants.AllowsForScopes(user.ID, groupIDs, assets.ResourceID(asset), nodeIDs, asset.Username, "connect", time.Now().UTC())) {
			return "", "", commandfilters.Decision{}, http.StatusForbidden
		}
		decision := commandfilters.Decision{Allowed: true, Action: commandfilters.ActionAllow}
		policy, policyError := checkAccessPolicies(d, user, asset, origin, true)
		if policyError != nil {
			return "", "", commandfilters.Decision{}, http.StatusServiceUnavailable
		}
		if !policy.Allowed {
			return "", "", commandfilters.Decision{}, http.StatusForbidden
		}
		if d.CommandFilters != nil {
			decision = d.CommandFilters.Decide(commandfilters.Scope{UserID: user.ID, GroupIDs: groupIDs, AssetID: assets.ResourceID(asset), NodeIDs: nodeIDs, Account: asset.Username}, command, !strings.ContainsAny(command, ";&|`$<>\\()\n\r\t"), time.Now().UTC())
		}
		return asset.Name, asset.Username, decision, http.StatusOK
	}
	jobGuardLocked := func(job jobs.Job) error {
		if job.ConnectionScope == "" && job.Plugin == nil && job.Discovery == nil && job.RemoteAccount == nil && job.State == "pending_review" {
			return jobs.ErrAccessDenied
		}
		if job.ConnectionScope != "" {
			connection, err := accessreviews.ParseConnectionScope(job.ConnectionScope)
			current, currentErr := d.Assets.Get(job.AssetID)
			if err != nil || currentErr != nil {
				return jobs.ErrAccessDenied
			}
			binding, err := d.Assets.BindConnection(current)
			if err != nil || binding != connection.Binding {
				return jobs.ErrAccessDenied
			}
		}
		if job.PlaybookStep != nil && (d.Operations == nil || !d.Operations.WorkflowJobAllowed(job.OperatorID, job.AssetID, *job.PlaybookStep, job.Command)) {
			return jobs.ErrAccessDenied
		}
		owner, ok := jobOwner(d, job.OperatorID)
		if !ok {
			return jobs.ErrAccessDenied
		}
		if !pluginJobAllowed(d, owner, job.AssetID, job.Plugin) || !discoveryJobAllowed(d, owner, job.AssetID, job.Discovery, job.AccessOrigin) || !remoteAccountJobAllowed(d, owner, job.AssetID, job.RemoteAccount, job.AccessOrigin) {
			return jobs.ErrAccessDenied
		}
		_, account, decision, status := authorize(owner, job.AssetID, job.Command, job.AccessOrigin)
		if status != http.StatusOK || account != job.Account || decision.Action == commandfilters.ActionDeny {
			return jobs.ErrAccessDenied
		}
		return nil
	}
	jobGuard := func(j jobs.Job) error { accessMu.RLock(); defer accessMu.RUnlock(); return jobGuardLocked(j) }
	d.Jobs.SetExecutionGuard(jobGuard)
	d.Jobs.SetConnectionContext(func(ctx context.Context, job jobs.Job) (context.Context, error) {
		connection, err := accessreviews.ParseConnectionScope(job.ConnectionScope)
		if err != nil {
			return ctx, jobs.ErrAccessDenied
		}
		ctx = assets.WithConnectionBinding(ctx, connection.Binding)
		return assets.WithWorkspaceIdentity(ctx, connection.Identity), nil
	})
	submitUser := func(user coreauth.User, input jobs.Input, reviewID string) (operations.Submission, error) {
		input, err := jobs.Validate(input)
		if err != nil {
			return operations.Submission{}, err
		}
		accessMu.RLock()
		defer accessMu.RUnlock()
		if input.PlaybookStep != nil && (d.Operations == nil || !d.Operations.WorkflowJobAllowed(user.ID, input.AssetID, *input.PlaybookStep, input.Command)) {
			return operations.Submission{}, operations.ErrDenied
		}
		if !pluginJobAllowed(d, user, input.AssetID, input.Plugin) || !discoveryJobAllowed(d, user, input.AssetID, input.Discovery, input.Origin) || !remoteAccountJobAllowed(d, user, input.AssetID, input.RemoteAccount, input.Origin) {
			return operations.Submission{}, operations.ErrDenied
		}
		assetName, account, decision, status := authorize(user, input.AssetID, input.Command, input.Origin)
		if status != http.StatusOK {
			return operations.Submission{}, operations.ErrDenied
		}
		asset, _ := d.Assets.Get(input.AssetID)
		reviewAction, reviewScope := accessreviews.ActionSSH, ""
		if input.Discovery != nil && input.Discovery.PlanID != "" {
			reviewAction = accessreviews.ActionAccountDiscovery
			reviewScope = input.Discovery.PlanID + ":" + strconv.FormatUint(input.Discovery.Sequence, 10)
		}
		if input.RemoteAccount != nil {
			reviewAction = accessreviews.ActionRemoteAccount
			reviewScope = input.RemoteAccount.Task.ID + ":" + strconv.FormatUint(input.RemoteAccount.Attempt, 10)
		}
		if input.Plugin == nil && input.Discovery == nil && input.RemoteAccount == nil && decision.Action != commandfilters.ActionDeny {
			binding, err := d.Assets.BindConnection(asset)
			if err != nil {
				return operations.Submission{}, operations.ErrDenied
			}
			workspace, identity := "", ""
			needsProof := decision.Action == commandfilters.ActionReview || asset.LoginReviewRequired && !effectivePermissions(user, d.RBAC, d.Groups).Allows("login_review.bypass")
			if needsProof && asset.SSHWorkspace != "" {
				probeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				identity, err = d.Assets.WorkspaceIdentity(assets.WithConnectionBinding(probeCtx, binding), asset.ID)
				cancel()
				if err != nil {
					return operations.Submission{}, err
				}
				workspace = asset.SSHWorkspace
			}
			reviewScope, err = accessreviews.ConnectionScope(binding, workspace, identity)
			if err != nil {
				return operations.Submission{}, err
			}
			input.ConnectionScope = reviewScope
		}
		pendingID := ""
		gate := func() error {
			if decision.Action == commandfilters.ActionDeny || effectivePermissions(user, d.RBAC, d.Groups).Allows("login_review.bypass") || !asset.LoginReviewRequired {
				return nil
			}
			if d.AccessReviews == nil {
				return errors.New("login review is unavailable")
			}
			if reviewID != "" {
				prior, err := d.AccessReviews.Get(reviewID)
				if err != nil {
					return operations.ErrDenied
				}
				if prior.UserID != user.ID || prior.AssetID != asset.ID || prior.Account != account || prior.Action != reviewAction || prior.RequestScope != reviewScope {
					return operations.ErrDenied
				}
				switch prior.State {
				case "denied", "expired", "consumed":
					return operations.ErrDenied
				case "pending":
					pendingID = prior.ID
					return errJobLoginPending
				}
			}
			approved, err := d.AccessReviews.ConsumeApprovedScopedAction(user.ID, asset.ID, account, reviewAction, reviewScope)
			if err != nil {
				return err
			}
			if approved {
				return nil
			}
			review, err := d.AccessReviews.RequestScopedAction(user.ID, user.Username, asset.ID, asset.Name, account, reviewAction, reviewScope)
			if err != nil {
				return err
			}
			pendingID = review.ID
			return errJobLoginPending
		}
		job, err := d.Jobs.SubmitWithGate(input, user.ID, user.Username, assetName, account, decision.Action, decision.RuleName, gate)
		if errors.Is(err, errJobLoginPending) {
			return operations.Submission{ReviewID: pendingID}, nil
		}
		return operations.Submission{Job: job}, err
	}
	if d.HostPlugins != nil {
		registerAccountDiscoveryRoutes(mux, d, submitUser, accessMu, jobGuard, jobGuardLocked)
		registerRemoteAccountRoutes(mux, d, submitUser, accessMu, jobGuard, jobGuardLocked)
		d.Jobs.SetPluginExecutor(func(ctx context.Context, j jobs.Job) (sshclient.ExecResult, error) {
			if (j.Plugin.Action == "events" || j.Plugin.Action == "events_collect") && d.AgentEvents != nil {
				src := agentevents.Source{AssetID: j.AssetID, AssetName: j.AssetName, Account: j.Account}
				cursor, e := d.AgentEvents.Cursor(src)
				if e != nil {
					return sshclient.ExecResult{ExitCode: 1}, e
				}
				out, e := d.HostPlugins.ExecuteEvents(ctx, j.AssetID, j.ID, *j.Plugin, cursor, func() error { return jobGuard(j) })
				if e != nil {
					return out, e
				}
				var result hostplugins.Result
				if json.Unmarshal([]byte(out.Stdout), &result) != nil || result.Events == nil {
					return out, hostplugins.ErrIntegrity
				}
				accessMu.RLock()
				defer accessMu.RUnlock()
				if e = jobGuardLocked(j); e != nil {
					return sshclient.ExecResult{ExitCode: 1}, e
				}
				n, e := d.AgentEvents.Import(src, agentevents.Collector{ID: j.OperatorID, Name: j.Operator, JobID: j.ID}, cursor, *result.Events)
				if e != nil {
					return sshclient.ExecResult{ExitCode: 1}, e
				}
				result.Imported = n
				result.MoreEvents = result.Events.More
				result.Events = nil
				raw, _ := json.Marshal(result)
				out.Stdout = string(raw)
				return out, nil
			}
			if j.Plugin.Action == "events" || j.Plugin.Action == "events_collect" {
				return sshclient.ExecResult{ExitCode: 1}, agentevents.ErrClosed
			}
			return d.HostPlugins.Execute(ctx, j.AssetID, j.ID, *j.Plugin, func() error { return jobGuard(j) })
		})
		registerHostPluginRoutes(mux, d, submitUser)
	}
	if d.Operations != nil {
		registerOperationRoutes(mux, d, authorize, accessMu)
		registerAgentEventRoutes(mux, d, authorize, accessMu)
		configureAgentCollection(d, accessMu)
		d.Operations.Start(func(ownerID string, input jobs.Input, reviewID string) (operations.Submission, error) {
			owner, ok := jobOwner(d, ownerID)
			if !ok {
				return operations.Submission{}, operations.ErrDenied
			}
			return submitUser(owner, input, reviewID)
		})
	}
	mux.Handle("POST /api/v1/ops/jobs", protect(func(w http.ResponseWriter, r *http.Request) {
		var input jobs.Input
		if decodeRequestJSON(w, r, &input) != nil {
			writeJobError(w, jobs.ErrInvalid)
			return
		}
		user, _ := PrincipalFromContext(r.Context())
		input.Origin = accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "exec"}
		result, err := submitUser(user, input, "")
		if err != nil {
			writeJobError(w, err)
			return
		}
		if result.ReviewID != "" {
			writeJSON(w, http.StatusAccepted, map[string]any{"review_id": result.ReviewID, "state": "pending"})
			return
		}
		writeJSON(w, http.StatusCreated, result.Job)
	}))
	mux.Handle("GET /api/v1/ops/jobs", protect(func(w http.ResponseWriter, r *http.Request) {
		limit, offset := 50, 0
		var err error
		if v := r.URL.Query().Get("limit"); v != "" {
			limit, err = strconv.Atoi(v)
		}
		if err == nil {
			if v := r.URL.Query().Get("offset"); v != "" {
				offset, err = strconv.Atoi(v)
			}
		}
		if err != nil || limit < 1 || limit > 100 || offset < 0 {
			writeJobError(w, jobs.ErrInvalid)
			return
		}
		user, _ := PrincipalFromContext(r.Context())
		owner := user.ID
		if hasPermission(r, "jobs.view_all") {
			owner = ""
		}
		items, total, err := d.Jobs.List(owner, offset, limit)
		if err != nil {
			writeJobError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"results": items, "total": total})
	}))
	getOwned := func(w http.ResponseWriter, r *http.Request) (jobs.Job, bool) {
		j, err := d.Jobs.Get(r.PathValue("jobID"))
		if err != nil && r.Method == http.MethodGet && d.AgentEvents != nil {
			if receipt, ok := d.AgentEvents.LatestReceipt(r.PathValue("jobID")); ok && len(receipt.Job) > 0 {
				err = json.Unmarshal(receipt.Job, &j)
			}
		}
		if err != nil && r.Method == http.MethodGet && d.AccountDiscovery != nil {
			if receipt, ok := d.AccountDiscovery.LatestCollection(r.PathValue("jobID")); ok && len(receipt.Job) > 0 {
				err = json.Unmarshal(receipt.Job, &j)
			}
		}
		if err != nil {
			writeJobError(w, err)
			return jobs.Job{}, false
		}
		user, _ := PrincipalFromContext(r.Context())
		permission := "jobs.view_all"
		if r.Method == http.MethodDelete {
			permission = "jobs.cancel_all"
		}
		if !hasPermission(r, permission) && j.OperatorID != user.ID {
			writeJobError(w, jobs.ErrNotFound)
			return jobs.Job{}, false
		}
		return j, true
	}
	mux.Handle("GET /api/v1/ops/jobs/{jobID}", protect(func(w http.ResponseWriter, r *http.Request) {
		if j, ok := getOwned(w, r); ok {
			writeJSON(w, http.StatusOK, j)
		}
	}))
	mux.Handle("DELETE /api/v1/ops/jobs/{jobID}", protect(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := getOwned(w, r); !ok {
			return
		}
		if err := d.Jobs.Cancel(r.PathValue("jobID")); err != nil {
			writeJobError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.Handle("POST /api/v1/ops/jobs/{jobID}/review", protectAdminAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Approve *bool `json:"approve"`
		}
		if decodeRequestJSON(w, r, &input) != nil || input.Approve == nil {
			writeJobError(w, jobs.ErrInvalid)
			return
		}
		job, err := d.Jobs.Get(r.PathValue("jobID"))
		if err != nil {
			writeJobError(w, err)
			return
		}
		accessMu.RLock()
		defer accessMu.RUnlock()
		if *input.Approve {
			owner, ok := jobOwner(d, job.OperatorID)
			if !ok {
				writeJSON(w, http.StatusConflict, map[string]string{"detail": "job owner is no longer available"})
				return
			}
			_, account, decision, status := authorize(owner, job.AssetID, job.Command, job.AccessOrigin)
			if status != http.StatusOK || account != job.Account || decision.Action == commandfilters.ActionDeny || !pluginJobAllowed(d, owner, job.AssetID, job.Plugin) || !discoveryJobAllowed(d, owner, job.AssetID, job.Discovery, job.AccessOrigin) || !remoteAccountJobAllowed(d, owner, job.AssetID, job.RemoteAccount, job.AccessOrigin) {
				writeJSON(w, http.StatusForbidden, map[string]string{"detail": "job authorization or command policy changed"})
				return
			}
		}
		reviewer, _ := PrincipalFromContext(r.Context())
		job, err = d.Jobs.Review(job.ID, reviewer.Username, *input.Approve)
		if err != nil {
			writeJobError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, job)
	}), d.AdminToken, d.Auth))
}
func writeJobError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	detail := "job audit or execution service is unavailable"
	switch {
	case errors.Is(err, operations.ErrDenied):
		status = http.StatusForbidden
		detail = "asset execution is not granted or login review was denied"
	case errors.Is(err, jobs.ErrInvalid):
		status = http.StatusBadRequest
		detail = "invalid job input"
	case errors.Is(err, jobs.ErrNotFound):
		status = http.StatusNotFound
		detail = "job not found"
	case errors.Is(err, jobs.ErrConflict):
		status = http.StatusConflict
		detail = "job state or request ID conflicts"
	case errors.Is(err, jobs.ErrBusy):
		status = http.StatusTooManyRequests
		detail = "job capacity reached"
	}
	writeJSON(w, status, map[string]string{"detail": detail})
}
