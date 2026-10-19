package api

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	"github.com/neko233-com/jumpserver233/server/internal/core/assetdiscovery"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
)

func assetDiscoveryError(w http.ResponseWriter, e error) {
	setNoStore(w)
	status := 503
	switch {
	case errors.Is(e, assetdiscovery.ErrInvalid), errors.Is(e, assets.ErrInvalidInput):
		status = 400
	case errors.Is(e, assetdiscovery.ErrNotFound), errors.Is(e, assets.ErrNotFound):
		status = 404
	case errors.Is(e, assetdiscovery.ErrConflict), errors.Is(e, assetdiscovery.ErrPreview), errors.Is(e, assets.ErrCredentialChanged):
		status = 409
	case errors.Is(e, assetdiscovery.ErrDenied), errors.Is(e, accesspolicies.ErrDenied):
		status = 403
	case errors.Is(e, assetdiscovery.ErrCapacity):
		status = 429
	}
	writeJSON(w, status, map[string]string{"error_code": assetdiscovery.ErrorCode(e)})
}
func registerAssetDiscoveryRoutes(mux *http.ServeMux, d Dependencies) {
	if d.AssetDiscovery == nil || d.Assets == nil || d.Auth == nil {
		return
	}
	service := d.AssetDiscovery
	store := service.Store()
	lockRead := func() func() {
		if d.GlobalAccessMu != nil && d.GlobalAccessMu != d.AccessMu {
			d.GlobalAccessMu.RLock()
		}
		d.AccessMu.RLock()
		return func() {
			d.AccessMu.RUnlock()
			if d.GlobalAccessMu != nil && d.GlobalAccessMu != d.AccessMu {
				d.GlobalAccessMu.RUnlock()
			}
		}
	}
	current := func(id, permission string) (coreauth.User, rbac.Snapshot, error) {
		u, ok := jobOwner(d, id)
		if !ok || d.OrganizationAllowed != nil && !d.OrganizationAllowed(u) {
			return u, rbac.Snapshot{}, assetdiscovery.ErrDenied
		}
		p := effectivePermissions(u, d.RBAC, d.Groups)
		if !p.Allows(permission) || !p.Allows("assets.view_all") {
			return u, p, assetdiscovery.ErrDenied
		}
		return u, p, nil
	}
	asActor := func(u coreauth.User) assetdiscovery.Actor { return assetdiscovery.Actor{ID: u.ID, Name: u.Username} }
	requestUser := func(w http.ResponseWriter, r *http.Request, permission string) (coreauth.User, rbac.Snapshot, bool) {
		setNoStore(w)
		principal, ok := PrincipalFromContext(r.Context())
		if !ok {
			assetDiscoveryError(w, assetdiscovery.ErrDenied)
			return principal, rbac.Snapshot{}, false
		}
		u, p, e := current(principal.ID, permission)
		if e != nil {
			assetDiscoveryError(w, e)
			return u, p, false
		}
		if !enforceLoginPolicy(w, r, u) {
			return u, p, false
		}
		return u, p, true
	}
	baseAuthorize := func(ctx context.Context, actor assetdiscovery.Actor, source assetdiscovery.Source, action string) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		permission := "assets.discovery." + action
		u, p, e := current(actor.ID, permission)
		if e != nil {
			return e
		}
		if action == "import" && !p.Allows("assets.manage") {
			return assetdiscovery.ErrDenied
		}
		if source.ID != "" {
			if e = service.ValidateSnapshot(source.ID, source.Revision, "", 0); e != nil {
				return e
			}
		}
		if action == "execute" && source.GatewayID != "" {
			origin := assetdiscovery.Origin(ctx)
			origin.Method = "ssh"
			if _, e := authorizeTerminalAsset(d, u, source.GatewayID, assets.ProtocolSSH, origin, false); e != nil {
				return assetdiscovery.ErrDenied
			}
		}
		if action == "execute" && source.ID != "" {
			dummy := assets.Asset{ID: source.ID, Name: source.Name, Protocol: assets.ProtocolSSH}
			decision, e := checkAccessPolicies(d, u, dummy, assetdiscovery.Origin(ctx), false)
			if e != nil || !decision.Allowed {
				return assetdiscovery.ErrDenied
			}
		}
		return nil
	}
	hooks := assetdiscovery.Hooks{
		Authorize: func(ctx context.Context, actor assetdiscovery.Actor, source assetdiscovery.Source, action string) error {
			release, lockError := lockDiscoveryRuntime(ctx, d, false)
			if lockError != nil {
				return lockError
			}
			defer release()
			return baseAuthorize(ctx, actor, source, action)
		},
		AuthorizeTarget: func(ctx context.Context, actor assetdiscovery.Actor, source assetdiscovery.Source, host string, port int) error {
			release, lockError := lockDiscoveryRuntime(ctx, d, false)
			if lockError != nil {
				return lockError
			}
			defer release()
			if e := baseAuthorize(ctx, actor, source, "execute"); e != nil {
				return e
			}
			u, _, e := current(actor.ID, "assets.discovery.execute")
			if e != nil {
				return e
			}
			for _, a := range d.Assets.DiscoveryExisting(host, port, source.GatewayID) {
				decision, e := checkAccessPolicies(d, u, a, assetdiscovery.Origin(ctx), false)
				if e != nil || !decision.Allowed {
					return assetdiscovery.ErrDenied
				}
			}
			return nil
		},
		Bound: d.Assets.DiscoveryBound,
		ApplyBatch: func(ctx context.Context, actor assetdiscovery.Actor, source assetdiscovery.Source, policy assetdiscovery.Policy, rows []assetdiscovery.ApplyRow) ([]assetdiscovery.ApplyResult, error) {
			release, e := lockDiscoveryRuntime(ctx, d, true)
			if e != nil {
				return nil, e
			}
			defer release()
			if e = baseAuthorize(ctx, actor, source, "import"); e != nil {
				return nil, e
			}
			if policy.AutoImport && policy.TrustNewSSHKeys {
				for _, r := range rows {
					if r.Finding.Protocol == "ssh" {
						if _, bound := d.Assets.DiscoveryBound(source.ID, r.Finding.ID); !bound {
							if e = baseAuthorize(ctx, actor, source, "trust"); e != nil {
								return nil, e
							}
						}
					}
				}
			}
			if e = service.ValidateSnapshot(source.ID, source.Revision, policy.ID, policy.Revision); e != nil {
				return nil, e
			}
			if policy.NodeID != "" {
				if d.Nodes == nil {
					return nil, assetdiscovery.ErrConflict
				}
				if _, e = d.Nodes.Get(policy.NodeID); e != nil {
					return nil, assetdiscovery.ErrConflict
				}
			}
			inputs := make([]assets.DiscoverySyncRow, len(rows))
			for i, r := range rows {
				inputs[i] = assets.DiscoverySyncRow{FindingID: r.Finding.ID, Input: r.Input, Update: policy.UpdateExisting, Missing: r.Missing, Options: assetdiscovery.AssetSyncOptions(source, policy, r.Finding)}
			}
			native, e := d.Assets.SyncDiscoveryBatch(ctx, source.ID, inputs, time.Now().UTC())
			if e != nil {
				return nil, e
			}
			out := make([]assetdiscovery.ApplyResult, len(native))
			for i, r := range native {
				out[i] = assetdiscovery.ApplyResult{AssetID: r.Asset.ID, State: r.State, Err: r.Err}
			}
			return out, nil
		},

		Apply: func(ctx context.Context, actor assetdiscovery.Actor, source assetdiscovery.Source, policy assetdiscovery.Policy, finding assetdiscovery.Finding, in assets.Input, missing bool) (string, string, error) {
			release, lockError := lockDiscoveryRuntime(ctx, d, true)
			if lockError != nil {
				return "", "", lockError
			}
			defer release()
			if e := baseAuthorize(ctx, actor, source, "import"); e != nil {
				return "", "", e
			}
			if e := service.ValidateSnapshot(source.ID, source.Revision, policy.ID, policy.Revision); e != nil {
				return "", "", e
			}
			if policy.NodeID != "" {
				if d.Nodes == nil {
					return "", "", assetdiscovery.ErrConflict
				}
				if _, e := d.Nodes.Get(policy.NodeID); e != nil {
					return "", "", assetdiscovery.ErrConflict
				}
			}
			a, state, e := d.Assets.SyncDiscovery(source.ID, finding.ID, in, policy.UpdateExisting, missing, time.Now().UTC(), assetdiscovery.AssetSyncOptions(source, policy, finding))
			return a.ID, state, e
		},
		Gateway: func(ctx context.Context, actor assetdiscovery.Actor, source assetdiscovery.Source, runID string) (assetdiscovery.Gateway, error) {
			release, lockError := lockDiscoveryRuntime(ctx, d, true)
			if lockError != nil {
				return assetdiscovery.Gateway{}, lockError
			}
			if e := baseAuthorize(ctx, actor, source, "execute"); e != nil {
				release()
				return assetdiscovery.Gateway{}, e
			}
			u, p, e := current(actor.ID, "assets.discovery.execute")
			if e != nil {
				release()
				return assetdiscovery.Gateway{}, e
			}
			open, binding, e := d.Assets.PrepareDiscoveryGateway(source.GatewayID)
			if e != nil {
				release()
				return assetdiscovery.Gateway{}, e
			}
			route, e := d.Assets.DiscoveryGatewayRoute(source.GatewayID)
			if e != nil {
				release()
				return assetdiscovery.Gateway{}, e
			}
			required := []struct {
				asset assets.Asset
				scope string
			}{}
			for _, a := range route {
				origin := assetdiscovery.Origin(ctx)
				origin.Method = "ssh"
				if _, e = authorizeTerminalAsset(d, u, a.ID, assets.ProtocolSSH, origin, false); e != nil {
					release()
					return assetdiscovery.Gateway{}, assetdiscovery.ErrDenied
				}
				if !a.LoginReviewRequired || p.Allows("login_review.bypass") {
					continue
				}
				if d.AccessReviews == nil {
					release()
					return assetdiscovery.Gateway{}, assetdiscovery.ErrDenied
				}
				if binding == "" {
					release()
					return assetdiscovery.Gateway{}, assetdiscovery.ErrDenied
				}
				sum := sha256.Sum256([]byte(runID + "\x00" + a.ID + "\x00" + binding))
				scope := "ad-" + hex.EncodeToString(sum[:])
				review, e := d.AccessReviews.RequestScopedAction(u.ID, u.Username, a.ID, a.Name, a.Username, accessreviews.ActionAssetDiscovery, scope)
				if e != nil {
					release()
					return assetdiscovery.Gateway{}, e
				}
				if review.State != accessreviews.StateApproved {
					release()
					return assetdiscovery.Gateway{}, &assetdiscovery.ReviewRequired{ID: review.ID, State: review.State, ExpiresAt: review.ExpiresAt}
				}
				required = append(required, struct {
					asset assets.Asset
					scope string
				}{a, scope})
			}
			for _, item := range required {
				approved, e := d.AccessReviews.ConsumeApprovedScopedAction(u.ID, item.asset.ID, item.asset.Username, accessreviews.ActionAssetDiscovery, item.scope)
				if e != nil || !approved {
					release()
					return assetdiscovery.Gateway{}, assetdiscovery.ErrDenied
				}
			}
			release()
			dial, close, currentBinding, e := open(ctx)
			if e != nil {
				return assetdiscovery.Gateway{}, e
			}
			return assetdiscovery.Gateway{Dial: dial, Close: close, Current: currentBinding}, nil
		},
	}
	_ = service.Configure(hooks)
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	read := func(permission string, h func(http.ResponseWriter, *http.Request, coreauth.User, rbac.Snapshot)) http.Handler {
		return protect(func(w http.ResponseWriter, r *http.Request) {
			release := lockRead()
			defer release()
			u, p, ok := requestUser(w, r, permission)
			if !ok {
				return
			}
			h(w, r, u, p)
		})
	}
	page := func(r *http.Request) (int, int, error) {
		offset, e1 := strconv.Atoi(defaultQuery(r, "offset", "0"))
		limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "100"))
		if e1 != nil || e2 != nil {
			return 0, 0, assetdiscovery.ErrInvalid
		}
		return offset, limit, nil
	}
	mux.Handle("POST /api/v1/asset-discovery/schedules/preview", read("assets.discovery.manage", func(w http.ResponseWriter, r *http.Request, _ coreauth.User, _ rbac.Snapshot) {
		var in operations.PreviewInput
		if decodeRequestJSONLimit(w, r, &in, 16<<10) != nil {
			assetDiscoveryError(w, assetdiscovery.ErrInvalid)
			return
		}
		result, e := operations.PreviewSchedule(in, time.Now().UTC())
		if e != nil {
			assetDiscoveryError(w, assetdiscovery.ErrInvalid)
			return
		}
		writeJSON(w, 200, result)
	}))
	mux.Handle("GET /api/v1/asset-discovery/sources", read("assets.discovery.view", func(w http.ResponseWriter, r *http.Request, _ coreauth.User, _ rbac.Snapshot) {
		rows, e := store.Sources()
		if e != nil {
			assetDiscoveryError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": len(rows)})
	}))
	mux.Handle("GET /api/v1/asset-discovery/sources/{sourceID}", read("assets.discovery.view", func(w http.ResponseWriter, r *http.Request, _ coreauth.User, _ rbac.Snapshot) {
		row, e := store.Source(r.PathValue("sourceID"))
		if e != nil {
			assetDiscoveryError(w, e)
			return
		}
		writeJSON(w, 200, row)
	}))
	saveSource := func(w http.ResponseWriter, r *http.Request) {
		var in assetdiscovery.SourceInput
		if decodeRequestJSONLimit(w, r, &in, 512<<10) != nil {
			assetDiscoveryError(w, assetdiscovery.ErrInvalid)
			return
		}
		release := lockUserLifecycle(d)
		u, _, ok := requestUser(w, r, "assets.discovery.manage")
		if !ok {
			release()
			return
		}
		if in.GatewayID != "" {
			if _, e := d.Assets.DiscoveryGatewayRoute(in.GatewayID); e != nil {
				release()
				assetDiscoveryError(w, assetdiscovery.ErrInvalid)
				return
			}
		}
		before, _ := store.Source(r.PathValue("sourceID"))
		out, e := store.SaveSource(r.PathValue("sourceID"), in, asActor(u), time.Now().UTC())
		release()
		if e != nil {
			assetDiscoveryError(w, e)
			return
		}
		if before.ID != "" && before.Revision != out.Revision {
			service.CancelSource(out.ID, "scan_configuration_changed")
		}
		status := 200
		if r.Method == "POST" {
			status = 201
		}
		writeJSON(w, status, out)
	}
	mux.Handle("POST /api/v1/asset-discovery/sources", protect(saveSource))
	mux.Handle("PUT /api/v1/asset-discovery/sources/{sourceID}", protect(saveSource))
	mux.Handle("DELETE /api/v1/asset-discovery/sources/{sourceID}", protect(func(w http.ResponseWriter, r *http.Request) {
		revision, e := strconv.Atoi(r.URL.Query().Get("revision"))
		if e != nil {
			assetDiscoveryError(w, assetdiscovery.ErrInvalid)
			return
		}
		release := lockUserLifecycle(d)
		u, _, ok := requestUser(w, r, "assets.discovery.manage")
		if !ok {
			release()
			return
		}
		e = store.DeleteSource(r.PathValue("sourceID"), revision, asActor(u), time.Now().UTC())
		release()
		if e != nil {
			assetDiscoveryError(w, e)
			return
		}
		service.CancelSource(r.PathValue("sourceID"), "scan_configuration_changed")
		w.WriteHeader(204)
	}))
	mux.Handle("GET /api/v1/asset-discovery/policies", read("assets.discovery.view", func(w http.ResponseWriter, r *http.Request, _ coreauth.User, _ rbac.Snapshot) {
		rows, e := store.Policies()
		if e != nil {
			assetDiscoveryError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": len(rows)})
	}))
	mux.Handle("GET /api/v1/asset-discovery/policies/{policyID}", read("assets.discovery.view", func(w http.ResponseWriter, r *http.Request, _ coreauth.User, _ rbac.Snapshot) {
		row, e := store.Policy(r.PathValue("policyID"))
		if e != nil {
			assetDiscoveryError(w, e)
			return
		}
		writeJSON(w, 200, row)
	}))
	savePolicy := func(w http.ResponseWriter, r *http.Request) {
		var in assetdiscovery.PolicyInput
		if decodeRequestJSONLimit(w, r, &in, 128<<10) != nil {
			assetDiscoveryError(w, assetdiscovery.ErrInvalid)
			return
		}
		release := lockUserLifecycle(d)
		u, p, ok := requestUser(w, r, "assets.discovery.manage")
		if !ok {
			release()
			return
		}
		if in.Enabled && (in.AutoImport || in.UpdateExisting || in.MissingAction == "disable") && (!p.Allows("assets.discovery.import") || !p.Allows("assets.manage") || in.TrustNewSSHKeys && !p.Allows("assets.discovery.trust")) {
			release()
			assetDiscoveryError(w, assetdiscovery.ErrDenied)
			return
		}
		if in.Enabled && in.Schedule != nil && !p.Allows("assets.discovery.execute") {
			release()
			assetDiscoveryError(w, assetdiscovery.ErrDenied)
			return
		}
		source, sourceError := store.Source(in.SourceID)
		if sourceError != nil || in.Enabled && in.AutoImport && !source.CredentialConfigured {
			release()
			assetDiscoveryError(w, assetdiscovery.ErrInvalid)
			return
		}
		if in.NodeID != "" {
			if d.Nodes == nil {
				release()
				assetDiscoveryError(w, assetdiscovery.ErrInvalid)
				return
			}
			if _, e := d.Nodes.Get(in.NodeID); e != nil {
				release()
				assetDiscoveryError(w, assetdiscovery.ErrInvalid)
				return
			}
		}
		before, _ := store.Policy(r.PathValue("policyID"))
		out, e := store.SavePolicy(r.PathValue("policyID"), in, asActor(u), time.Now().UTC(), accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "asset_discovery"})
		release()
		if e != nil {
			assetDiscoveryError(w, e)
			return
		}
		if before.ID != "" && before.Revision != out.Revision {
			service.CancelPolicy(out.ID, "scan_configuration_changed")
		}
		status := 200
		if r.Method == "POST" {
			status = 201
		}
		writeJSON(w, status, out)
	}
	mux.Handle("POST /api/v1/asset-discovery/policies", protect(savePolicy))
	mux.Handle("PUT /api/v1/asset-discovery/policies/{policyID}", protect(savePolicy))
	mux.Handle("DELETE /api/v1/asset-discovery/policies/{policyID}", protect(func(w http.ResponseWriter, r *http.Request) {
		revision, e := strconv.Atoi(r.URL.Query().Get("revision"))
		if e != nil {
			assetDiscoveryError(w, assetdiscovery.ErrInvalid)
			return
		}
		release := lockUserLifecycle(d)
		u, _, ok := requestUser(w, r, "assets.discovery.manage")
		if !ok {
			release()
			return
		}
		e = store.DeletePolicy(r.PathValue("policyID"), revision, asActor(u), time.Now().UTC())
		release()
		if e != nil {
			assetDiscoveryError(w, e)
			return
		}
		service.CancelPolicy(r.PathValue("policyID"), "scan_configuration_changed")
		w.WriteHeader(204)
	}))
	mux.Handle("POST /api/v1/asset-discovery/runs", protect(func(w http.ResponseWriter, r *http.Request) {
		var in assetdiscovery.RunInput
		if decodeRequestJSONLimit(w, r, &in, 16<<10) != nil {
			assetDiscoveryError(w, assetdiscovery.ErrInvalid)
			return
		}
		release := lockRead()
		u, _, ok := requestUser(w, r, "assets.discovery.execute")
		release()
		if !ok {
			return
		}
		ctx := assetdiscovery.WithOrigin(r.Context(), accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "asset_discovery"})
		out, e := service.StartRun(ctx, in, asActor(u))
		if e != nil {
			assetDiscoveryError(w, e)
			return
		}
		writeJSON(w, 202, out)
	}))
	mux.Handle("GET /api/v1/asset-discovery/runs", read("assets.discovery.view", func(w http.ResponseWriter, r *http.Request, _ coreauth.User, _ rbac.Snapshot) {
		offset, limit, e := page(r)
		if e != nil {
			assetDiscoveryError(w, e)
			return
		}
		rows, total, e := service.Runs(r.URL.Query().Get("source_id"), offset, limit)
		if e != nil {
			assetDiscoveryError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": total})
	}))
	mux.Handle("GET /api/v1/asset-discovery/runs/{runID}", read("assets.discovery.view", func(w http.ResponseWriter, r *http.Request, _ coreauth.User, _ rbac.Snapshot) {
		row, e := service.Run(r.PathValue("runID"))
		if e != nil {
			assetDiscoveryError(w, e)
			return
		}
		writeJSON(w, 200, row)
	}))
	mux.Handle("POST /api/v1/asset-discovery/runs/{runID}/cancel", protect(func(w http.ResponseWriter, r *http.Request) {
		release := lockRead()
		u, _, ok := requestUser(w, r, "assets.discovery.execute")
		release()
		if !ok {
			return
		}
		out, e := service.Cancel(r.Context(), r.PathValue("runID"), asActor(u))
		if e != nil {
			assetDiscoveryError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("GET /api/v1/asset-discovery/findings", read("assets.discovery.view", func(w http.ResponseWriter, r *http.Request, _ coreauth.User, _ rbac.Snapshot) {
		offset, limit, e := page(r)
		if e != nil {
			assetDiscoveryError(w, e)
			return
		}
		rows, total, e := store.Findings(r.URL.Query().Get("source_id"), offset, limit)
		if e != nil {
			assetDiscoveryError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": total})
	}))
	mux.Handle("POST /api/v1/asset-discovery/import-preview", protect(func(w http.ResponseWriter, r *http.Request) {
		var in assetdiscovery.PreviewInput
		if decodeRequestJSONLimit(w, r, &in, 128<<10) != nil {
			assetDiscoveryError(w, assetdiscovery.ErrInvalid)
			return
		}
		release := lockRead()
		u, p, ok := requestUser(w, r, "assets.discovery.import")
		release()
		if !ok {
			return
		}
		if !p.Allows("assets.manage") {
			assetDiscoveryError(w, assetdiscovery.ErrDenied)
			return
		}
		out, e := service.Preview(r.Context(), in, asActor(u))
		if e != nil {
			assetDiscoveryError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("POST /api/v1/asset-discovery/import", protect(func(w http.ResponseWriter, r *http.Request) {
		var in assetdiscovery.ImportInput
		if decodeRequestJSONLimit(w, r, &in, 16<<10) != nil {
			assetDiscoveryError(w, assetdiscovery.ErrInvalid)
			return
		}
		release := lockRead()
		u, p, ok := requestUser(w, r, "assets.discovery.import")
		release()
		if !ok {
			return
		}
		if !p.Allows("assets.manage") {
			assetDiscoveryError(w, assetdiscovery.ErrDenied)
			return
		}
		out, e := service.Import(r.Context(), in, asActor(u))
		if e != nil {
			assetDiscoveryError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("GET /api/v1/asset-discovery/audit", read("assets.discovery.view", func(w http.ResponseWriter, r *http.Request, _ coreauth.User, _ rbac.Snapshot) {
		offset, limit, e := page(r)
		if e != nil {
			assetDiscoveryError(w, e)
			return
		}
		rows, total, e := store.Audit(offset, limit)
		if e != nil {
			assetDiscoveryError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": total})
	}))
	mux.Handle("GET /api/v1/asset-discovery/findings.csv", read("assets.discovery.export", func(w http.ResponseWriter, r *http.Request, _ coreauth.User, _ rbac.Snapshot) {
		rows := []assetdiscovery.Finding{}
		for offset := 0; ; offset += 500 {
			page, total, e := store.Findings(r.URL.Query().Get("source_id"), offset, 500)
			if e != nil {
				assetDiscoveryError(w, e)
				return
			}
			rows = append(rows, page...)
			if len(rows) >= total {
				break
			}
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="asset-discovery.csv"`)
		writer := csv.NewWriter(w)
		defer writer.Flush()
		_ = writer.Write([]string{"source_id", "host", "port", "protocol", "open", "ssh_verified", "host_key_fingerprint", "last_seen", "asset_id", "sync_state", "error_code", "cloud_provider", "cloud_account", "cloud_region", "cloud_instance_id"})
		for _, f := range rows {
			cloud := []string{"", "", "", ""}
			if f.Cloud != nil {
				cloud = []string{f.Cloud.Provider, f.Cloud.AccountID, f.Cloud.Region, f.Cloud.ID}
			}
			_ = writer.Write(append([]string{f.SourceID, f.Host, strconv.Itoa(f.Port), f.Protocol, strconv.FormatBool(f.Open), strconv.FormatBool(f.SSHVerified), f.HostKeyFingerprint, f.LastSeen.Format(time.RFC3339), f.AssetID, f.SyncState, strings.TrimSpace(f.SyncError)}, cloud...))
		}
	}))
}
