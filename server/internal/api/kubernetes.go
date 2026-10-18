package api

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/kubeclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	"github.com/neko233-com/jumpserver233/server/internal/core/databasequery"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
)

func authorizeKubernetes(d Dependencies, u coreauth.User, id string, origin accesspolicies.Origin, audit bool) (assets.Asset, error) {
	return authorizeTerminalAsset(d, u, id, assets.ProtocolKubernetes, origin, audit)
}
func authorizeTerminalAsset(d Dependencies, u coreauth.User, id, protocol string, origin accesspolicies.Origin, audit bool) (assets.Asset, error) {
	a, e := d.Assets.Get(id)
	if e != nil {
		return a, assets.ErrNotFound
	}
	if assets.Protocol(a) != protocol || protocol == assets.ProtocolKubernetes && a.Kubernetes == nil || protocol == assets.ProtocolTelnet && a.Telnet == nil || protocol == assets.ProtocolRDP && a.RDP == nil {
		return a, assets.ErrUnsupportedProtocol
	}
	var groups, nodes []string
	if d.Groups != nil {
		groups = d.Groups.GroupIDsForUser(u.ID)
	}
	if d.Nodes != nil {
		nodes = d.Nodes.AncestorIDs(a.NodeID)
	}
	if !effectivePermissions(u, d.RBAC, d.Groups).Allows("assets.connect_all") && (d.Grants == nil || !d.Grants.AllowsForScopes(u.ID, groups, assets.ResourceID(a), nodes, a.Username, "connect", time.Now().UTC())) {
		return a, accesspolicies.ErrDenied
	}
	for current, hops := a, 0; ; hops++ {
		decision, e := checkAccessPolicies(d, u, current, origin, audit)
		if e != nil || !decision.Allowed {
			return a, accesspolicies.ErrDenied
		}
		if current.GatewayID == "" {
			break
		}
		if hops >= 3 {
			return a, accesspolicies.ErrDenied
		}
		current, e = d.Assets.Get(current.GatewayID)
		if e != nil || !assets.IsSSH(current) {
			return a, accesspolicies.ErrDenied
		}
	}
	return a, nil
}
func kubeBinding(d Dependencies, a assets.Asset) string {
	return databasequery.Binding(struct {
		Route    string
		Settings *kubeclient.Settings
	}{databaseRouteBinding(d, a), a.Kubernetes})
}
func registerKubernetesRoutes(mux *http.ServeMux, d Dependencies, accessMu *sync.RWMutex) {
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	writeError := func(w http.ResponseWriter, e error) {
		switch {
		case errors.Is(e, assets.ErrNotFound):
			writeJSON(w, 404, map[string]string{"detail": "asset not found"})
		case errors.Is(e, assets.ErrUnsupportedProtocol), errors.Is(e, kubeclient.ErrInvalid):
			writeJSON(w, 400, map[string]string{"detail": "invalid Kubernetes target"})
		case errors.Is(e, kubeclient.ErrScope), errors.Is(e, accesspolicies.ErrDenied):
			writeJSON(w, 403, map[string]string{"detail": "Kubernetes access is not granted"})
		default:
			writeJSON(w, 502, map[string]string{"detail": "could not access Kubernetes"})
		}
	}
	mux.Handle("GET /api/v1/assets/{assetID}/kubernetes/pods", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		u, _ := PrincipalFromContext(r.Context())
		origin := accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "kubernetes"}
		accessMu.RLock()
		a, e := authorizeKubernetes(d, u, r.PathValue("assetID"), origin, false)
		binding := kubeBinding(d, a)
		accessMu.RUnlock()
		if e != nil {
			writeError(w, e)
			return
		}
		namespace := r.URL.Query().Get("namespace")
		if namespace == "" {
			namespace = a.Kubernetes.Namespaces[0]
		}
		pods, e := d.Assets.KubernetesPods(r.Context(), a.ID, namespace)
		if e != nil {
			writeError(w, e)
			return
		}
		accessMu.RLock()
		current, e := authorizeKubernetes(d, u, a.ID, origin, false)
		valid := e == nil && kubeBinding(d, current) == binding
		accessMu.RUnlock()
		if !valid {
			writeError(w, accesspolicies.ErrDenied)
			return
		}
		writeJSON(w, 200, map[string]any{"namespaces": a.Kubernetes.Namespaces, "namespace": namespace, "pods": pods})
	}))
	mux.Handle("POST /api/v1/assets/{assetID}/kubernetes/sessions", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		var input struct {
			kubeclient.Selection
			Cols int `json:"cols"`
			Rows int `json:"rows"`
		}
		if decodeRequestJSON(w, r, &input) != nil || input.Cols < 2 || input.Cols > 500 || input.Rows < 2 || input.Rows > 500 {
			writeError(w, kubeclient.ErrInvalid)
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		origin := accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "kubernetes"}
		accessMu.RLock()
		a, e := authorizeKubernetes(d, u, r.PathValue("assetID"), origin, true)
		binding := kubeBinding(d, a)
		accessMu.RUnlock()
		if e != nil {
			writeError(w, e)
			return
		}
		if e = kubeclient.ValidateSelection(*a.Kubernetes, input.Selection); e != nil {
			writeError(w, e)
			return
		}
		if a.LoginReviewRequired && !effectivePermissions(u, d.RBAC, d.Groups).Allows("login_review.bypass") {
			if d.AccessReviews == nil {
				writeJSON(w, 503, map[string]string{"detail": "login review unavailable"})
				return
			}
			approved, e := d.AccessReviews.ConsumeApprovedAction(u.ID, a.ID, a.Username, accessreviews.ActionKubernetes)
			if e != nil {
				writeError(w, e)
				return
			}
			if !approved {
				review, e := d.AccessReviews.RequestAction(u.ID, u.Username, a.ID, a.Name, a.Username, accessreviews.ActionKubernetes)
				if e != nil {
					writeError(w, e)
					return
				}
				writeJSON(w, 202, map[string]any{"review_id": review.ID, "state": review.State, "expires_at": review.ExpiresAt})
				return
			}
		}
		guard := func(ctx context.Context) error {
			currentOrigin := origin
			currentOrigin.SourceIP = accesspolicies.SourceIP(ctx)
			currentUser, ok := jobOwnerSnapshot(d, u)
			if !ok {
				return accesspolicies.ErrDenied
			}
			accessMu.RLock()
			defer accessMu.RUnlock()
			current, e := authorizeKubernetes(d, currentUser, a.ID, currentOrigin, false)
			if e != nil || kubeBinding(d, current) != binding {
				return accesspolicies.ErrDenied
			}
			return nil
		}
		request := gateway.CreateRequest{AssetID: a.ID, Cols: input.Cols, Rows: input.Rows, OperatorID: u.ID, Operator: u.Username, AccessPolicy: guard}
		if d.CommandFilters != nil {
			request.CommandPolicy = func(command string, supported bool, at time.Time) gateway.CommandPolicyDecision {
				current, _ := d.Assets.Get(a.ID)
				var groups, nodes []string
				if d.Groups != nil {
					groups = d.Groups.GroupIDsForUser(u.ID)
				}
				if d.Nodes != nil {
					nodes = d.Nodes.AncestorIDs(current.NodeID)
				}
				decision := d.CommandFilters.Decide(commandfilters.Scope{UserID: u.ID, GroupIDs: groups, AssetID: assets.ResourceID(a), NodeIDs: nodes, Account: a.Username}, command, supported, at)
				return gateway.CommandPolicyDecision{Allowed: decision.Allowed, RequireReview: decision.Action == commandfilters.ActionReview, RuleName: decision.RuleName}
			}
		}
		request.Open = func(ctx context.Context, id string, cols, rows int) (gateway.AssetInfo, gateway.Terminal, error) {
			if e := guard(ctx); e != nil {
				return gateway.AssetInfo{}, nil, e
			}
			asset, shell, e := d.Assets.OpenKubernetesShell(ctx, id, input.Selection, cols, rows)
			if e != nil {
				return gateway.AssetInfo{}, nil, e
			}
			if e = guard(ctx); e != nil {
				shell.Close()
				return gateway.AssetInfo{}, nil, e
			}
			v := shell.Selection
			return gateway.AssetInfo{ID: asset.ID, Name: asset.Name, Host: asset.Host, Port: asset.Port, Username: asset.Username, GatewayIDs: asset.GatewayIDs, Protocol: assets.ProtocolKubernetes, Kubernetes: &gateway.KubernetesSession{Namespace: v.Namespace, Pod: v.Pod, Container: v.Container, PodUID: shell.PodUID}}, shell, nil
		}
		session, e := d.Sessions.Create(r.Context(), request)
		if e != nil {
			writeError(w, e)
			return
		}
		if d.OrganizationID != "" {
			session.WebSocketURL += "?org=" + d.OrganizationID
		}
		writeJSON(w, 201, session)
	}))
}
