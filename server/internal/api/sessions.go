package api

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	coreaccessreviews "github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	corecommandfilters "github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	coregrants "github.com/neko233-com/jumpserver233/server/internal/core/grants"
	coregroups "github.com/neko233-com/jumpserver233/server/internal/core/groups"
	corenodes "github.com/neko233-com/jumpserver233/server/internal/core/nodes"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
)

func registerSessionRoutes(mux *http.ServeMux, broker *gateway.Broker, adminToken string, identities *coreauth.Service, assets *coreassets.Service, grants *coregrants.Store, commandFilters *corecommandfilters.Store, groups *coregroups.Store, nodes *corenodes.Store, accessReviews *coreaccessreviews.Store, accessMu *sync.RWMutex) {
	registerSessionMonitorRoutes(mux, broker, adminToken, identities)
	mux.Handle("POST /api/v1/sessions", protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request gateway.CreateRequest
		if err := decodeRequestJSON(w, r, &request); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid session payload"})
			return
		}
		if principal, ok := PrincipalFromContext(r.Context()); ok {
			request.OperatorID = principal.ID
			request.Operator = principal.Username
			if assets == nil {
				if !hasPermission(r, "assets.connect_all") {
					writeJSON(w, http.StatusForbidden, map[string]string{"detail": "asset access is not granted"})
					return
				}
			} else {
				accessMu.RLock()
				asset, err := assets.Get(request.AssetID)
				if err != nil {
					accessMu.RUnlock()
					writeAssetError(w, err)
					return
				}
				if !coreassets.IsSSH(asset) {
					accessMu.RUnlock()
					writeAssetError(w, coreassets.ErrUnsupportedProtocol)
					return
				}
				var groupIDs []string
				if groups != nil {
					groupIDs = groups.GroupIDsForUser(principal.ID)
				}
				var nodeIDs []string
				if nodes != nil {
					nodeIDs = nodes.AncestorIDs(asset.NodeID)
				}
				if commandFilters != nil {
					request.CommandPolicy = func(command string, supported bool, at time.Time) gateway.CommandPolicyDecision {
						current, e := assets.Get(asset.ID)
						if e != nil {
							return gateway.CommandPolicyDecision{}
						}
						var currentGroups, currentNodes []string
						if groups != nil {
							currentGroups = groups.GroupIDsForUser(principal.ID)
						}
						if nodes != nil {
							currentNodes = nodes.AncestorIDs(current.NodeID)
						}
						scope := corecommandfilters.Scope{UserID: principal.ID, GroupIDs: currentGroups, AssetID: current.ID, NodeIDs: currentNodes, Account: current.Username}
						decision := commandFilters.Decide(scope, command, supported, at)
						return gateway.CommandPolicyDecision{Allowed: decision.Allowed, RequireReview: decision.Action == corecommandfilters.ActionReview, RuleName: decision.RuleName}
					}
				}
				if !hasPermission(r, "assets.connect_all") {
					if grants == nil {
						accessMu.RUnlock()
						writeJSON(w, http.StatusForbidden, map[string]string{"detail": "asset access is not granted"})
						return
					}
					allowed := grants.AllowsForScopes(principal.ID, groupIDs, asset.ID, nodeIDs, asset.Username, "connect", time.Now().UTC())
					if !allowed {
						accessMu.RUnlock()
						writeJSON(w, http.StatusForbidden, map[string]string{"detail": "asset access is not granted"})
						return
					}
				}
				requireReview := !hasPermission(r, "login_review.bypass") && asset.LoginReviewRequired
				accessMu.RUnlock()
				if !enforceAssetPolicy(w, r, principal, asset, "ssh") {
					return
				}
				d := policyDependencies(r)
				binding := databaseRouteBinding(d, asset)
				request.AccessPolicy = func(ctx context.Context) error {
					currentUser := principal
					if identities != nil && principal.ID != "admin-token" && principal.ID != "loopback-admin" {
						var ok bool
						currentUser, ok = identities.ActiveUserByID(principal.ID)
						if !ok {
							return accesspolicies.ErrDenied
						}
					}
					accessMu.RLock()
					defer accessMu.RUnlock()
					current, e := authorizeTerminalAsset(d, currentUser, asset.ID, coreassets.ProtocolSSH, accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(ctx), Method: "ssh"}, false)
					if e != nil || binding == "" || databaseRouteBinding(d, current) != binding {
						return accesspolicies.ErrDenied
					}
					return nil
				}
				if requireReview {
					if accessReviews == nil {
						writeJSON(w, http.StatusServiceUnavailable, map[string]string{"detail": "login review is unavailable"})
						return
					}
					approved, err := accessReviews.ConsumeApproved(principal.ID, asset.ID, asset.Username)
					if err != nil {
						writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "could not validate login review"})
						return
					}
					if !approved {
						review, err := accessReviews.Request(principal.ID, principal.Username, asset.ID, asset.Name, asset.Username)
						if err != nil {
							writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "could not create login review"})
							return
						}
						setNoStore(w)
						writeJSON(w, http.StatusAccepted, map[string]any{"review_id": review.ID, "state": review.State, "expires_at": review.ExpiresAt})
						return
					}
				}
			}
		}
		session, err := broker.Create(r.Context(), request)
		if err != nil {
			switch {
			case errors.Is(err, gateway.ErrSessionAccessDenied):
				writeJSON(w, http.StatusForbidden, map[string]string{"detail": "terminal access denied"})
			case errors.Is(err, gateway.ErrInvalidSessionRequest):
				writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid session request"})
			case errors.Is(err, coreassets.ErrNotFound):
				writeJSON(w, http.StatusNotFound, map[string]string{"detail": "asset not found"})
			default:
				writeJSON(w, http.StatusBadGateway, map[string]string{"detail": "could not open SSH session"})
			}
			return
		}
		if d := policyDependencies(r); d.OrganizationID != "" {
			session.WebSocketURL += "?org=" + d.OrganizationID
		}
		writeJSON(w, http.StatusCreated, session)
	}), adminToken, identities))
	mux.Handle("DELETE /api/v1/sessions/{sessionID}", protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := PrincipalFromContext(r.Context())
		var err error
		if hasPermission(r, "audit.sessions.terminate_all") {
			err = broker.Close(r.PathValue("sessionID"))
		} else {
			err = broker.CloseForOperator(r.PathValue("sessionID"), principal.ID)
		}
		if err != nil {
			if errors.Is(err, gateway.ErrSessionNotFound) {
				writeJSON(w, http.StatusNotFound, map[string]string{"detail": "session not found"})
			} else {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "could not stop session"})
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}), adminToken, identities))
	mux.Handle("GET /api/v1/sessions", protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit, offset := 50, 0
		var err error
		if value := r.URL.Query().Get("limit"); value != "" {
			limit, err = strconv.Atoi(value)
		}
		if err == nil {
			if value := r.URL.Query().Get("offset"); value != "" {
				offset, err = strconv.Atoi(value)
			}
		}
		if err != nil || limit < 1 || limit > 200 || offset < 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid session pagination"})
			return
		}
		principal, _ := PrincipalFromContext(r.Context())
		var results []gateway.SessionRecord
		var total, activeTotal int
		if hasPermission(r, "audit.sessions.view_all") || hasPermission(r, "audit.sessions.monitor_all") {
			results, total, activeTotal, err = broker.ListSessions(offset, limit)
		} else {
			results, total, activeTotal, err = broker.ListSessionsForOperator(principal.ID, offset, limit)
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "could not read session index"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"results": results, "total": total, "active_total": activeTotal, "limit": limit, "offset": offset})
	}), adminToken, identities))
	mux.Handle("GET /api/v1/sessions/{sessionID}/commands", protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit, offset := 50, 0
		var err error
		if value := r.URL.Query().Get("limit"); value != "" {
			limit, err = strconv.Atoi(value)
		}
		if err == nil {
			if value := r.URL.Query().Get("offset"); value != "" {
				offset, err = strconv.Atoi(value)
			}
		}
		if err != nil || limit < 1 || limit > 200 || offset < 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid command audit pagination"})
			return
		}
		principal, _ := PrincipalFromContext(r.Context())
		var results []gateway.CommandRecord
		var total int
		if hasPermission(r, "audit.commands.view_all") {
			results, total, err = broker.ListCommands(r.PathValue("sessionID"), offset, limit)
		} else {
			results, total, err = broker.ListCommandsForOperator(r.PathValue("sessionID"), principal.ID, offset, limit)
		}
		if err != nil {
			if errors.Is(err, gateway.ErrSessionNotFound) {
				writeJSON(w, http.StatusNotFound, map[string]string{"detail": "session not found"})
				return
			}
			if errors.Is(err, gateway.ErrInvalidCommandRequest) {
				writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid command audit request"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "could not read command audit"})
			return
		}
		setNoStore(w)
		writeJSON(w, http.StatusOK, map[string]any{"results": results, "total": total, "limit": limit, "offset": offset})
	}), adminToken, identities))
	mux.Handle("GET /api/v1/sessions/{sessionID}/replay", protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := PrincipalFromContext(r.Context())
		var replay io.ReadCloser
		var err error
		if hasPermission(r, "audit.replays.view_all") {
			replay, err = broker.OpenReplay(r.PathValue("sessionID"))
		} else {
			replay, err = broker.OpenReplayForOperator(r.PathValue("sessionID"), principal.ID)
		}
		if err != nil {
			switch {
			case errors.Is(err, gateway.ErrSessionNotFound), errors.Is(err, gateway.ErrReplayUnavailable):
				writeJSON(w, http.StatusNotFound, map[string]string{"detail": "session replay not found"})
			default:
				writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "could not open session replay"})
			}
			return
		}
		defer replay.Close()
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Disposition", "inline; filename=\"session-replay.json.gz\"")
		w.Header().Set("Cache-Control", "private, no-store")
		w.WriteHeader(http.StatusOK)
		compressed := gzip.NewWriter(w)
		_, _ = io.Copy(compressed, replay)
		_ = compressed.Close()
	}), adminToken, identities))
	mux.HandleFunc("GET /ws/api/v1/sessions/{sessionID}/terminal", broker.ServeTerminal)
}
