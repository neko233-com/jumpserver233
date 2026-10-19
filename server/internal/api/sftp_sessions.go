package api

import (
	"net/http"
	"time"

	coreaccessreviews "github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	corefiles "github.com/neko233-com/jumpserver233/server/internal/core/files"
	coregrants "github.com/neko233-com/jumpserver233/server/internal/core/grants"
	coregroups "github.com/neko233-com/jumpserver233/server/internal/core/groups"
	corenodes "github.com/neko233-com/jumpserver233/server/internal/core/nodes"
)

const sftpAccessSessionHeader = "X-JMS-SFTP-Session"

func registerSFTPAccessSessionRoutes(mux *http.ServeMux, assets *coreassets.Service, identities *coreauth.Service, grants *coregrants.Store, adminToken string, groups *coregroups.Store, nodes *corenodes.Store, reviews *coreaccessreviews.Store, sessions *corefiles.AccessSessionStore, accessMu interface {
	RLock()
	RUnlock()
}) {
	authenticated := func(handler http.HandlerFunc) http.Handler {
		return protectAuthenticatedAPI(handler, adminToken, identities)
	}

	mux.Handle("POST /api/v1/assets/{assetID}/files/session", authenticated(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := PrincipalFromContext(r.Context())
		asset, allowed, err := resolveSFTPAccess(r, r.PathValue("assetID"), assets, grants, groups, nodes, accessMu)
		if err != nil {
			writeFileError(w, err)
			return
		}
		if !allowed {
			writeJSON(w, http.StatusForbidden, map[string]string{"detail": "sftp access is not granted"})
			return
		}
		if !enforceAssetPolicy(w, r, principal, asset, "sftp") {
			return
		}
		if hasPermission(r, "login_review.bypass") || !asset.LoginReviewRequired {
			setNoStore(w)
			writeJSON(w, http.StatusOK, map[string]any{"required": false})
			return
		}
		if reviews == nil || sessions == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"detail": "SFTP login review is unavailable"})
			return
		}

		binding, err := assets.BindConnection(asset)
		if err != nil {
			writeFileError(w, err)
			return
		}
		ctx := coreassets.WithConnectionBinding(r.Context(), binding)
		identity, err := assets.WorkspaceIdentity(ctx, asset.ID)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"detail": "could not verify SFTP workspace"})
			return
		}
		scope, err := coreaccessreviews.ConnectionScope(binding, asset.SSHWorkspace, identity)
		if err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"detail": "SFTP connection authorization changed"})
			return
		}
		approved, err := reviews.ConsumeApprovedScopedAction(principal.ID, asset.ID, asset.Username, coreaccessreviews.ActionSFTP, scope)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "could not consume SFTP approval"})
			return
		}
		if approved {
			token, expiresAt, err := sessions.IssueBound(principal.ID, asset.ID, asset.Username, binding, identity)
			if err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"detail": "could not create SFTP access session"})
				return
			}
			setNoStore(w)
			writeJSON(w, http.StatusCreated, map[string]any{
				"required": true, "session_token": token, "expires_at": expiresAt,
			})
			return
		}

		review, err := reviews.RequestScopedAction(principal.ID, principal.Username, asset.ID, asset.Name, asset.Username, coreaccessreviews.ActionSFTP, scope)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "could not request SFTP login review"})
			return
		}
		setNoStore(w)
		writeJSON(w, http.StatusAccepted, map[string]any{
			"required": true, "review_id": review.ID, "state": review.State, "action": review.Action, "expires_at": review.ExpiresAt,
		})
	}))

	mux.Handle("DELETE /api/v1/assets/{assetID}/files/session", authenticated(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := PrincipalFromContext(r.Context())
		if sessions != nil {
			if asset, err := assets.Get(r.PathValue("assetID")); err == nil {
				sessions.Revoke(r.Header.Get(sftpAccessSessionHeader), principal.ID, asset.ID, asset.Username)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
}

func resolveSFTPAccess(r *http.Request, assetID string, assets *coreassets.Service, grants *coregrants.Store, groups *coregroups.Store, nodes *corenodes.Store, accessMu interface {
	RLock()
	RUnlock()
}) (coreassets.Asset, bool, error) {
	accessMu.RLock()
	defer accessMu.RUnlock()
	asset, err := assets.Get(assetID)
	if err != nil {
		return coreassets.Asset{}, false, err
	}
	principal, _ := PrincipalFromContext(r.Context())
	if hasPermission(r, "assets.sftp_all") {
		return asset, true, nil
	}
	var groupIDs []string
	if groups != nil {
		groupIDs = groups.GroupIDsForUser(principal.ID)
	}
	var nodeIDs []string
	if nodes != nil {
		nodeIDs = nodes.AncestorIDs(asset.NodeID)
	}
	allowed := grants != nil && grants.AllowsForScopes(principal.ID, groupIDs, coreassets.ResourceID(asset), nodeIDs, asset.Username, "sftp", time.Now().UTC())
	return asset, allowed, nil
}
