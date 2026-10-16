package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	coregrants "github.com/neko233-com/jumpserver233/server/internal/core/grants"
	coregroups "github.com/neko233-com/jumpserver233/server/internal/core/groups"
	corenodes "github.com/neko233-com/jumpserver233/server/internal/core/nodes"
)

func registerAssetRoutes(mux *http.ServeMux, service *coreassets.Service, adminToken string, identities *coreauth.Service, grants *coregrants.Store, groups *coregroups.Store, nodes *corenodes.Store, accessMu *sync.RWMutex) {
	protect := func(handler http.HandlerFunc) http.Handler {
		return protectAdminAPI(handler, adminToken, identities)
	}
	mux.Handle("GET /api/v1/assets", protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := PrincipalFromContext(r.Context())
		accessMu.RLock()
		defer accessMu.RUnlock()
		items := service.List()
		visible := items[:0]
		permissionsSnapshot := permissionsForRequest(r, principal)
		var groupIDs []string
		if groups != nil {
			groupIDs = groups.GroupIDsForUser(principal.ID)
		}
		for _, item := range items {
			var permissions []string
			if grants != nil {
				var nodeIDs []string
				if nodes != nil {
					nodeIDs = nodes.AncestorIDs(item.NodeID)
				}
				permissions = grants.ActionsForScopes(principal.ID, groupIDs, item.ID, nodeIDs, item.Username, time.Now().UTC())
			}
			for action, permission := range map[string]string{"view": "assets.view_all", "manage": "assets.manage", "connect": "assets.connect_all", "sftp": "assets.sftp_all", "probe": "assets.probe", "rotate": "assets.rotate", "backups": "assets.backups"} {
				if permissionsSnapshot.Allows(permission) {
					if !hasAction(permissions, action) {
						permissions = append(permissions, action)
					}
					if (action == "manage" || action == "connect" || action == "sftp") && !hasAction(permissions, "view") {
						permissions = append(permissions, "view")
					}
				}
			}
			if !hasAction(permissions, "view") {
				continue
			}
			item.Permissions = permissions
			sort.Strings(item.Permissions)
			if !permissionsSnapshot.Allows("assets.manage") && !permissionsSnapshot.Allows("assets.rotate") && !permissionsSnapshot.Allows("assets.backups") {
				item.PasswordRotation = nil
				item.SSHKeyRotation = nil
				item.PasswordRotatedAt = time.Time{}
			}
			visible = append(visible, item)
		}
		items = visible
		setNoStore(w)
		writeJSON(w, http.StatusOK, items)
	}), adminToken, identities))
	mux.Handle("POST /api/v1/assets", protect(func(w http.ResponseWriter, r *http.Request) {
		accessMu.Lock()
		defer accessMu.Unlock()
		var input coreassets.Input
		if err := decodeRequestJSON(w, r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid asset payload"})
			return
		}
		if !validAssetNode(nodes, input.NodeID) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "asset node does not exist"})
			return
		}
		if input.KeyRotationEnabled != nil && *input.KeyRotationEnabled && !hasPermission(r, "assets.rotate") {
			writeJSON(w, http.StatusForbidden, map[string]string{"detail": "SSH key rotation permission required"})
			return
		}
		asset, err := service.Create(input)
		if err != nil {
			writeAssetError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, coreassets.ListItem{Asset: asset, Monitor: coreassets.MonitorStatus{State: "unknown"}})
	}))
	mux.Handle("PUT /api/v1/assets/{assetID}", protect(func(w http.ResponseWriter, r *http.Request) {
		accessMu.Lock()
		defer accessMu.Unlock()
		var input coreassets.Input
		if err := decodeRequestJSON(w, r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid asset payload"})
			return
		}
		if !validAssetNode(nodes, input.NodeID) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "asset node does not exist"})
			return
		}
		if input.KeyRotationEnabled != nil && !hasPermission(r, "assets.rotate") {
			current, e := service.Get(r.PathValue("assetID"))
			if e != nil {
				writeAssetError(w, e)
				return
			}
			if current.KeyRotationEnabled != *input.KeyRotationEnabled {
				writeJSON(w, http.StatusForbidden, map[string]string{"detail": "SSH key rotation permission required"})
				return
			}
		}
		asset, err := service.Update(r.PathValue("assetID"), input)
		if err != nil {
			writeAssetError(w, err)
			return
		}
		for _, item := range service.List() {
			if item.ID == asset.ID {
				writeJSON(w, http.StatusOK, item)
				return
			}
		}
		writeJSON(w, http.StatusOK, coreassets.ListItem{Asset: asset, Monitor: coreassets.MonitorStatus{State: "unknown"}})
	}))
	mux.Handle("DELETE /api/v1/assets/{assetID}", protect(func(w http.ResponseWriter, r *http.Request) {
		accessMu.Lock()
		defer accessMu.Unlock()
		if err := service.Delete(r.PathValue("assetID")); err != nil {
			writeAssetError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.Handle("POST /api/v1/assets/{assetID}/probe", protect(func(w http.ResponseWriter, r *http.Request) {
		item, err := service.Probe(r.Context(), r.PathValue("assetID"))
		if err != nil && errors.Is(err, coreassets.ErrNotFound) {
			writeAssetError(w, err)
			return
		}
		if item.ID == "" {
			writeAssetError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, item)
	}))
	mux.Handle("POST /api/v1/assets/{assetID}/password-rotation", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		item, err := service.RotatePassword(r.Context(), r.PathValue("assetID"))
		if err != nil {
			writeAssetError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, item)
	}))
	mux.Handle("POST /api/v1/assets/{assetID}/ssh-key-rotation", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		var input struct {
			RequestID        string `json:"request_id"`
			ExpectedRevision uint64 `json:"expected_revision"`
		}
		if decodeRequestJSON(w, r, &input) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid SSH key request"})
			return
		}
		principal, _ := PrincipalFromContext(r.Context())
		actor := principal.ID
		if actor == "" {
			actor = "bootstrap-admin"
		}
		item, e := service.RotateSSHKey(r.Context(), r.PathValue("assetID"), input.RequestID, input.ExpectedRevision, actor)
		if e != nil {
			writeAssetError(w, e)
			return
		}
		writeJSON(w, http.StatusOK, item)
	}))
	mux.Handle("POST /api/v1/assets/{assetID}/ssh-key-rotation/cancel", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		var input struct {
			OperationID string `json:"operation_id"`
		}
		if decodeRequestJSON(w, r, &input) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid SSH key request"})
			return
		}
		principal, _ := PrincipalFromContext(r.Context())
		actor := principal.ID
		if actor == "" {
			actor = "bootstrap-admin"
		}
		item, e := service.CancelSSHKeyChange(r.Context(), r.PathValue("assetID"), input.OperationID, actor)
		if e != nil {
			writeAssetError(w, e)
			return
		}
		writeJSON(w, http.StatusOK, item)
	}))
	mux.Handle("GET /api/v1/assets/{assetID}/credential-backups", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		backups, err := service.ListCredentialBackups(r.PathValue("assetID"))
		if err != nil {
			writeAssetError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, backups)
	}))
	mux.Handle("POST /api/v1/assets/{assetID}/credential-backups", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		principal, _ := PrincipalFromContext(r.Context())
		backup, err := service.CreateCredentialBackup(r.PathValue("assetID"), principal.Username)
		if err != nil {
			writeAssetError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, backup)
	}))
	mux.Handle("DELETE /api/v1/assets/{assetID}/credential-backups/{backupID}", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		principal, _ := PrincipalFromContext(r.Context())
		if err := service.DeleteCredentialBackup(r.PathValue("assetID"), r.PathValue("backupID"), principal.Username); err != nil {
			writeAssetError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.Handle("POST /api/v1/assets/{assetID}/credential-backups/{backupID}/restore", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		principal, _ := PrincipalFromContext(r.Context())
		item, err := service.RestoreCredentialBackup(r.Context(), r.PathValue("assetID"), r.PathValue("backupID"), principal.Username)
		if err != nil {
			writeAssetError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, item)
	}))
}

func validAssetNode(nodes *corenodes.Store, nodeID string) bool {
	if nodeID == "" {
		return true
	}
	if nodes == nil {
		return false
	}
	_, err := nodes.Get(nodeID)
	return err == nil
}

func hasAction(actions []string, expected string) bool {
	for _, action := range actions {
		if action == expected {
			return true
		}
	}
	return false
}

func decodeRequestJSON(w http.ResponseWriter, r *http.Request, input any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(input); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("asset payload must contain one JSON object")
	}
	return nil
}

func writeAssetError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, coreassets.ErrUnsupportedProtocol):
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "asset_protocol_not_supported"})
	case errors.Is(err, coreassets.ErrSharedCredentialConflict):
		writeJSON(w, http.StatusConflict, map[string]string{"detail": "shared_credential_conflict"})
	case errors.Is(err, coreassets.ErrSSHKeyPending), errors.Is(err, coreassets.ErrSSHKeyCommitted), errors.Is(err, coreassets.ErrSSHKeyCancelled):
		writeJSON(w, http.StatusConflict, map[string]string{"detail": "ssh_key_change_conflict"})
	case errors.Is(err, coreassets.ErrSSHKeyRotationFailed):
		writeJSON(w, http.StatusBadGateway, map[string]string{"detail": "ssh_key_rotation_failed"})
	case errors.Is(err, coreassets.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "asset not found"})
	case errors.Is(err, coreassets.ErrCredentialBackupNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "credential_backup_not_found"})
	case errors.Is(err, coreassets.ErrCredentialType):
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "credential_type_not_supported"})
	case errors.Is(err, coreassets.ErrCredentialChanged):
		writeJSON(w, http.StatusConflict, map[string]string{"detail": "credential_changed_during_verification"})
	case errors.Is(err, coreassets.ErrInvalidInput):
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": err.Error()})
	case errors.Is(err, coreassets.ErrGatewayInUse):
		writeJSON(w, http.StatusConflict, map[string]string{"detail": "ssh_gateway_in_use"})
	case errors.Is(err, coreassets.ErrRotationPending), errors.Is(err, coreassets.ErrRotationInProgress):
		writeJSON(w, http.StatusConflict, map[string]string{"detail": "password_rotation_in_progress"})
	case errors.Is(err, coreassets.ErrCredentialBackupLimit):
		writeJSON(w, http.StatusConflict, map[string]string{"detail": "credential_backup_limit_reached"})
	case errors.Is(err, coreassets.ErrPasswordRotationFailed):
		writeJSON(w, http.StatusBadGateway, map[string]string{"detail": "password_rotation_failed"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "asset operation failed"})
	}
}
