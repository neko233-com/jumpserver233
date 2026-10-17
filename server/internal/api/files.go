package api

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"path"
	"strconv"
	"sync"
	"time"

	coreaccessreviews "github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	corefiles "github.com/neko233-com/jumpserver233/server/internal/core/files"
	coregrants "github.com/neko233-com/jumpserver233/server/internal/core/grants"
	coregroups "github.com/neko233-com/jumpserver233/server/internal/core/groups"
	corenodes "github.com/neko233-com/jumpserver233/server/internal/core/nodes"
)

func registerFileRoutes(mux *http.ServeMux, service *corefiles.Service, assets *coreassets.Service, identities *coreauth.Service, grants *coregrants.Store, adminToken string, groups *coregroups.Store, nodes *corenodes.Store, accessReviews *coreaccessreviews.Store, sftpSessions *corefiles.AccessSessionStore, accessMu *sync.RWMutex) {
	protect := func(handler http.HandlerFunc) http.Handler {
		return protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assetID := r.PathValue("assetID")
			principal, _ := PrincipalFromContext(r.Context())
			var asset coreassets.Asset
			if !hasPermission(r, "assets.sftp_all") {
				accessMu.RLock()
				currentAsset, err := assets.Get(assetID)
				if err != nil {
					accessMu.RUnlock()
					writeAssetError(w, err)
					return
				}
				asset = currentAsset
				var groupIDs []string
				if groups != nil {
					groupIDs = groups.GroupIDsForUser(principal.ID)
				}
				var nodeIDs []string
				if nodes != nil {
					nodeIDs = nodes.AncestorIDs(asset.NodeID)
				}
				allowed := grants != nil && grants.AllowsForScopes(principal.ID, groupIDs, coreassets.ResourceID(asset), nodeIDs, asset.Username, "sftp", time.Now().UTC())
				accessMu.RUnlock()
				if !allowed {
					writeJSON(w, http.StatusForbidden, map[string]string{"detail": "sftp access is not granted"})
					return
				}
			}
			if asset.ID == "" {
				var err error
				asset, err = assets.Get(assetID)
				if err != nil {
					writeAssetError(w, err)
					return
				}
			}
			if !enforceAssetPolicy(w, r, principal, asset, "sftp") {
				return
			}
			if !coreassets.IsSSH(asset) {
				writeAssetError(w, coreassets.ErrUnsupportedProtocol)
				return
			}
			method := ""
			switch {
			case r.Method == "PUT":
				method = "upload"
			case r.Method == "DELETE":
				method = "delete"
			case r.Method == "POST":
				method = "mkdir"
			case r.URL.Path == "/api/v1/assets/"+assetID+"/files/content":
				method = "download"
			}
			if method != "" && !enforceAssetPolicy(w, r, principal, asset, method) {
				return
			}
			if !hasPermission(r, "login_review.bypass") && asset.LoginReviewRequired {
				if accessReviews == nil || sftpSessions == nil {
					writeJSON(w, http.StatusServiceUnavailable, map[string]string{"detail": "SFTP login review is unavailable"})
					return
				}
				if !sftpSessions.Authorize(r.Header.Get(sftpAccessSessionHeader), principal.ID, asset.ID, asset.Username) {
					writeJSON(w, http.StatusPreconditionRequired, map[string]string{"detail": "SFTP login review session is required"})
					return
				}
			}
			handler(w, r)
		}), adminToken, identities)
	}

	registerSFTPAccessSessionRoutes(mux, assets, identities, grants, adminToken, groups, nodes, accessReviews, sftpSessions, accessMu)

	mux.Handle("GET /api/v1/assets/{assetID}/files", protect(func(w http.ResponseWriter, r *http.Request) {
		items, err := service.List(r.Context(), r.PathValue("assetID"), r.URL.Query().Get("path"))
		if err != nil {
			writeFileError(w, err)
			return
		}
		setNoStore(w)
		writeJSON(w, http.StatusOK, map[string]any{"path": r.URL.Query().Get("path"), "entries": items})
	}))

	mux.Handle("POST /api/v1/assets/{assetID}/directories", protect(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Path string `json:"path"`
		}
		if err := decodeRequestJSON(w, r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid directory payload"})
			return
		}
		if err := service.MakeDirectory(r.Context(), principalActor(r), r.PathValue("assetID"), input.Path); err != nil {
			writeFileError(w, err)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))

	mux.Handle("DELETE /api/v1/assets/{assetID}/files/content", protect(func(w http.ResponseWriter, r *http.Request) {
		if err := service.Delete(r.Context(), principalActor(r), r.PathValue("assetID"), r.URL.Query().Get("path")); err != nil {
			writeFileError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	mux.Handle("PUT /api/v1/assets/{assetID}/files/content", protect(func(w http.ResponseWriter, r *http.Request) {
		overwrite := false
		if value := r.URL.Query().Get("overwrite"); value != "" {
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid overwrite flag"})
				return
			}
			overwrite = parsed
		}
		bytes, err := service.Upload(r.Context(), principalActor(r), r.PathValue("assetID"), r.URL.Query().Get("path"), r.Body, overwrite)
		if err != nil {
			writeFileError(w, err)
			return
		}
		setNoStore(w)
		writeJSON(w, http.StatusCreated, map[string]int64{"bytes": bytes})
	}))

	mux.Handle("GET /api/v1/assets/{assetID}/files/content", protect(func(w http.ResponseWriter, r *http.Request) {
		relativePath := r.URL.Query().Get("path")
		download, err := service.OpenDownload(r.Context(), principalActor(r), r.PathValue("assetID"), relativePath)
		if err != nil {
			writeFileError(w, err)
			return
		}
		name := path.Base(relativePath)
		if name == "." || name == "/" || name == "" {
			name = "download"
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
		setNoStore(w)
		if download.Info.Size >= 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(download.Info.Size, 10))
		}
		w.WriteHeader(http.StatusOK)
		bytes, copyErr := io.Copy(w, download.Reader)
		download.Finish(bytes, copyErr)
	}))

	mux.Handle("GET /api/v1/file-transfers", protectFileAudit(service, adminToken, identities))
}

func protectFileAudit(service *corefiles.Service, adminToken string, identities *coreauth.Service) http.Handler {
	return protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid audit pagination"})
			return
		}
		principal, _ := PrincipalFromContext(r.Context())
		actor := ""
		if !hasPermission(r, "audit.files.view_all") {
			actor = principal.Username
		}
		results, total, err := service.ListAudit(actor, offset, limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "could not read file-transfer audit"})
			return
		}
		setNoStore(w)
		writeJSON(w, http.StatusOK, map[string]any{"results": results, "total": total, "limit": limit, "offset": offset})
	}), adminToken, identities)
}

func principalActor(r *http.Request) string {
	principal, _ := PrincipalFromContext(r.Context())
	return principal.Username
}

func writeFileError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, coreassets.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "asset not found"})
	case errors.Is(err, corefiles.ErrInvalidPath):
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid remote path"})
	case errors.Is(err, corefiles.ErrUnsafePath):
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "symbolic links are not followed"})
	case errors.Is(err, corefiles.ErrConflict):
		writeJSON(w, http.StatusConflict, map[string]string{"detail": "remote file already exists"})
	case errors.Is(err, corefiles.ErrNotFile):
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "remote path is not a regular file"})
	case errors.Is(err, corefiles.ErrTooLarge):
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"detail": "file exceeds the transfer size limit"})
	case corefiles.IsNotExist(err):
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "remote path not found"})
	default:
		writeJSON(w, http.StatusBadGateway, map[string]string{"detail": "file transfer failed"})
	}
}
