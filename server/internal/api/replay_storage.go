package api

import (
	"errors"
	"net/http"
	"strconv"
	"sync"

	"github.com/neko233-com/jumpserver233/server/internal/core/replayarchive"
)

func replayStorageError(w http.ResponseWriter, e error) {
	status, code := 503, "replay_storage_unavailable"
	switch {
	case errors.Is(e, replayarchive.ErrInvalid):
		status, code = 400, "replay_storage_invalid"
	case errors.Is(e, replayarchive.ErrNotFound):
		status, code = 404, "replay_storage_not_found"
	case errors.Is(e, replayarchive.ErrConflict):
		status, code = 409, "replay_storage_conflict"
	case errors.Is(e, replayarchive.ErrIntegrity):
		status, code = 409, "replay_storage_integrity"
	case errors.Is(e, replayarchive.ErrCapacity):
		status, code = 507, "replay_storage_capacity"
	}
	setNoStore(w)
	writeJSON(w, status, map[string]string{"error_code": code})
}
func replayStoragePage(r *http.Request) (int, int, error) {
	offset, limit := 0, 50
	var e error
	if v := r.URL.Query().Get("offset"); v != "" {
		offset, e = strconv.Atoi(v)
		if e != nil {
			return 0, 0, replayarchive.ErrInvalid
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		limit, e = strconv.Atoi(v)
	}
	if e != nil || offset < 0 || limit < 1 || limit > 100 {
		return 0, 0, replayarchive.ErrInvalid
	}
	return offset, limit, nil
}
func replayStorageRef(r *http.Request) replayarchive.Ref {
	return replayarchive.Ref{Kind: r.PathValue("kind"), SessionID: r.PathValue("sessionID")}
}
func replayStorageAuthorized(d Dependencies, r *http.Request, ref replayarchive.Ref) bool {
	if !replayarchive.ValidRef(ref) {
		return false
	}
	u, _ := PrincipalFromContext(r.Context())
	all := hasPermission(r, "audit.replays.view_all")
	if ref.Kind == "terminal" {
		if d.Sessions == nil {
			return false
		}
		_, e := d.Sessions.ReplayRecord(ref.SessionID, u.ID, all)
		return e == nil
	}
	if d.Desktops == nil {
		return false
	}
	record, e := d.Desktops.Get(ref.SessionID, u.ID, all)
	return e == nil && record.Status == "ended"
}
func replayStorageVisible(d Dependencies, r *http.Request) (map[replayarchive.Ref]bool, error) {
	u, _ := PrincipalFromContext(r.Context())
	all := hasPermission(r, "audit.replays.view_all")
	visible := map[replayarchive.Ref]bool{}
	if d.Sessions != nil {
		rows, e := d.Sessions.ReplayRecords()
		if e != nil {
			return nil, e
		}
		for _, row := range rows {
			if all || u.ID != "" && row.OperatorID == u.ID {
				visible[replayarchive.Ref{Kind: "terminal", SessionID: row.SessionID}] = true
			}
		}
	}
	if d.Desktops != nil {
		rows, e := d.Desktops.ReplayRecords(r.Context())
		if e != nil {
			return nil, e
		}
		for _, row := range rows {
			if all || u.ID != "" && row.OperatorID == u.ID {
				visible[replayarchive.Ref{Kind: "desktop", SessionID: row.ID}] = true
			}
		}
	}
	return visible, nil
}
func registerReplayStorageRoutes(mux *http.ServeMux, d Dependencies, mu *sync.RWMutex) {
	if d.ReplayArchive == nil {
		return
	}
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	require := func(w http.ResponseWriter, r *http.Request, permission string) bool {
		setNoStore(w)
		if !hasPermission(r, permission) {
			writeJSON(w, 403, map[string]string{"error_code": "permission_denied"})
			return false
		}
		return true
	}
	base := "/api/v1/settings/replay-storage"
	mux.Handle("GET "+base, protect(func(w http.ResponseWriter, r *http.Request) {
		if !require(w, r, "replay_storage.view") {
			return
		}
		c, e := d.ReplayArchive.Config()
		if e != nil {
			replayStorageError(w, e)
			return
		}
		if !hasPermission(r, "replay_storage.manage") {
			c.Cloud = nil
			c.SFTPAssetID = ""
			c.SFTPDirectory = ""
			c.SFTPTarget = ""
			c.HasSecret = false
			c.HasSessionToken = false
		}
		writeJSON(w, 200, map[string]any{"config": c, "postgres_available": d.ReplayArchiveDatabase})
	}))
	mux.Handle("PUT "+base, protect(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !require(w, r, "replay_storage.manage") {
			return
		}
		var in replayarchive.Input
		if decodeRequestJSON(w, r, &in) != nil {
			return
		}
		if in.Provider == "postgres" && !d.ReplayArchiveDatabase {
			replayStorageError(w, replayarchive.ErrInvalid)
			return
		}
		// Persistent SFTP storage is an explicit system operation. A storage role
		// alone never turns an asset's view grant into background file access.
		if in.Provider == "sftp" {
			if d.Assets == nil || !hasPermission(r, "assets.manage") || !hasPermission(r, "assets.sftp_all") {
				writeJSON(w, 403, map[string]string{"error_code": "permission_denied"})
				return
			}
			a, e := d.Assets.Get(in.SFTPAssetID)
			if e != nil || a.LoginReviewRequired && !hasPermission(r, "login_review.bypass") {
				replayStorageError(w, replayarchive.ErrNotFound)
				return
			}
			target, _, e := d.Assets.ReplayStorageTarget(a.ID)
			if e != nil {
				replayStorageError(w, replayarchive.ErrInvalid)
				return
			}
			in.SFTPTarget = target
		} else {
			in.SFTPTarget = ""
		}
		u, _ := PrincipalFromContext(r.Context())
		c, e := d.ReplayArchive.Save(u.ID, in)
		if e != nil {
			replayStorageError(w, e)
			return
		}
		writeJSON(w, 200, c)
	}))
	mux.Handle("GET "+base+"/records", protect(func(w http.ResponseWriter, r *http.Request) {
		if !require(w, r, "replay_storage.view") {
			return
		}
		offset, limit, e := replayStoragePage(r)
		if e != nil {
			replayStorageError(w, e)
			return
		}
		visible, e := replayStorageVisible(d, r)
		if e != nil {
			replayStorageError(w, e)
			return
		}
		rows, total, e := d.ReplayArchive.ListFor(offset, limit, func(ref replayarchive.Ref) bool { return visible[ref] })
		if e != nil {
			replayStorageError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": total, "offset": offset, "limit": limit})
	}))
	mux.Handle("GET "+base+"/audit", protect(func(w http.ResponseWriter, r *http.Request) {
		if !require(w, r, "replay_storage.audit") {
			return
		}
		offset, limit, e := replayStoragePage(r)
		if e != nil {
			replayStorageError(w, e)
			return
		}
		visible, e := replayStorageVisible(d, r)
		if e != nil {
			replayStorageError(w, e)
			return
		}
		rows, total, e := d.ReplayArchive.AuditFor(offset, limit, func(ref replayarchive.Ref) bool { return visible[ref] })
		if e != nil {
			replayStorageError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": total, "offset": offset, "limit": limit})
	}))
	path := base + "/records/{kind}/{sessionID}"
	mux.Handle("GET "+path, protect(func(w http.ResponseWriter, r *http.Request) {
		if !require(w, r, "replay_storage.view") {
			return
		}
		ref := replayStorageRef(r)
		if !replayStorageAuthorized(d, r, ref) {
			replayStorageError(w, replayarchive.ErrNotFound)
			return
		}
		record, e := d.ReplayArchive.Get(ref)
		if e != nil {
			replayStorageError(w, e)
			return
		}
		writeJSON(w, 200, record)
	}))
	for _, action := range []string{"archive", "retry", "verify", "evict"} {
		mux.Handle("POST "+path+"/"+action, protect(func(w http.ResponseWriter, r *http.Request) {
			permission := "replay_storage.archive"
			if action == "verify" {
				permission = "replay_storage.verify"
			}
			if action == "evict" {
				permission = "replay_storage.evict"
			}
			if !require(w, r, permission) {
				return
			}
			ref := replayStorageRef(r)
			if !replayStorageAuthorized(d, r, ref) {
				replayStorageError(w, replayarchive.ErrNotFound)
				return
			}
			var in struct {
				RequestID string `json:"request_id"`
			}
			if decodeRequestJSON(w, r, &in) != nil {
				return
			}
			u, _ := PrincipalFromContext(r.Context())
			var record replayarchive.Record
			var e error
			switch action {
			case "archive":
				record, e = d.ReplayArchive.Queue(ref, u.ID, in.RequestID)
			case "retry":
				record, e = d.ReplayArchive.Retry(ref, u.ID, in.RequestID)
			case "verify":
				record, e = d.ReplayArchive.Verify(r.Context(), ref, u.ID, in.RequestID)
			case "evict":
				record, e = d.ReplayArchive.Evict(r.Context(), ref, u.ID, in.RequestID)
			}
			if e != nil {
				replayStorageError(w, e)
				return
			}
			writeJSON(w, 200, record)
		}))
	}
}
