package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/assistant"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
)

func assistantError(w http.ResponseWriter, e error) {
	status, code := 503, "assistant_unavailable"
	switch {
	case errors.Is(e, assistant.ErrInvalid):
		status, code = 400, "assistant_invalid"
	case errors.Is(e, assistant.ErrDenied):
		status, code = 403, "assistant_denied"
	case errors.Is(e, assistant.ErrConflict):
		status, code = 409, "assistant_conflict"
	case errors.Is(e, assistant.ErrNotFound):
		status, code = 404, "assistant_not_found"
	case errors.Is(e, assistant.ErrCapacity):
		status, code = 507, "assistant_capacity"
	case errors.Is(e, workgate.ErrDraining):
		status, code = 503, "service_draining"
	}
	writeJSON(w, status, map[string]string{"error_code": code})
}

// Runtime teardown may hold the authorization write lock while joining model
// calls. Their periodic guards must remain cancelable while waiting for it.
func assistantPermissionReadLock(ctx context.Context, global, local *sync.RWMutex) (func(), error) {
	for {
		if ctx.Err() != nil {
			return nil, assistant.ErrDenied
		}
		globalLocked := global != nil && global != local
		if !globalLocked || global.TryRLock() {
			if local.TryRLock() {
				return func() {
					local.RUnlock()
					if globalLocked {
						global.RUnlock()
					}
				}, nil
			}
			if globalLocked {
				global.RUnlock()
			}
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, assistant.ErrDenied
		case <-timer.C:
		}
	}
}
func registerAssistantRoutes(mux *http.ServeMux, d Dependencies, mu *sync.RWMutex) {
	if d.Assistant == nil || d.Auth == nil {
		return
	}
	lock := func() func() {
		global := d.GlobalAccessMu
		if global != nil && global != mu {
			global.RLock()
		}
		mu.RLock()
		return func() {
			mu.RUnlock()
			if global != nil && global != mu {
				global.RUnlock()
			}
		}
	}
	protect := func(fn func(http.ResponseWriter, *http.Request, coreauth.User, rbac.Snapshot)) http.Handler {
		return protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			setNoStore(w)
			u, _ := PrincipalFromContext(r.Context())
			u, p, ok := notificationActor(r.Context(), d, u.ID)
			if !ok {
				assistantError(w, assistant.ErrDenied)
				return
			}
			fn(w, r, u, p)
		}), d.AdminToken, d.Auth)
	}
	current := func(r *http.Request, id, permission string) (coreauth.User, rbac.Snapshot, bool) {
		fresh, status := resolvePrincipal(r, d.AdminToken, d.Auth)
		if status != 200 || fresh.ID != id {
			return fresh, rbac.Snapshot{}, false
		}
		u, p, ok := notificationActor(r.Context(), d, id)
		return u, p, ok && p.Allows(permission)
	}
	page := func(r *http.Request) (int, int, bool) {
		offset, e := strconv.Atoi(defaultQuery(r, "offset", "0"))
		limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "20"))
		return offset, limit, e == nil && e2 == nil && offset >= 0 && limit > 0 && limit <= 100
	}
	mux.Handle("GET /api/v1/assistant/capabilities", protect(func(w http.ResponseWriter, r *http.Request, u coreauth.User, p rbac.Snapshot) {
		unlock := lock()
		defer unlock()
		u, p, ok := notificationActor(r.Context(), d, u.ID)
		_ = u
		if !ok {
			assistantError(w, assistant.ErrDenied)
			return
		}
		config, e := d.Assistant.Settings()
		if e != nil {
			assistantError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"use": p.Allows("assistant.use"), "manage": p.Allows("assistant.manage"), "audit": p.Allows("assistant.audit"), "enabled": config.Enabled && config.Configured, "model": config.Model})
	}))
	mux.Handle("GET /api/v1/assistant/settings", protect(func(w http.ResponseWriter, r *http.Request, u coreauth.User, _ rbac.Snapshot) {
		unlock := lock()
		defer unlock()
		if _, _, ok := current(r, u.ID, "assistant.manage"); !ok {
			assistantError(w, assistant.ErrDenied)
			return
		}
		out, e := d.Assistant.Settings()
		if e != nil {
			assistantError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("PUT /api/v1/assistant/settings", protect(func(w http.ResponseWriter, r *http.Request, u coreauth.User, _ rbac.Snapshot) {
		var in assistant.SettingsInput
		if decodeRequestJSON(w, r, &in) != nil {
			assistantError(w, assistant.ErrInvalid)
			return
		}
		unlock := lock()
		defer unlock()
		if _, _, ok := current(r, u.ID, "assistant.manage"); !ok {
			assistantError(w, assistant.ErrDenied)
			return
		}
		out, e := d.Assistant.SaveSettings(u.ID, in)
		if e != nil {
			assistantError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("POST /api/v1/assistant/turns", protect(func(w http.ResponseWriter, r *http.Request, u coreauth.User, p rbac.Snapshot) {
		if !p.Allows("assistant.use") {
			assistantError(w, assistant.ErrDenied)
			return
		}
		var in assistant.Input
		if decodeRequestJSON(w, r, &in) != nil {
			assistantError(w, assistant.ErrInvalid)
			return
		}
		initial := reportAuthority(d, u, p)
		guard := func(ctx context.Context) error {
			unlock, e := assistantPermissionReadLock(ctx, d.GlobalAccessMu, mu)
			if e != nil {
				return e
			}
			defer unlock()
			fresh, permissions, ok := current(r.WithContext(ctx), u.ID, "assistant.use")
			if !ok || reportAuthority(d, fresh, permissions) != initial {
				return assistant.ErrDenied
			}
			return nil
		}
		result, e := d.Assistant.Submit(r.Context(), u.ID, in, guard)
		if e != nil {
			assistantError(w, e)
			return
		}
		unlock := lock()
		defer unlock()
		fresh, permissions, ok := current(r, u.ID, "assistant.use")
		if !ok || reportAuthority(d, fresh, permissions) != initial {
			assistantError(w, assistant.ErrDenied)
			return
		}
		status := 200
		if result.Turn.Status == "pending" {
			status = 202
		}
		writeJSON(w, status, result)
	}))
	mux.Handle("GET /api/v1/assistant/conversations", protect(func(w http.ResponseWriter, r *http.Request, u coreauth.User, _ rbac.Snapshot) {
		offset, limit, valid := page(r)
		all, archived := r.URL.Query().Get("all") == "true", r.URL.Query().Get("archived") == "true"
		if !valid {
			assistantError(w, assistant.ErrInvalid)
			return
		}
		permission := "assistant.use"
		if all {
			permission = "assistant.audit"
		}
		unlock := lock()
		defer unlock()
		if _, _, ok := current(r, u.ID, permission); !ok {
			assistantError(w, assistant.ErrDenied)
			return
		}
		out, e := d.Assistant.Page(u.ID, all, archived, offset, limit)
		if e != nil {
			assistantError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("GET /api/v1/assistant/conversations/{conversationID}", protect(func(w http.ResponseWriter, r *http.Request, u coreauth.User, _ rbac.Snapshot) {
		all := r.URL.Query().Get("all") == "true"
		permission := "assistant.use"
		if all {
			permission = "assistant.audit"
		}
		unlock := lock()
		defer unlock()
		if _, _, ok := current(r, u.ID, permission); !ok {
			assistantError(w, assistant.ErrDenied)
			return
		}
		out, e := d.Assistant.Get(u.ID, r.PathValue("conversationID"), all)
		if e != nil {
			assistantError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("POST /api/v1/assistant/conversations/{conversationID}/archive", protect(func(w http.ResponseWriter, r *http.Request, u coreauth.User, _ rbac.Snapshot) {
		var in struct {
			Revision  int    `json:"revision"`
			RequestID string `json:"request_id"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			assistantError(w, assistant.ErrInvalid)
			return
		}
		unlock := lock()
		defer unlock()
		if _, _, ok := current(r, u.ID, "assistant.use"); !ok {
			assistantError(w, assistant.ErrDenied)
			return
		}
		if e := d.Assistant.Archive(u.ID, r.PathValue("conversationID"), in.Revision, in.RequestID); e != nil {
			assistantError(w, e)
			return
		}
		w.WriteHeader(204)
	}))
	mux.Handle("GET /api/v1/assistant/audit", protect(func(w http.ResponseWriter, r *http.Request, u coreauth.User, _ rbac.Snapshot) {
		offset, limit, ok := page(r)
		if !ok {
			assistantError(w, assistant.ErrInvalid)
			return
		}
		unlock := lock()
		defer unlock()
		if _, _, ok = current(r, u.ID, "assistant.audit"); !ok {
			assistantError(w, assistant.ErrDenied)
			return
		}
		out, e := d.Assistant.Audit(offset, limit)
		if e != nil {
			assistantError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
}
