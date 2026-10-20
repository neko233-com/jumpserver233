package api

import (
	"errors"
	"net/http"
	"sync"

	"github.com/neko233-com/jumpserver233/server/internal/connector/pamtypes"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
)

func pamAPIError(w http.ResponseWriter, e error) {
	status, code := 503, "pam_unavailable"
	switch {
	case errors.Is(e, pamtypes.ErrInvalid), errors.Is(e, assets.ErrInvalidInput), errors.Is(e, assets.ErrCredentialType):
		status, code = 400, "pam_invalid"
	case errors.Is(e, pamtypes.ErrChanged), errors.Is(e, assets.ErrCredentialChanged), errors.Is(e, assets.ErrAccountImportConflict), errors.Is(e, assets.ErrAccountImportExpired):
		status, code = 409, "pam_conflict"
	case errors.Is(e, assets.ErrNotFound):
		status, code = 404, "pam_not_found"
	case errors.Is(e, pamtypes.ErrScope), errors.Is(e, assets.ErrUnsupportedProtocol):
		status, code = 412, "pam_scope"
	case errors.Is(e, assets.ErrRotationPending), errors.Is(e, assets.ErrRotationInProgress):
		status, code = 409, "pam_busy"
	}
	writeJSON(w, status, map[string]string{"error_code": code})
}
func registerPAMRoutes(mux *http.ServeMux, d Dependencies, mu *sync.RWMutex) {
	if d.Assets == nil || d.Auth == nil {
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
	protect := func(permission string, fn func(http.ResponseWriter, *http.Request, coreauth.User, pamtypes.Guard)) http.Handler {
		return protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			setNoStore(w)
			u, _ := PrincipalFromContext(r.Context())
			release := lock()
			defer release()
			guard := func() error {
				principal, status := resolvePrincipal(r, d.AdminToken, d.Auth)
				if status != 200 || principal.ID != u.ID {
					return pamtypes.ErrScope
				}
				fresh, p, ok := notificationActor(r.Context(), d, u.ID)
				if !ok || !p.Allows(permission) || !p.Allows("assets.view_all") || permission == "accounts.manage" && !p.Allows("assets.rotate") {
					return pamtypes.ErrScope
				}
				a, e := d.Assets.Get(r.PathValue("assetID"))
				if e != nil {
					return e
				}
				decision, e := checkAccessPolicies(d, fresh, a, accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "credential_rotation"}, false)
				if e != nil || !decision.Allowed {
					return pamtypes.ErrScope
				}
				return r.Context().Err()
			}
			if e := guard(); e != nil {
				writeJSON(w, 403, map[string]string{"error_code": "pam_denied"})
				return
			}
			fn(w, r, u, guard)
		}), d.AdminToken, d.Auth)
	}
	mux.Handle("GET /api/v1/assets/{assetID}/pam/principals", protect("accounts.discover", func(w http.ResponseWriter, r *http.Request, _ coreauth.User, guard pamtypes.Guard) {
		ctx, release, e := workgate.FromContext(r.Context()).Enter(r.Context(), "credential_operations")
		if e != nil {
			pamAPIError(w, e)
			return
		}
		defer release()
		out, e := d.Assets.DiscoverPAM(ctx, r.PathValue("assetID"), guard)
		if e != nil {
			pamAPIError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("PUT /api/v1/assets/{assetID}/pam/platform", protect("accounts.manage", func(w http.ResponseWriter, r *http.Request, u coreauth.User, _ pamtypes.Guard) {
		var in struct {
			Platform  string `json:"platform"`
			Version   string `json:"version"`
			RequestID string `json:"request_id"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			pamAPIError(w, pamtypes.ErrInvalid)
			return
		}
		out, e := d.Assets.ConfigurePAMPlatform(r.Context(), r.PathValue("assetID"), in.Platform, in.Version, in.RequestID, assets.AccountActor{ID: u.ID, Name: u.Username})
		if e != nil {
			pamAPIError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("POST /api/v1/assets/{assetID}/pam/import-preview", protect("accounts.manage", func(w http.ResponseWriter, r *http.Request, u coreauth.User, guard pamtypes.Guard) {
		_, p, ok := notificationActor(r.Context(), d, u.ID)
		if !ok || !p.Allows("accounts.discover") || !p.Allows("accounts.import") {
			writeJSON(w, 403, map[string]string{"error_code": "pam_denied"})
			return
		}
		var in assets.PAMImportInput
		if decodeRequestJSON(w, r, &in) != nil {
			pamAPIError(w, pamtypes.ErrInvalid)
			return
		}
		ctx, release, e := workgate.FromContext(r.Context()).Enter(r.Context(), "credential_operations")
		if e != nil {
			pamAPIError(w, e)
			return
		}
		defer release()
		out, e := d.Assets.PreviewPAMImport(ctx, r.PathValue("assetID"), in, assets.AccountActor{ID: u.ID, Name: u.Username}, guard)
		if e != nil {
			pamAPIError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("POST /api/v1/assets/{assetID}/pam/import-commit", protect("accounts.manage", func(w http.ResponseWriter, r *http.Request, u coreauth.User, _ pamtypes.Guard) {
		_, p, ok := notificationActor(r.Context(), d, u.ID)
		if !ok || !p.Allows("accounts.discover") || !p.Allows("accounts.import") {
			writeJSON(w, 403, map[string]string{"error_code": "pam_denied"})
			return
		}
		var in assets.PAMImportInput
		if decodeRequestJSON(w, r, &in) != nil {
			pamAPIError(w, pamtypes.ErrInvalid)
			return
		}
		out, e := d.Assets.CommitPAMImport(r.Context(), r.PathValue("assetID"), in, assets.AccountActor{ID: u.ID, Name: u.Username})
		if e != nil {
			pamAPIError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
}
