package api

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"

	"github.com/neko233-com/jumpserver233/server/internal/maintenance"
	"github.com/neko233-com/jumpserver233/server/internal/releasebundle"
)

const installationSchedulePath = "/api/v1/settings/security/updates/installation"

func installationScheduleError(w http.ResponseWriter, e error) {
	status, code := 503, "unavailable"
	if errors.Is(e, releasebundle.ErrInvalid) {
		status, code = 400, "invalid"
	}
	if errors.Is(e, releasebundle.ErrInstallConflict) || errors.Is(e, releasebundle.ErrInstallPending) || errors.Is(e, releasebundle.ErrStageConflict) {
		status, code = 409, "conflict"
	}
	if errors.Is(e, maintenance.ErrBusy) {
		status, code = 409, "busy"
	}
	writeJSON(w, status, map[string]string{"error_code": code})
}
func validateInstallationBinding(ctx context.Context, d Dependencies) error {
	v, e := releasebundle.InstallationStatus(ctx, d.ReleaseRoot)
	if e != nil {
		return e
	}
	actual, e := filepath.EvalSymlinks(v.DataDir)
	if e != nil {
		return e
	}
	expected, e := filepath.EvalSymlinks(d.InstallationDataDir)
	if e != nil {
		return e
	}
	if actual != expected || v.DataDir == "" {
		return releasebundle.ErrInstallConflict
	}
	return nil
}
func installationScheduleSnapshot(w http.ResponseWriter, r *http.Request, d Dependencies) {
	if d.ReleaseRoot == "" {
		writeJSON(w, 200, map[string]bool{"configured": false})
		return
	}
	if e := validateInstallationBinding(r.Context(), d); e != nil {
		installationScheduleError(w, e)
		return
	}
	v, e := releasebundle.ScheduleState(r.Context(), d.ReleaseRoot)
	if e != nil {
		installationScheduleError(w, e)
		return
	}
	i, e := releasebundle.InstallationStatus(r.Context(), d.ReleaseRoot)
	if e != nil {
		installationScheduleError(w, e)
		return
	}
	writeJSON(w, 200, map[string]any{"configured": true, "revision": v.Revision, "plan": v.Plan, "events": v.Events, "supervisor_seen_at": v.SupervisorSeenAt, "installation_revision": i.Revision, "current": i.Current})
}
func registerInstallationScheduleRoutes(mux *http.ServeMux, d Dependencies) {
	if d.Tenant || d.Auth == nil {
		return
	}
	protect := func(fn http.HandlerFunc) http.Handler {
		return protectAdminAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { setNoStore(w); fn(w, r) }), d.AdminToken, d.Auth)
	}
	mux.Handle("GET "+installationSchedulePath, protect(func(w http.ResponseWriter, r *http.Request) { installationScheduleSnapshot(w, r, d) }))
	bound := func(w http.ResponseWriter, r *http.Request) bool {
		if d.ReleaseRoot == "" {
			writeJSON(w, 409, map[string]string{"error_code": "unsupported"})
			return false
		}
		if e := validateInstallationBinding(r.Context(), d); e != nil {
			installationScheduleError(w, e)
			return false
		}
		return true
	}
	mux.Handle("GET "+installationSchedulePath+"/candidates", protect(func(w http.ResponseWriter, r *http.Request) {
		if !bound(w, r) {
			return
		}
		v, e := releasebundle.StagedCandidates(r.Context(), d.ReleaseRoot)
		if e != nil {
			installationScheduleError(w, e)
			return
		}
		writeJSON(w, 200, v)
	}))
	mux.Handle("POST "+installationSchedulePath, protect(func(w http.ResponseWriter, r *http.Request) {
		if !bound(w, r) {
			return
		}
		var in releasebundle.ScheduleInput
		if decodeRequestJSON(w, r, &in) != nil {
			installationScheduleError(w, releasebundle.ErrInvalid)
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		if _, e := releasebundle.SaveSchedule(r.Context(), d.ReleaseRoot, in, u.ID, u.Username); e != nil {
			installationScheduleError(w, e)
			return
		}
		installationScheduleSnapshot(w, r, d)
	}))
	mux.Handle("POST "+installationSchedulePath+"/cancel", protect(func(w http.ResponseWriter, r *http.Request) {
		if !bound(w, r) {
			return
		}
		var in releasebundle.CancelScheduleInput
		if decodeRequestJSON(w, r, &in) != nil {
			installationScheduleError(w, releasebundle.ErrInvalid)
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		if _, e := releasebundle.CancelSchedule(r.Context(), d.ReleaseRoot, in, u.ID, u.Username); e != nil {
			installationScheduleError(w, e)
			return
		}
		installationScheduleSnapshot(w, r, d)
	}))
}
