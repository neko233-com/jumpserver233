package api

import (
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
	"net/http"
)

func pluginJobAllowed(d Dependencies, u coreauth.User, id string, o *hostplugins.Operation) bool {
	if o == nil {
		return true
	}
	if d.HostPlugins == nil || o.Validate() != nil {
		return false
	}
	p := effectivePermissions(u, d.RBAC, d.Groups)
	if !p.Allows(o.Permission()) && !(o.Permission() == "plugins.inspect" && (p.Allows("plugins.manage") || p.Allows("plugins.protect"))) {
		return false
	}
	a, e := d.Assets.Get(id)
	return e == nil && o.Binding == databaseRouteBinding(d, a)
}
func registerHostPluginRoutes(mux *http.ServeMux, d Dependencies, submit func(coreauth.User, jobs.Input, string) (operations.Submission, error)) {
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	mux.Handle("GET /api/v1/host-plugins", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !hasPermission(r, "plugins.inspect") && !hasPermission(r, "plugins.manage") && !hasPermission(r, "plugins.protect") {
			writeJSON(w, 403, map[string]string{"detail": "host plugin permission required"})
			return
		}
		writeJSON(w, 200, hostplugins.Catalog())
	}))
	mux.Handle("POST /api/v1/assets/{assetID}/host-plugins/{pluginID}/jobs", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		var in struct {
			Action     string                        `json:"action"`
			RequestID  string                        `json:"request_id"`
			Timeout    int                           `json:"timeout_seconds"`
			ReviewID   string                        `json:"review_id"`
			Version    string                        `json:"version"`
			Protection *hostplugins.ProtectionPolicy `json:"protection"`
		}
		if decodeRequestJSON(w, r, &in) != nil || in.RequestID == "" {
			writeJobError(w, jobs.ErrInvalid)
			return
		}
		def, e := hostplugins.Lookup(r.PathValue("pluginID"))
		if e != nil || !def.Allows(in.Action) || in.Action == "events_collect" {
			writeJobError(w, jobs.ErrInvalid)
			return
		}
		if in.Version != "" {
			def, e = hostplugins.LookupVersion(def.ID, in.Version)
			if e != nil {
				writeJobError(w, jobs.ErrInvalid)
				return
			}
		}
		a, e := d.Assets.Get(r.PathValue("assetID"))
		if e != nil {
			writeJobError(w, jobs.ErrNotFound)
			return
		}
		op := hostplugins.Operation{Plugin: def.ID, Action: in.Action, Version: def.Version, Binding: databaseRouteBinding(d, a)}
		if in.Version == "" && in.Action != "install" && in.Action != "upgrade" {
			op.Selection = "installed"
		}
		if in.Protection != nil {
			policy, err := in.Protection.Normalize()
			if err != nil {
				writeJobError(w, jobs.ErrInvalid)
				return
			}
			op.Protection = &policy
		}
		if in.Timeout == 0 {
			in.Timeout = 180
		}
		input := jobs.Input{AssetID: a.ID, Command: op.Command(), Plugin: &op, TimeoutSeconds: in.Timeout, RequestID: in.RequestID, Origin: accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "exec"}}
		user, _ := PrincipalFromContext(r.Context())
		result, e := submit(user, input, in.ReviewID)
		if e != nil {
			writeJobError(w, e)
			return
		}
		if result.ReviewID != "" {
			writeJSON(w, 202, map[string]string{"review_id": result.ReviewID, "state": "pending"})
			return
		}
		writeJSON(w, 201, result.Job)
	}))
}
