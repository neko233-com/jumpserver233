package api

import (
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/credentialpolicy"
	"net/http"
	"sync"
)

const sshPasswordPolicyPath = "/api/v1/accounts/password-policy"

func registerSSHPasswordPolicyRoutes(mux *http.ServeMux, d Dependencies, accessMu *sync.RWMutex) {
	if d.Auth == nil || d.SSHPasswordPolicy == nil {
		return
	}
	if d.AccessMu == nil {
		d.AccessMu = accessMu
	}
	handle := func(permission string, save bool) http.Handler {
		return protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			setNoStore(w)
			if d.GlobalAccessMu != nil && d.GlobalAccessMu != d.AccessMu {
				d.GlobalAccessMu.RLock()
				defer d.GlobalAccessMu.RUnlock()
			}
			if d.AccessMu != nil {
				d.AccessMu.RLock()
				defer d.AccessMu.RUnlock()
			}
			principal, ok := PrincipalFromContext(r.Context())
			u, active := jobOwnerSnapshot(d, principal)
			if !ok || !active || d.OrganizationAllowed != nil && !d.OrganizationAllowed(u) || !effectivePermissions(u, d.RBAC, d.Groups).Allows(permission) {
				writeJSON(w, 403, map[string]string{"error_code": "denied"})
				return
			}
			if save {
				var in credentialpolicy.Input
				if decodeRequestJSON(w, r, &in) != nil {
					writeJSON(w, 400, map[string]string{"error_code": "invalid"})
					return
				}
				if _, e := d.SSHPasswordPolicy.Save(in, u.ID, u.Username); e != nil {
					status, code := 503, "unavailable"
					if errors.Is(e, credentialpolicy.ErrInvalid) {
						status, code = 400, "invalid"
					}
					if errors.Is(e, credentialpolicy.ErrConflict) {
						status, code = 409, "conflict"
					}
					writeJSON(w, status, map[string]string{"error_code": code})
					return
				}
			}
			writeJSON(w, 200, map[string]any{"policy": d.SSHPasswordPolicy.Snapshot(), "audit": d.SSHPasswordPolicy.Audit()})
		}), d.AdminToken, d.Auth)
	}
	mux.Handle("GET "+sshPasswordPolicyPath, handle("accounts.password_policy.view", false))
	mux.Handle("PUT "+sshPasswordPolicyPath, handle("accounts.password_policy.manage", true))
}
