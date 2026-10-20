package api

import (
	"errors"
	"net/http"
	"strconv"
	"sync"

	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/sshcertificates"
)

func sshCertificateError(w http.ResponseWriter, e error) {
	status, code := 503, "ssh_certificates_unavailable"
	switch {
	case errors.Is(e, sshcertificates.ErrInvalid):
		status, code = 400, "ssh_certificates_invalid"
	case errors.Is(e, sshcertificates.ErrConflict):
		status, code = 409, "ssh_certificates_conflict"
	case errors.Is(e, sshcertificates.ErrNotFound):
		status, code = 404, "ssh_certificates_not_found"
	case errors.Is(e, sshcertificates.ErrInUse):
		status, code = 409, "ssh_certificates_in_use"
	case errors.Is(e, sshcertificates.ErrCapacity):
		status, code = 507, "ssh_certificates_capacity"
	}
	setNoStore(w)
	writeJSON(w, status, map[string]string{"error_code": code})
}
func certificateAsset(d Dependencies, r *http.Request, write bool) (coreassets.Asset, bool) {
	u, _ := PrincipalFromContext(r.Context())
	p := permissionsForRequest(r, u)
	if write && (!p.Allows("ssh_certificates.assign") || !p.Allows("assets.manage")) {
		return coreassets.Asset{}, false
	}
	a, e := d.Assets.Get(r.PathValue("assetID"))
	if e != nil || !coreassets.IsSSH(a) {
		return a, false
	}
	groups := []string{}
	if d.Groups != nil {
		groups = d.Groups.GroupIDsForUser(u.ID)
	}
	nodes := []string{}
	if d.Nodes != nil {
		nodes = d.Nodes.AncestorIDs(a.NodeID)
	}
	return a, hasAction(scopedAssetActions(u.ID, a, p, d.Grants, groups, nodes), "view")
}
func registerSSHCertificateRoutes(mux *http.ServeMux, d Dependencies, mu *sync.RWMutex) {
	if d.SSHCertificates == nil || d.Assets == nil {
		return
	}
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	require := func(w http.ResponseWriter, r *http.Request, permission string) bool {
		if !hasPermission(r, permission) {
			setNoStore(w)
			writeJSON(w, 403, map[string]string{"error_code": "permission_denied"})
			return false
		}
		return true
	}
	base := "/api/v1/settings/ssh-certificates"
	mux.Handle("GET "+base+"/issuers", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !require(w, r, "ssh_certificates.view") {
			return
		}
		rows, e := d.SSHCertificates.Issuers()
		if e != nil {
			sshCertificateError(w, e)
			return
		}
		if !hasPermission(r, "ssh_certificates.manage") {
			for i := range rows {
				rows[i].Endpoint = ""
				rows[i].Mount = ""
				rows[i].Role = ""
				rows[i].Namespace = ""
				rows[i].RootCAPEM = ""
				rows[i].HasToken = false
			}
		}
		writeJSON(w, 200, rows)
	}))
	save := func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		mu.Lock()
		defer mu.Unlock()
		if !require(w, r, "ssh_certificates.manage") {
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		var in sshcertificates.Input
		if decodeRequestJSON(w, r, &in) != nil {
			sshCertificateError(w, sshcertificates.ErrInvalid)
			return
		}
		v, e := d.SSHCertificates.Save(r.PathValue("issuerID"), u.ID, in)
		if e != nil {
			sshCertificateError(w, e)
			return
		}
		status := 200
		if r.Method == "POST" {
			status = 201
		}
		writeJSON(w, status, v)
	}
	mux.Handle("POST "+base+"/issuers", protect(save))
	mux.Handle("PUT "+base+"/issuers/{issuerID}", protect(save))
	mutation := func(action string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			setNoStore(w)
			mu.Lock()
			defer mu.Unlock()
			if !require(w, r, "ssh_certificates.manage") {
				return
			}
			u, _ := PrincipalFromContext(r.Context())
			var in struct {
				Revision  int    `json:"revision"`
				RequestID string `json:"request_id"`
			}
			if decodeRequestJSON(w, r, &in) != nil {
				sshCertificateError(w, sshcertificates.ErrInvalid)
				return
			}
			if action != "delete" {
				var v sshcertificates.Issuer
				var e error
				if action == "activate" {
					v, e = d.SSHCertificates.Activate(r.PathValue("issuerID"), u.ID, in.Revision, in.RequestID)
				} else {
					v, e = d.SSHCertificates.Rotate(r.PathValue("issuerID"), u.ID, in.Revision, in.RequestID)
				}
				if e != nil {
					sshCertificateError(w, e)
					return
				}
				writeJSON(w, 200, v)
			} else {
				refs, e := d.SSHCertificates.References(r.PathValue("issuerID"))
				if e != nil {
					sshCertificateError(w, e)
					return
				}
				missing := map[string]bool{}
				for _, id := range refs {
					_, e := d.Assets.Get(id)
					if errors.Is(e, coreassets.ErrNotFound) {
						missing[id] = true
					}
				}
				if e := d.SSHCertificates.Delete(r.PathValue("issuerID"), u.ID, in.Revision, in.RequestID, missing); e != nil {
					sshCertificateError(w, e)
					return
				}
				w.WriteHeader(204)
			}
		}
	}
	mux.Handle("POST "+base+"/issuers/{issuerID}/rotate", protect(mutation("rotate")))
	mux.Handle("POST "+base+"/issuers/{issuerID}/activate", protect(mutation("activate")))
	mux.Handle("DELETE "+base+"/issuers/{issuerID}", protect(mutation("delete")))
	mux.Handle("GET "+base+"/bindings/{assetID}", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		mu.RLock()
		defer mu.RUnlock()
		a, ok := certificateAsset(d, r, false)
		if !ok {
			sshCertificateError(w, sshcertificates.ErrNotFound)
			return
		}
		v, e := d.SSHCertificates.Binding(a.ID)
		if e != nil {
			sshCertificateError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"binding": v, "target": coreassets.SSHCertificateTarget(a), "assignable": hasPermission(r, "ssh_certificates.assign") && hasPermission(r, "assets.manage")})
	}))
	mux.Handle("PUT "+base+"/bindings/{assetID}", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		mu.Lock()
		defer mu.Unlock()
		a, ok := certificateAsset(d, r, true)
		if !ok {
			sshCertificateError(w, sshcertificates.ErrNotFound)
			return
		}
		u, _ := PrincipalFromContext(r.Context())
		var in sshcertificates.BindingInput
		if decodeRequestJSON(w, r, &in) != nil {
			sshCertificateError(w, sshcertificates.ErrInvalid)
			return
		}
		v, e := d.Assets.BindSSHCertificate(a.ID, u.ID, in)
		if e != nil {
			sshCertificateError(w, e)
			return
		}
		writeJSON(w, 200, v)
	}))
	mux.Handle("GET "+base+"/audit", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		if !require(w, r, "ssh_certificates.audit") {
			return
		}
		offset, e := strconv.Atoi(defaultQuery(r, "offset", "0"))
		limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "50"))
		if e != nil || e2 != nil {
			sshCertificateError(w, sshcertificates.ErrInvalid)
			return
		}
		rows, total, e := d.SSHCertificates.Audit(offset, limit)
		if e != nil {
			sshCertificateError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": total})
	}))
}
