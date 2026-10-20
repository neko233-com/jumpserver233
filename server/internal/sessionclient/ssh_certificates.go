package sessionclient

import (
	"context"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/core/sshcertificates"
)

type SSHIssuer = sshcertificates.Issuer
type SSHIssuerInput = sshcertificates.Input
type SSHCertificateBinding = sshcertificates.Binding
type SSHCertificateBindingInput = sshcertificates.BindingInput
type SSHCertificateBindingDetails struct {
	Binding    SSHCertificateBinding  `json:"binding"`
	Target     sshcertificates.Target `json:"target"`
	Assignable bool                   `json:"assignable"`
}
type SSHCertificateAuditPage struct {
	Results []sshcertificates.Audit `json:"results"`
	Total   int                     `json:"total"`
}

const sshCertificateBase = "/api/v1/settings/ssh-certificates"

func (c *Client) ActivateSSHIssuer(ctx context.Context, id string, revision int, request string) (SSHIssuer, error) {
	var out SSHIssuer
	if !sshcertificates.ValidID(id) || revision < 1 || request == "" {
		return out, sshcertificates.ErrInvalid
	}
	e := c.jobRequest(ctx, "POST", sshCertificateBase+"/issuers/"+id+"/activate", map[string]any{"revision": revision, "request_id": request}, &out)
	return out, e
}

func (c *Client) SSHIssuers(ctx context.Context) ([]SSHIssuer, error) {
	out := []SSHIssuer{}
	e := c.jobRequest(ctx, "GET", sshCertificateBase+"/issuers", nil, &out)
	return out, e
}
func (c *Client) SaveSSHIssuer(ctx context.Context, id string, in SSHIssuerInput) (SSHIssuer, error) {
	var out SSHIssuer
	if id != "" && !sshcertificates.ValidID(id) {
		return out, sshcertificates.ErrInvalid
	}
	in, e := sshcertificates.Prepare(in)
	if e != nil {
		return out, e
	}
	method, path := "POST", sshCertificateBase+"/issuers"
	if id != "" {
		method, path = "PUT", path+"/"+id
	}
	e = c.jobRequest(ctx, method, path, in, &out)
	return out, e
}
func (c *Client) RotateSSHIssuer(ctx context.Context, id string, revision int, request string) (SSHIssuer, error) {
	var out SSHIssuer
	if !sshcertificates.ValidID(id) || revision < 1 || request == "" {
		return out, sshcertificates.ErrInvalid
	}
	e := c.jobRequest(ctx, "POST", sshCertificateBase+"/issuers/"+id+"/rotate", map[string]any{"revision": revision, "request_id": request}, &out)
	return out, e
}
func (c *Client) DeleteSSHIssuer(ctx context.Context, id string, revision int, request string) error {
	if !sshcertificates.ValidID(id) || revision < 1 || request == "" {
		return sshcertificates.ErrInvalid
	}
	return c.jobRequest(ctx, "DELETE", sshCertificateBase+"/issuers/"+id, map[string]any{"revision": revision, "request_id": request}, nil)
}
func (c *Client) SSHCertificateBinding(ctx context.Context, id string) (SSHCertificateBindingDetails, error) {
	var out SSHCertificateBindingDetails
	if !sshcertificates.ValidAssetID(id) {
		return out, sshcertificates.ErrInvalid
	}
	e := c.jobRequest(ctx, "GET", sshCertificateBase+"/bindings/"+id, nil, &out)
	return out, e
}
func (c *Client) BindSSHCertificate(ctx context.Context, id string, in SSHCertificateBindingInput) (SSHCertificateBinding, error) {
	var out SSHCertificateBinding
	if !sshcertificates.ValidAssetID(id) || in.IssuerID != "" && !sshcertificates.ValidID(in.IssuerID) || in.Revision < 0 || in.RequestID == "" {
		return out, sshcertificates.ErrInvalid
	}
	e := c.jobRequest(ctx, "PUT", sshCertificateBase+"/bindings/"+id, in, &out)
	return out, e
}
func (c *Client) SSHCertificateAudit(ctx context.Context, offset, limit int) (SSHCertificateAuditPage, error) {
	var out SSHCertificateAuditPage
	if offset < 0 || limit < 1 || limit > 100 {
		return out, sshcertificates.ErrInvalid
	}
	e := c.jobRequest(ctx, "GET", fmt.Sprintf("%s/audit?offset=%d&limit=%d", sshCertificateBase, offset, limit), nil, &out)
	return out, e
}
