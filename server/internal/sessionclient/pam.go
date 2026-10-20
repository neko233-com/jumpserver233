package sessionclient

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/connector/pamtypes"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"net/url"
	"regexp"
)

type PAMPrincipal = pamtypes.Principal
type PAMSettings = assets.PAMSettings
type PAMDiscovery = assets.PAMDiscovery
type PAMImportInput = assets.PAMImportInput
type PAMImportPreview = assets.AccountImportPreview
type PAMImportReceipt = assets.AccountImportReceipt
type PAMPlatformInput struct {
	Platform  string `json:"platform"`
	Version   string `json:"version"`
	RequestID string `json:"request_id"`
}

var pamAssetID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

func pamAssetPath(id string) (string, error) {
	if !pamAssetID.MatchString(id) {
		return "", pamtypes.ErrInvalid
	}
	return "/api/v1/assets/" + url.PathEscape(id) + "/pam", nil
}
func (c *Client) PAMPrincipals(ctx context.Context, id string) (PAMDiscovery, error) {
	var out PAMDiscovery
	path, e := pamAssetPath(id)
	if e != nil {
		return out, e
	}
	e = c.jobRequest(ctx, "GET", path+"/principals", nil, &out)
	return out, e
}
func (c *Client) ConfigurePAMPlatform(ctx context.Context, id string, in PAMPlatformInput) (PAMImportReceipt, error) {
	var out PAMImportReceipt
	path, e := pamAssetPath(id)
	if e != nil {
		return out, e
	}
	e = c.jobRequest(ctx, "PUT", path+"/platform", in, &out)
	return out, e
}
func (c *Client) PreviewPAMImport(ctx context.Context, id string, in PAMImportInput) (PAMImportPreview, error) {
	var out PAMImportPreview
	path, e := pamAssetPath(id)
	if e != nil {
		return out, e
	}
	e = c.jobRequest(ctx, "POST", path+"/import-preview", in, &out)
	return out, e
}
func (c *Client) CommitPAMImport(ctx context.Context, id string, in PAMImportInput) (PAMImportReceipt, error) {
	var out PAMImportReceipt
	path, e := pamAssetPath(id)
	if e != nil {
		return out, e
	}
	e = c.jobRequest(ctx, "POST", path+"/import-commit", in, &out)
	return out, e
}
