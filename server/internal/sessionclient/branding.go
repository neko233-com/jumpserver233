package sessionclient

import (
	"context"
	"fmt"

	"github.com/neko233-com/jumpserver233/server/internal/core/branding"
)

type BrandingSettings = branding.Public
type BrandingInput = branding.Input
type BrandingConfiguration struct {
	Settings branding.Public        `json:"settings"`
	Themes   []branding.ThemeOption `json:"themes"`
}
type BrandingAuditPage struct {
	Results []branding.Audit `json:"results"`
	Total   int              `json:"total"`
}

func (c *Client) Branding(ctx context.Context) (BrandingConfiguration, error) {
	var out BrandingConfiguration
	e := c.jobRequest(ctx, "GET", "/api/v1/settings/branding", nil, &out)
	return out, e
}
func (c *Client) SaveBranding(ctx context.Context, in BrandingInput) (BrandingSettings, error) {
	var out BrandingSettings
	normalized, e := branding.Prepare(in)
	if e != nil {
		return out, e
	}
	e = c.jobRequest(ctx, "PUT", "/api/v1/settings/branding", normalized, &out)
	return out, e
}
func (c *Client) BrandingAudit(ctx context.Context, offset, limit int) (BrandingAuditPage, error) {
	var out BrandingAuditPage
	if offset < 0 || offset > 100000 || limit < 1 || limit > 100 {
		return out, branding.ErrInvalid
	}
	e := c.jobRequest(ctx, "GET", fmt.Sprintf("/api/v1/settings/branding/audit?offset=%d&limit=%d", offset, limit), nil, &out)
	return out, e
}
