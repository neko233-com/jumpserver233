package sessionclient

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/updates"
)

const updatesPath = "/api/v1/settings/security/updates"

func (c *Client) UpdateStatus(ctx context.Context) (updates.Status, error) {
	var out updates.Status
	e := c.jobRequest(ctx, "GET", updatesPath, nil, &out)
	return out, e
}
func (c *Client) SaveUpdateSettings(ctx context.Context, in updates.Settings) (updates.Status, error) {
	var out updates.Status
	e := c.jobRequest(ctx, "PUT", updatesPath, in, &out)
	return out, e
}
func (c *Client) CheckUpdates(ctx context.Context, revision int, id string) (updates.Status, error) {
	var out updates.Status
	e := c.jobRequest(ctx, "POST", updatesPath+"/check", map[string]any{"revision": revision, "request_id": id}, &out)
	return out, e
}
func (c *Client) UpdateAudit(ctx context.Context) ([]updates.Audit, error) {
	out := []updates.Audit{}
	e := c.jobRequest(ctx, "GET", updatesPath+"/audit", nil, &out)
	return out, e
}
