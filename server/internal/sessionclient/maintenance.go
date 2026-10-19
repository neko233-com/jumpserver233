package sessionclient

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/servicemaintenance"
)

const maintenancePath = "/api/v1/settings/security/maintenance"

func (c *Client) MaintenanceStatus(ctx context.Context) (servicemaintenance.Status, error) {
	var out servicemaintenance.Status
	e := c.jobRequest(ctx, "GET", maintenancePath, nil, &out)
	return out, e
}
func (c *Client) SetMaintenance(ctx context.Context, in servicemaintenance.Input) (servicemaintenance.Status, error) {
	var out servicemaintenance.Status
	e := c.jobRequest(ctx, "PUT", maintenancePath, in, &out)
	return out, e
}
