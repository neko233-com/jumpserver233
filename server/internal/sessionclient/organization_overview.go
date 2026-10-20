package sessionclient

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
	"strconv"
)

type OrganizationOverview = organizations.Overview

func (c *Client) OrganizationOverview(ctx context.Context, includeArchived bool) (OrganizationOverview, error) {
	var out OrganizationOverview
	err := c.jobRequest(ctx, "GET", "/api/v1/organizations/overview?include_archived="+strconv.FormatBool(includeArchived), nil, &out)
	return out, err
}
