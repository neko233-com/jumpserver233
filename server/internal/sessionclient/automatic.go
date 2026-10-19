package sessionclient

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/releasebundle"
)

const automaticPath = "/api/v1/settings/security/updates/installation/automatic"

func (c *Client) AutomaticUpdateStatus(ctx context.Context) (releasebundle.AutomaticState, error) {
	var v releasebundle.AutomaticState
	e := c.jobRequest(ctx, "GET", automaticPath, nil, &v)
	return v, e
}
func (c *Client) SaveAutomaticUpdatePolicy(ctx context.Context, in releasebundle.AutomaticPolicyInput) (releasebundle.AutomaticState, error) {
	var v releasebundle.AutomaticState
	e := c.jobRequest(ctx, "PUT", automaticPath, in, &v)
	return v, e
}
