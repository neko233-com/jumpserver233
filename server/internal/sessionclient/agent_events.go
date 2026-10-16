package sessionclient

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/agentevents"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
	"net/http"
	"net/url"
	"strconv"
)

func (c *Client) AgentEvents(ctx context.Context, assetID string, before uint64) (agentevents.Page, error) {
	var v agentevents.Page
	path := "/api/v1/audit/agent-events"
	if assetID != "" {
		path = "/api/v1/assets/" + url.PathEscape(assetID) + "/agent-events"
	}
	e := c.jobRequest(ctx, http.MethodGet, path+"?limit=50&before="+strconv.FormatUint(before, 10), nil, &v)
	return v, e
}
func (c *Client) AgentCollection(ctx context.Context, assetID string) ([]operations.Plan, error) {
	var v []operations.Plan
	e := c.jobRequest(ctx, http.MethodGet, "/api/v1/assets/"+url.PathEscape(assetID)+"/agent-events/collection", nil, &v)
	return v, e
}
func (c *Client) SetAgentCollection(ctx context.Context, assetID string, enabled bool, interval int, requestID string) error {
	return c.jobRequest(ctx, http.MethodPost, "/api/v1/assets/"+url.PathEscape(assetID)+"/agent-events/collection", map[string]any{"enabled": enabled, "interval_seconds": interval, "request_id": requestID}, nil)
}
