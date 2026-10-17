package sessionclient

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/neko233-com/jumpserver233/server/internal/core/accountdiscovery"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
)

type AccountDiscoveryRequest struct {
	RequestID string `json:"request_id"`
	ReviewID  string `json:"review_id,omitempty"`
	Timeout   int    `json:"timeout_seconds"`
}

func (c *Client) DiscoverAccounts(ctx context.Context, asset string, in AccountDiscoveryRequest) (jobs.Job, error) {
	var out jobs.Job
	e := c.jobRequest(ctx, http.MethodPost, "/api/v1/assets/"+url.PathEscape(asset)+"/account-discovery/jobs", in, &out)
	return out, e
}
func (c *Client) DiscoveredAccounts(ctx context.Context, asset string, offset, limit int) (accountdiscovery.Page, error) {
	var out accountdiscovery.Page
	e := c.jobRequest(ctx, http.MethodGet, "/api/v1/assets/"+url.PathEscape(asset)+"/discovered-accounts?offset="+strconv.Itoa(offset)+"&limit="+strconv.Itoa(limit), nil, &out)
	return out, e
}
func (c *Client) ReviewDiscoveredAccount(ctx context.Context, asset, id, state, note string, revision int) (accountdiscovery.Finding, error) {
	var out accountdiscovery.Finding
	e := c.jobRequest(ctx, http.MethodPut, "/api/v1/assets/"+url.PathEscape(asset)+"/discovered-accounts/"+url.PathEscape(id), map[string]any{"review": state, "note": note, "revision": revision}, &out)
	return out, e
}
func (c *Client) AccountDiscoveryAudit(ctx context.Context, asset string, offset, limit int) (any, error) {
	var out any
	e := c.jobRequest(ctx, http.MethodGet, "/api/v1/assets/"+url.PathEscape(asset)+"/discovered-accounts/audit?offset="+strconv.Itoa(offset)+"&limit="+strconv.Itoa(limit), nil, &out)
	return out, e
}
