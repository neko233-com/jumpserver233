package sessionclient

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"net/http"
	"net/url"
)

type PluginRequest struct {
	Action         string                        `json:"action"`
	RequestID      string                        `json:"request_id"`
	TimeoutSeconds int                           `json:"timeout_seconds"`
	ReviewID       string                        `json:"review_id,omitempty"`
	Version        string                        `json:"version,omitempty"`
	Protection     *hostplugins.ProtectionPolicy `json:"protection,omitempty"`
}

func (c *Client) HostPlugins(ctx context.Context) ([]hostplugins.Definition, error) {
	var result []hostplugins.Definition
	e := c.jobRequest(ctx, http.MethodGet, "/api/v1/host-plugins", nil, &result)
	return result, e
}
func (c *Client) SubmitPlugin(ctx context.Context, assetID, pluginID string, input PluginRequest) (jobs.Job, error) {
	var result jobs.Job
	e := c.jobRequest(ctx, http.MethodPost, "/api/v1/assets/"+url.PathEscape(assetID)+"/host-plugins/"+url.PathEscape(pluginID)+"/jobs", input, &result)
	return result, e
}
