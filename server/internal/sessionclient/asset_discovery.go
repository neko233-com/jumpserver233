package sessionclient

import (
	"context"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/core/assetdiscovery"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type DiscoveryPage[T any] struct {
	Results []T `json:"results"`
	Total   int `json:"total"`
}

func (c *Client) DiscoverySources(ctx context.Context) (DiscoveryPage[assetdiscovery.Source], error) {
	var out DiscoveryPage[assetdiscovery.Source]
	e := c.jobRequest(ctx, "GET", "/api/v1/asset-discovery/sources", nil, &out)
	return out, e
}
func (c *Client) DiscoverySource(ctx context.Context, id string) (assetdiscovery.Source, error) {
	var out assetdiscovery.Source
	e := c.jobRequest(ctx, "GET", "/api/v1/asset-discovery/sources/"+url.PathEscape(id), nil, &out)
	return out, e
}
func (c *Client) SaveDiscoverySource(ctx context.Context, id string, in assetdiscovery.SourceInput) (assetdiscovery.Source, error) {
	var out assetdiscovery.Source
	method, path := "POST", "/api/v1/asset-discovery/sources"
	if id != "" {
		method = "PUT"
		path += "/" + url.PathEscape(id)
	}
	e := c.jobRequest(ctx, method, path, in, &out)
	return out, e
}
func (c *Client) DeleteDiscoverySource(ctx context.Context, id string, revision int) error {
	return c.jobRequest(ctx, "DELETE", fmt.Sprintf("/api/v1/asset-discovery/sources/%s?revision=%d", url.PathEscape(id), revision), nil, nil)
}
func (c *Client) DiscoveryPolicies(ctx context.Context) (DiscoveryPage[assetdiscovery.Policy], error) {
	var out DiscoveryPage[assetdiscovery.Policy]
	e := c.jobRequest(ctx, "GET", "/api/v1/asset-discovery/policies", nil, &out)
	return out, e
}
func (c *Client) SaveDiscoveryPolicy(ctx context.Context, id string, in assetdiscovery.PolicyInput) (assetdiscovery.Policy, error) {
	var out assetdiscovery.Policy
	method, path := "POST", "/api/v1/asset-discovery/policies"
	if id != "" {
		method = "PUT"
		path += "/" + url.PathEscape(id)
	}
	e := c.jobRequest(ctx, method, path, in, &out)
	return out, e
}
func (c *Client) DeleteDiscoveryPolicy(ctx context.Context, id string, revision int) error {
	return c.jobRequest(ctx, "DELETE", fmt.Sprintf("/api/v1/asset-discovery/policies/%s?revision=%d", url.PathEscape(id), revision), nil, nil)
}
func (c *Client) StartDiscoveryRun(ctx context.Context, in assetdiscovery.RunInput) (assetdiscovery.Run, error) {
	var out assetdiscovery.Run
	e := c.jobRequest(ctx, "POST", "/api/v1/asset-discovery/runs", in, &out)
	return out, e
}
func (c *Client) DiscoveryRun(ctx context.Context, id string) (assetdiscovery.Run, error) {
	var out assetdiscovery.Run
	e := c.jobRequest(ctx, "GET", "/api/v1/asset-discovery/runs/"+url.PathEscape(id), nil, &out)
	return out, e
}
func (c *Client) CancelDiscoveryRun(ctx context.Context, id string) (assetdiscovery.Run, error) {
	var out assetdiscovery.Run
	e := c.jobRequest(ctx, "POST", "/api/v1/asset-discovery/runs/"+url.PathEscape(id)+"/cancel", nil, &out)
	return out, e
}
func (c *Client) DiscoveryRuns(ctx context.Context, source string, offset, limit int) (DiscoveryPage[assetdiscovery.Run], error) {
	var out DiscoveryPage[assetdiscovery.Run]
	e := c.discoveryPage(ctx, "runs", source, offset, limit, &out)
	return out, e
}
func (c *Client) DiscoveryFindings(ctx context.Context, source string, offset, limit int) (DiscoveryPage[assetdiscovery.Finding], error) {
	var out DiscoveryPage[assetdiscovery.Finding]
	e := c.discoveryPage(ctx, "findings", source, offset, limit, &out)
	return out, e
}
func (c *Client) DiscoveryAudit(ctx context.Context, offset, limit int) (DiscoveryPage[assetdiscovery.Audit], error) {
	var out DiscoveryPage[assetdiscovery.Audit]
	e := c.discoveryPage(ctx, "audit", "", offset, limit, &out)
	return out, e
}
func (c *Client) discoveryPage(ctx context.Context, kind, source string, offset, limit int, out any) error {
	if offset < 0 || offset > 100000 || limit < 1 || limit > 500 {
		return assetdiscovery.ErrInvalid
	}
	return c.jobRequest(ctx, "GET", fmt.Sprintf("/api/v1/asset-discovery/%s?source_id=%s&offset=%d&limit=%d", kind, url.QueryEscape(source), offset, limit), nil, out)
}
func (c *Client) PreviewDiscoveryImport(ctx context.Context, in assetdiscovery.PreviewInput) (assetdiscovery.Preview, error) {
	var out assetdiscovery.Preview
	e := c.jobRequest(ctx, "POST", "/api/v1/asset-discovery/import-preview", in, &out)
	return out, e
}
func (c *Client) ImportDiscoveryAssets(ctx context.Context, in assetdiscovery.ImportInput) (assetdiscovery.ImportResult, error) {
	var out assetdiscovery.ImportResult
	e := c.jobRequest(ctx, "POST", "/api/v1/asset-discovery/import", in, &out)
	return out, e
}
func (c *Client) ExportDiscoveryFindings(ctx context.Context, source string, w io.Writer) error {
	endpoint := *c.serverURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/api/v1/asset-discovery/findings.csv"
	endpoint.RawQuery = "source_id=" + url.QueryEscape(source)
	request, e := http.NewRequestWithContext(ctx, "GET", endpoint.String(), nil)
	if e != nil {
		return e
	}
	if e = c.authorizeRequest(request); e != nil {
		return e
	}
	response, e := c.http.Do(request)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("discovery export HTTP %d", response.StatusCode)
	}
	_, e = io.Copy(w, io.LimitReader(response.Body, 16<<20))
	return e
}
