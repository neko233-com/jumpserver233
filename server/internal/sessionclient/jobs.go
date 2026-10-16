package sessionclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
)

func (c *Client) SubmitJob(ctx context.Context, input jobs.Input) (jobs.Job, error) {
	var result jobs.Job
	err := c.jobRequest(ctx, http.MethodPost, "/api/v1/ops/jobs", input, &result)
	return result, err
}
func (c *Client) GetJob(ctx context.Context, id string) (jobs.Job, error) {
	var result jobs.Job
	err := c.jobRequest(ctx, http.MethodGet, "/api/v1/ops/jobs/"+url.PathEscape(id), nil, &result)
	return result, err
}
func (c *Client) CancelJob(ctx context.Context, id string) error {
	return c.jobRequest(ctx, http.MethodDelete, "/api/v1/ops/jobs/"+url.PathEscape(id), nil, nil)
}
func (c *Client) jobRequest(ctx context.Context, method, path string, input, output any) error {
	endpoint := *c.serverURL
	target, err := url.Parse(path)
	if err != nil || target.IsAbs() || target.Host != "" {
		return fmt.Errorf("invalid API path")
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + target.Path
	endpoint.RawQuery = target.RawQuery
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = strings.NewReader(string(data))
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return err
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if err = c.authorizeRequest(req); err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("SSH job API request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusAccepted {
		var pending struct {
			ReviewID string `json:"review_id"`
		}
		if json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&pending) != nil || pending.ReviewID == "" {
			return fmt.Errorf("invalid login review response")
		}
		return &AccessReviewPendingError{ReviewID: pending.ReviewID}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var problem struct {
			Detail string `json:"detail"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&problem)
		if problem.Detail == "" {
			problem.Detail = resp.Status
		}
		return fmt.Errorf("SSH job API: %s", problem.Detail)
	}
	if output != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 1024*1024)).Decode(output)
	}
	return nil
}
