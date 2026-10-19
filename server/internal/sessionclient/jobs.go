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

type APIError struct {
	StatusCode int
	Detail     string
}

func (e *APIError) Error() string { return "SSH job API: " + e.Detail }

func (c *Client) SubmitJob(ctx context.Context, input jobs.Input) (jobs.Job, error) {
	var result jobs.Job
	if c.managedAccount != "" {
		if _, e := jobs.Validate(input); e != nil {
			return result, e
		}
		id, e := c.selectedAsset(ctx, input.AssetID)
		if e != nil {
			return result, e
		}
		input.AssetID = id
	}
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
	if c.platformNotifications && strings.HasPrefix(path, "/api/v1/notifications/") {
		path = strings.Replace(path, "/api/v1/notifications/", "/api/v1/platform-notifications/", 1)
	}
	path, selectionErr := c.selectedAccountPath(ctx, path)
	if selectionErr != nil {
		return selectionErr
	}
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
	if resp.StatusCode == http.StatusAccepted && !strings.Contains(target.Path, "/remote-account-tasks") && !strings.HasPrefix(target.Path, "/api/v1/asset-discovery/") && !strings.HasPrefix(target.Path, "/api/v1/accounts/rotation-") {
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
			Detail string         `json:"detail"`
			Code   string         `json:"error_code"`
			Issue  *PlaybookIssue `json:"issue"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&problem)
		if strings.HasPrefix(target.Path, "/api/v1/ops/playbooks") && problem.Code == "playbook_invalid" {
			return &PlaybookValidationError{Issue: problem.Issue}
		}
		if problem.Detail == "" && strings.Contains(target.Path, "/remote-account-tasks") {
			switch problem.Code {
			case "invalid", "not_found", "pending", "referenced", "conflict", "capacity", "denied", "unavailable":
				problem.Detail = problem.Code
			}
		}
		if problem.Detail == "" && (strings.HasPrefix(target.Path, "/api/v1/accounts/imports") || strings.HasPrefix(target.Path, "/api/v1/accounts/risks") || strings.HasPrefix(target.Path, "/api/v1/accounts/rotation-")) {
			switch problem.Code {
			case "invalid", "denied", "not_found", "conflict", "expired", "capacity", "unavailable", "busy":
				problem.Detail = problem.Code
			}
		}
		if problem.Detail == "" {
			if strings.HasPrefix(target.Path, "/api/v1/notifications/") || strings.HasPrefix(target.Path, "/api/v1/platform-notifications/") || strings.HasPrefix(target.Path, "/api/v1/audits/logins") || strings.HasPrefix(target.Path, "/api/v1/reports/") {
				switch problem.Code {
				case "invalid", "denied", "not_found", "conflict", "verification_required", "rate_limit", "capacity", "unavailable":
					problem.Detail = problem.Code
				}
			}
		}
		if problem.Detail == "" {
			if strings.HasPrefix(target.Path, "/api/v1/tickets/") {
				switch problem.Code {
				case "invalid", "denied", "not_found", "conflict", "source_changed", "reviewers_unavailable", "capacity", "unavailable":
					problem.Detail = problem.Code
				}
			}
		}
		if problem.Detail == "" {
			problem.Detail = resp.Status
		}
		return &APIError{StatusCode: resp.StatusCode, Detail: problem.Detail}
	}
	if output != nil {
		limit := int64(1024 * 1024)
		if strings.HasPrefix(target.Path, "/api/v1/ops/") {
			limit = 16 << 20
		}
		if strings.HasPrefix(target.Path, "/api/v1/accounts/risks") || strings.HasPrefix(target.Path, "/api/v1/accounts/rotation-") || strings.HasPrefix(target.Path, "/api/v1/tickets/") {
			limit = 8 << 20
		}
		return json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(output)
	}
	return nil
}
