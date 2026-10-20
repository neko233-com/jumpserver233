package sessionclient

import (
	"context"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/core/credentialpolicy"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Rotation plan DTOs deliberately contain metadata only.
type RotationSelection struct {
	AccountID   string `json:"account_id"`
	CollectorID string `json:"collector_id,omitempty"`
}
type RotationRef struct {
	AssetID           string `json:"asset_id"`
	AccountID         string `json:"account_id"`
	AssetName         string `json:"asset_name"`
	Username          string `json:"username"`
	CredentialType    string `json:"credential_type"`
	CollectorID       string `json:"collector_id,omitempty"`
	CollectorUsername string `json:"collector_username,omitempty"`
}
type RotationPlanInput struct {
	PasswordMode   string                 `json:"password_mode,omitempty"`
	PasswordPolicy credentialpolicy.Rules `json:"password_policy,omitzero"`
	Name           string                 `json:"name"`
	Targets        []RotationSelection    `json:"targets,omitempty"`
	Kind           string                 `json:"kind"`
	Enabled        bool                   `json:"enabled"`
	RunAt          time.Time              `json:"run_at,omitzero"`
	IntervalHours  int                    `json:"interval_hours,omitempty"`
	OnlyDue        bool                   `json:"only_due"`
	Revision       int                    `json:"revision"`
}

// Request-only: fixed_password is never part of RotationPlan or RotationRun.
type RotationPlanSaveInput struct {
	RotationPlanInput
	RequestID     string `json:"request_id,omitempty"`
	FixedPassword string `json:"fixed_password,omitempty"`
}
type RotationOrigin struct {
	SourceIP string `json:"source_ip"`
	Method   string `json:"method"`
}
type RotationPlan struct {
	SaveRequestID string `json:"save_request_id,omitempty"`
	RotationPlanInput
	ID           string             `json:"id"`
	Owner        AccountImportActor `json:"owner"`
	TargetCount  int                `json:"target_count"`
	Accounts     []RotationRef      `json:"accounts"`
	NextRun      time.Time          `json:"next_run,omitzero"`
	LastRunID    string             `json:"last_run_id,omitempty"`
	ErrorCode    string             `json:"error_code,omitempty"`
	CreatedAt    time.Time          `json:"created_at"`
	UpdatedAt    time.Time          `json:"updated_at"`
	AccessOrigin RotationOrigin     `json:"access_origin"`
}
type RotationItem struct {
	RotationRef
	SourceItemID   string    `json:"source_item_id,omitempty"`
	RetryRunID     string    `json:"retry_run_id,omitempty"`
	ID             string    `json:"id"`
	State          string    `json:"state"`
	ErrorCode      string    `json:"error_code,omitempty"`
	LinkedTo       string    `json:"linked_to,omitempty"`
	BeforeRevision uint64    `json:"before_revision"`
	AfterRevision  uint64    `json:"after_revision,omitempty"`
	StartedAt      time.Time `json:"started_at,omitzero"`
	FinishedAt     time.Time `json:"finished_at,omitzero"`
}
type RotationRun struct {
	ParentRunID    string                 `json:"parent_run_id,omitempty"`
	RetryItemIDs   []string               `json:"retry_item_ids,omitempty"`
	RetryAll       bool                   `json:"retry_all,omitempty"`
	PasswordMode   string                 `json:"password_mode,omitempty"`
	PasswordPolicy credentialpolicy.Rules `json:"password_policy,omitzero"`
	ID             string                 `json:"id"`
	PlanID         string                 `json:"plan_id"`
	PlanRevision   int                    `json:"plan_revision"`
	Name           string                 `json:"name"`
	Owner          AccountImportActor     `json:"owner"`
	RequestID      string                 `json:"request_id"`
	Scheduled      bool                   `json:"scheduled"`
	Cancelled      bool                   `json:"cancelled"`
	State          string                 `json:"state"`
	CreatedAt      time.Time              `json:"created_at"`
	FinishedAt     time.Time              `json:"finished_at,omitzero"`
	Items          []RotationItem         `json:"items"`
	Total          int                    `json:"total,omitempty"`
	Succeeded      int                    `json:"succeeded,omitempty"`
	Failed         int                    `json:"failed,omitempty"`
	Skipped        int                    `json:"skipped,omitempty"`
	AccessOrigin   RotationOrigin         `json:"access_origin"`
}
type RotationAudit struct {
	ParentRunID string             `json:"parent_run_id,omitempty"`
	Origin      RotationOrigin     `json:"access_origin,omitempty"`
	At          time.Time          `json:"at"`
	Actor       AccountImportActor `json:"actor"`
	Action      string             `json:"action"`
	PlanID      string             `json:"plan_id"`
	RunID       string             `json:"run_id,omitempty"`
	Revision    int                `json:"revision,omitempty"`
}
type RotationPage[T any] struct {
	Results []T `json:"results"`
	Total   int `json:"total"`
}

func rotationPaging(offset, limit int) string {
	return "offset=" + strconv.Itoa(offset) + "&limit=" + strconv.Itoa(limit)
}
func (c *Client) RotationTargets(ctx context.Context, q, collectorFor string, offset, limit int) (RotationPage[RotationRef], error) {
	var out RotationPage[RotationRef]
	e := c.jobRequest(ctx, "GET", "/api/v1/accounts/rotation-targets?"+rotationPaging(offset, limit)+"&q="+url.QueryEscape(q)+"&collector_for="+url.QueryEscape(collectorFor), nil, &out)
	return out, e
}
func (c *Client) RotationPlans(ctx context.Context, offset, limit int) (RotationPage[RotationPlan], error) {
	var out RotationPage[RotationPlan]
	e := c.jobRequest(ctx, "GET", "/api/v1/accounts/rotation-plans?"+rotationPaging(offset, limit), nil, &out)
	return out, e
}
func (c *Client) RotationPlan(ctx context.Context, id string) (RotationPlan, error) {
	var out RotationPlan
	e := c.jobRequest(ctx, "GET", "/api/v1/accounts/rotation-plans/"+url.PathEscape(id), nil, &out)
	return out, e
}
func (c *Client) SaveRotationPlan(ctx context.Context, id string, in RotationPlanInput) (RotationPlan, error) {
	return c.SaveRotationPlanRequest(ctx, id, RotationPlanSaveInput{RotationPlanInput: in})
}
func (c *Client) SaveRotationPlanRequest(ctx context.Context, id string, in RotationPlanSaveInput) (RotationPlan, error) {
	var out RotationPlan
	method, path := "POST", "/api/v1/accounts/rotation-plans"
	if id != "" {
		method = "PUT"
		path += "/" + url.PathEscape(id)
	}
	e := c.jobRequest(ctx, method, path, in, &out)
	return out, e
}
func (c *Client) DeleteRotationPlan(ctx context.Context, id string, revision int) error {
	return c.jobRequest(ctx, "DELETE", "/api/v1/accounts/rotation-plans/"+url.PathEscape(id)+"?revision="+strconv.Itoa(revision), nil, nil)
}
func (c *Client) RunRotationPlan(ctx context.Context, id, requestID string) (RotationRun, error) {
	var out RotationRun
	e := c.jobRequest(ctx, "POST", "/api/v1/accounts/rotation-plans/"+url.PathEscape(id)+"/runs", map[string]string{"request_id": requestID}, &out)
	return out, e
}
func (c *Client) RotationRuns(ctx context.Context, planID string, offset, limit int) (RotationPage[RotationRun], error) {
	var out RotationPage[RotationRun]
	e := c.jobRequest(ctx, "GET", "/api/v1/accounts/rotation-runs?"+rotationPaging(offset, limit)+"&plan_id="+url.QueryEscape(planID), nil, &out)
	return out, e
}
func (c *Client) RotationRun(ctx context.Context, id string) (RotationRun, error) {
	var out RotationRun
	e := c.jobRequest(ctx, "GET", "/api/v1/accounts/rotation-runs/"+url.PathEscape(id), nil, &out)
	return out, e
}
func (c *Client) CancelRotationRun(ctx context.Context, id string) error {
	return c.jobRequest(ctx, "POST", "/api/v1/accounts/rotation-runs/"+url.PathEscape(id)+"/cancel", nil, nil)
}
func (c *Client) RecoverRotationRun(ctx context.Context, id string) error {
	return c.jobRequest(ctx, "POST", "/api/v1/accounts/rotation-runs/"+url.PathEscape(id)+"/recover", nil, nil)
}

type RotationRetryInput struct {
	RequestID    string   `json:"request_id"`
	PlanRevision int      `json:"plan_revision"`
	ItemIDs      []string `json:"item_ids,omitempty"`
}

func (c *Client) RetryRotationRun(ctx context.Context, id string, in RotationRetryInput) (RotationRun, error) {
	var out RotationRun
	e := c.jobRequest(ctx, "POST", "/api/v1/accounts/rotation-runs/"+url.PathEscape(id)+"/retry", in, &out)
	return out, e
}
func (c *Client) RotationAudit(ctx context.Context, offset, limit int) (RotationPage[RotationAudit], error) {
	var out RotationPage[RotationAudit]
	e := c.jobRequest(ctx, "GET", "/api/v1/accounts/rotation-audit?"+rotationPaging(offset, limit), nil, &out)
	return out, e
}
func (c *Client) ExportRotationRun(ctx context.Context, id string) ([]byte, error) {
	endpoint := *c.serverURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/api/v1/accounts/rotation-runs/" + url.PathEscape(id) + "/export"
	req, e := http.NewRequestWithContext(ctx, "GET", endpoint.String(), nil)
	if e != nil {
		return nil, e
	}
	if e = c.authorizeRequest(req); e != nil {
		return nil, e
	}
	resp, e := c.http.Do(req)
	if e != nil {
		return nil, fmt.Errorf("rotation export request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, &APIError{StatusCode: resp.StatusCode, Detail: "rotation export rejected"}
	}
	if resp.Header.Get("Content-Type") != "text/csv; charset=utf-8" {
		return nil, fmt.Errorf("invalid rotation export response")
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, (8<<20)+1))
	if e != nil || len(raw) > 8<<20 {
		return nil, fmt.Errorf("rotation export is too large")
	}
	return raw, nil
}
