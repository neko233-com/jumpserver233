package sessionclient

import (
	"context"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
	"net/url"
	"strconv"
	"strings"
)

type OperationSchedule = operations.Schedule
type OperationScheduleUpdate = operations.ScheduleUpdate
type OperationPreviewInput = operations.PreviewInput
type OperationPreview = operations.SchedulePreview
type OperationPlanInput = operations.PlanInput
type OperationPlan = operations.Plan
type OperationRun = operations.Run
type OperationTemplateInput = operations.TemplateInput
type OperationTemplate = operations.Template
type OperationEvent = operations.ScheduleEvent
type OperationRuns struct {
	Results []OperationRun `json:"results"`
	Total   int            `json:"total"`
}
type OperationPlans struct {
	Results []OperationPlan `json:"results"`
	Total   int             `json:"total"`
}

func (c *Client) OperationPlansPage(ctx context.Context, offset, limit int) (OperationPlans, error) {
	var out OperationPlans
	q, e := operationPage(offset, limit)
	if e != nil {
		return out, e
	}
	e = c.jobRequest(ctx, "GET", "/api/v1/ops/plans"+q, nil, &out)
	return out, e
}

type OperationEvents struct {
	Results []OperationEvent `json:"results"`
	Total   int              `json:"total"`
}

func validOperationID(id, prefix string) bool {
	if !strings.HasPrefix(id, prefix) || len(id) != len(prefix)+32 {
		return false
	}
	for _, c := range strings.TrimPrefix(id, prefix) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (c *Client) PreviewOperationSchedule(ctx context.Context, in OperationPreviewInput) (OperationPreview, error) {
	var out OperationPreview
	e := c.jobRequest(ctx, "POST", "/api/v1/ops/schedules/preview", in, &out)
	return out, e
}
func (c *Client) OperationPlans(ctx context.Context) ([]OperationPlan, error) {
	var out []OperationPlan
	e := c.jobRequest(ctx, "GET", "/api/v1/ops/plans", nil, &out)
	return out, e
}
func (c *Client) OperationPlan(ctx context.Context, id string) (OperationPlan, error) {
	var out OperationPlan
	if !validOperationID(id, "plan-") {
		return out, fmt.Errorf("invalid plan ID")
	}
	e := c.jobRequest(ctx, "GET", "/api/v1/ops/plans/"+url.PathEscape(id), nil, &out)
	return out, e
}
func (c *Client) CreateOperationPlan(ctx context.Context, in OperationPlanInput) (OperationPlan, error) {
	var out OperationPlan
	e := c.jobRequest(ctx, "POST", "/api/v1/ops/plans", in, &out)
	return out, e
}
func (c *Client) UpdateOperationSchedule(ctx context.Context, id string, in OperationScheduleUpdate) (OperationPlan, error) {
	var out OperationPlan
	if !validOperationID(id, "plan-") {
		return out, fmt.Errorf("invalid plan ID")
	}
	e := c.jobRequest(ctx, "PUT", "/api/v1/ops/plans/"+url.PathEscape(id)+"/schedule", in, &out)
	return out, e
}
func (c *Client) SetOperationPlanEnabled(ctx context.Context, id string, enabled bool, revision int) (OperationPlan, error) {
	var out OperationPlan
	if !validOperationID(id, "plan-") || revision < 1 {
		return out, fmt.Errorf("plan ID and revision required")
	}
	e := c.jobRequest(ctx, "PUT", "/api/v1/ops/plans/"+url.PathEscape(id), struct {
		Enabled  bool `json:"enabled"`
		Revision int  `json:"revision"`
	}{enabled, revision}, &out)
	return out, e
}
func operationPage(offset, limit int) (string, error) {
	if offset < 0 || limit < 1 || limit > 100 {
		return "", fmt.Errorf("invalid operation page")
	}
	return "?offset=" + strconv.Itoa(offset) + "&limit=" + strconv.Itoa(limit), nil
}
func (c *Client) OperationScheduleEvents(ctx context.Context, id string, offset, limit int) (OperationEvents, error) {
	var out OperationEvents
	q, e := operationPage(offset, limit)
	if e != nil {
		return out, e
	}
	if !validOperationID(id, "plan-") {
		return out, fmt.Errorf("invalid plan ID")
	}
	e = c.jobRequest(ctx, "GET", "/api/v1/ops/plans/"+url.PathEscape(id)+"/events"+q, nil, &out)
	return out, e
}
func (c *Client) OperationRuns(ctx context.Context, offset, limit int) (OperationRuns, error) {
	var out OperationRuns
	q, e := operationPage(offset, limit)
	if e != nil {
		return out, e
	}
	e = c.jobRequest(ctx, "GET", "/api/v1/ops/runs"+q, nil, &out)
	return out, e
}
func (c *Client) OperationRun(ctx context.Context, id string) (OperationRun, error) {
	var out OperationRun
	if !validOperationID(id, "run-") {
		return out, fmt.Errorf("invalid run ID")
	}
	e := c.jobRequest(ctx, "GET", "/api/v1/ops/runs/"+url.PathEscape(id), nil, &out)
	return out, e
}
func (c *Client) CancelOperationRun(ctx context.Context, id string) error {
	if !validOperationID(id, "run-") {
		return fmt.Errorf("invalid run ID")
	}
	return c.jobRequest(ctx, "POST", "/api/v1/ops/runs/"+url.PathEscape(id)+"/cancel", struct{}{}, nil)
}
func (c *Client) OperationTemplates(ctx context.Context) ([]OperationTemplate, error) {
	var out []OperationTemplate
	e := c.jobRequest(ctx, "GET", "/api/v1/ops/templates", nil, &out)
	return out, e
}
func (c *Client) SaveOperationTemplate(ctx context.Context, id string, in OperationTemplateInput) (OperationTemplate, error) {
	var out OperationTemplate
	method, path := "POST", "/api/v1/ops/templates"
	if id != "" {
		if !validOperationID(id, "template-") {
			return out, fmt.Errorf("invalid template ID")
		}
		method = "PUT"
		path += "/" + url.PathEscape(id)
	}
	e := c.jobRequest(ctx, method, path, in, &out)
	return out, e
}
func (c *Client) DeleteOperationTemplate(ctx context.Context, id string, revision int) error {
	if !validOperationID(id, "template-") || revision < 1 {
		return fmt.Errorf("template ID and revision required")
	}
	return c.jobRequest(ctx, "DELETE", "/api/v1/ops/templates/"+url.PathEscape(id)+"?revision="+strconv.Itoa(revision), nil, nil)
}
