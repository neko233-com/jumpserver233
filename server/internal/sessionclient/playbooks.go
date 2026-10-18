package sessionclient

import (
	"context"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
	"github.com/neko233-com/jumpserver233/server/internal/core/playbooks"
	"net/url"
	"strconv"
	"strings"
)

type PlaybookInput = operations.PlaybookInput
type Playbook = operations.Playbook
type PlaybookDetail = operations.PlaybookDetail
type PlaybookWorkspace = playbooks.Workspace
type PlaybookProgram = playbooks.Program
type PlaybookStepOutput = operations.LocalEvidence
type PlaybookIssue = playbooks.Issue
type PlaybookPage struct {
	Results []Playbook `json:"results"`
	Total   int        `json:"total"`
}
type PlaybookEventPage struct {
	Results []operations.PlaybookEvent `json:"results"`
	Total   int                        `json:"total"`
}
type PlaybookValidation struct {
	Valid     bool   `json:"valid"`
	ProgramID string `json:"program_id"`
	MaxSteps  int    `json:"max_steps"`
	Tasks     []struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Module  string `json:"module"`
		File    string `json:"file"`
		Line    int    `json:"line"`
		Handler bool   `json:"handler"`
	} `json:"tasks"`
}
type PlaybookValidationError struct{ Issue *PlaybookIssue }

func (e *PlaybookValidationError) Error() string {
	if e.Issue == nil {
		return "invalid native Playbook"
	}
	return fmt.Sprintf("invalid native Playbook: %s (%s:%d:%d)", e.Issue.Code, e.Issue.File, e.Issue.Line, e.Issue.Column)
}
func (c *Client) ValidatePlaybook(ctx context.Context, in PlaybookWorkspace) (PlaybookValidation, error) {
	var out PlaybookValidation
	e := c.jobRequest(ctx, "POST", "/api/v1/ops/playbooks/validate", in, &out)
	return out, e
}
func (c *Client) Playbooks(ctx context.Context, offset, limit int) (PlaybookPage, error) {
	var out PlaybookPage
	q, e := operationPage(offset, limit)
	if e != nil {
		return out, e
	}
	e = c.jobRequest(ctx, "GET", "/api/v1/ops/playbooks"+q, nil, &out)
	return out, e
}
func (c *Client) Playbook(ctx context.Context, id string) (PlaybookDetail, error) {
	var out PlaybookDetail
	if !validOperationID(id, "playbook-") {
		return out, fmt.Errorf("invalid Playbook ID")
	}
	e := c.jobRequest(ctx, "GET", "/api/v1/ops/playbooks/"+url.PathEscape(id), nil, &out)
	return out, e
}
func (c *Client) SavePlaybook(ctx context.Context, id string, in PlaybookInput) (PlaybookDetail, error) {
	var out PlaybookDetail
	method, path := "POST", "/api/v1/ops/playbooks"
	if id != "" {
		if !validOperationID(id, "playbook-") {
			return out, fmt.Errorf("invalid Playbook ID")
		}
		method = "PUT"
		path += "/" + url.PathEscape(id)
	}
	e := c.jobRequest(ctx, method, path, in, &out)
	return out, e
}
func (c *Client) DeletePlaybook(ctx context.Context, id string, revision int) error {
	if !validOperationID(id, "playbook-") || revision < 1 {
		return fmt.Errorf("Playbook ID and revision required")
	}
	return c.jobRequest(ctx, "DELETE", "/api/v1/ops/playbooks/"+url.PathEscape(id)+"?revision="+strconv.Itoa(revision), nil, nil)
}
func (c *Client) PlaybookEvents(ctx context.Context, id string, offset, limit int) (PlaybookEventPage, error) {
	var out PlaybookEventPage
	if !validOperationID(id, "playbook-") {
		return out, fmt.Errorf("invalid Playbook ID")
	}
	q, e := operationPage(offset, limit)
	if e != nil {
		return out, e
	}
	e = c.jobRequest(ctx, "GET", "/api/v1/ops/playbooks/"+url.PathEscape(id)+"/events"+q, nil, &out)
	return out, e
}
func (c *Client) OperationProgram(ctx context.Context, id string) (PlaybookProgram, error) {
	var out PlaybookProgram
	if !validOperationID(id, "run-") {
		return out, fmt.Errorf("invalid run ID")
	}
	e := c.jobRequest(ctx, "GET", "/api/v1/ops/runs/"+url.PathEscape(id)+"/program", nil, &out)
	return out, e
}
func workflowAssetID(id string) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
func (c *Client) OperationStepOutput(ctx context.Context, run, asset, step string) (PlaybookStepOutput, error) {
	var out PlaybookStepOutput
	if !validOperationID(run, "run-") || !workflowAssetID(asset) || !validOperationID(step, "step-") {
		return out, fmt.Errorf("run, asset and step IDs required")
	}
	e := c.jobRequest(ctx, "GET", "/api/v1/ops/runs/"+url.PathEscape(run)+"/steps/"+url.PathEscape(asset)+"/"+url.PathEscape(step), nil, &out)
	return out, e
}
func (c *Client) TriggerOperationPlan(ctx context.Context, id, requestID string) (OperationRun, error) {
	var out OperationRun
	if !validOperationID(id, "plan-") || requestID == "" || len(requestID) > 100 || strings.ContainsAny(requestID, "\x00\r\n") {
		return out, fmt.Errorf("plan ID and unique request ID required")
	}
	e := c.jobRequest(ctx, "POST", "/api/v1/ops/plans/"+url.PathEscape(id)+"/runs", struct {
		RequestID string `json:"request_id"`
	}{requestID}, &out)
	return out, e
}
