package sessionclient

import (
	"context"
	"fmt"
	"net/url"

	"github.com/neko233-com/jumpserver233/server/internal/core/labels"
)

type Label = labels.Label
type LabelInput = labels.Input
type LabelBinding = labels.Binding
type LabelBindingInput = labels.BindingInput
type LabelResource = labels.Resource
type LabelChoice = labels.Choice
type LabelPage struct {
	Results []Label `json:"results"`
	Total   int     `json:"total"`
}
type LabelBindingDetails struct {
	Binding    LabelBinding     `json:"binding"`
	Effective  []labels.Applied `json:"effective"`
	Assignable bool             `json:"assignable"`
}
type LabelAuditPage struct {
	Results []labels.Audit `json:"results"`
	Total   int            `json:"total"`
}

func (c *Client) Labels(ctx context.Context, search string, offset, limit int) (LabelPage, error) {
	var out LabelPage
	if offset < 0 || limit < 1 || limit > 100 {
		return out, labels.ErrInvalid
	}
	e := c.jobRequest(ctx, "GET", fmt.Sprintf("/api/v1/labels/labels?search=%s&offset=%d&limit=%d", url.QueryEscape(search), offset, limit), nil, &out)
	return out, e
}
func (c *Client) LabelChoices(ctx context.Context) ([]LabelChoice, error) {
	out := []LabelChoice{}
	e := c.jobRequest(ctx, "GET", "/api/v1/labels/choices", nil, &out)
	return out, e
}
func (c *Client) SaveLabel(ctx context.Context, id string, in LabelInput) (Label, error) {
	var out Label
	if id != "" && !labels.ValidID(id) {
		return out, labels.ErrInvalid
	}
	normalized, e := labels.Prepare(in)
	if e != nil {
		return out, e
	}
	method, path := "POST", "/api/v1/labels/labels"
	if id != "" {
		method, path = "PUT", path+"/"+id
	}
	e = c.jobRequest(ctx, method, path, normalized, &out)
	return out, e
}
func (c *Client) DeleteLabel(ctx context.Context, id string, revision int, requestID string) error {
	if !labels.ValidID(id) || revision < 1 {
		return labels.ErrInvalid
	}
	return c.jobRequest(ctx, "DELETE", "/api/v1/labels/labels/"+id, struct {
		Revision  int    `json:"revision"`
		RequestID string `json:"request_id"`
	}{revision, requestID}, nil)
}
func (c *Client) LabelBinding(ctx context.Context, r LabelResource) (LabelBindingDetails, error) {
	var out LabelBindingDetails
	if !labels.ValidResource(r) {
		return out, labels.ErrInvalid
	}
	e := c.jobRequest(ctx, "GET", "/api/v1/labels/bindings/"+r.Type+"/"+r.ID, nil, &out)
	return out, e
}
func (c *Client) BindLabels(ctx context.Context, r LabelResource, in LabelBindingInput) (LabelBinding, error) {
	var out LabelBinding
	if !labels.ValidResource(r) {
		return out, labels.ErrInvalid
	}
	e := c.jobRequest(ctx, "PUT", "/api/v1/labels/bindings/"+r.Type+"/"+r.ID, in, &out)
	return out, e
}
func (c *Client) LabelAudit(ctx context.Context, offset, limit int) (LabelAuditPage, error) {
	var out LabelAuditPage
	if offset < 0 || limit < 1 || limit > 100 {
		return out, labels.ErrInvalid
	}
	e := c.jobRequest(ctx, "GET", fmt.Sprintf("/api/v1/labels/audit?offset=%d&limit=%d", offset, limit), nil, &out)
	return out, e
}
