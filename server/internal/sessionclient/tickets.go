package sessionclient

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/tickets"
	"net/url"
)

// Public workflow DTOs contain metadata only; private bindings and receipts are
// absent from these types and from every endpoint response.
type Ticket = tickets.Ticket
type TicketPolicy = tickets.Policy
type TicketPolicyInput = tickets.PolicyInput
type TicketInput = tickets.SubmitInput
type TicketAmendment = tickets.Amendment
type TicketDecision = tickets.Decision
type TicketRef = tickets.Ref
type TicketAudit = tickets.Audit

func (c *Client) TicketPolicies(ctx context.Context, offset, limit int) (tickets.Page[TicketPolicy], error) {
	var out tickets.Page[TicketPolicy]
	e := c.jobRequest(ctx, "GET", "/api/v1/tickets/policies?"+rotationPaging(offset, limit), nil, &out)
	return out, e
}
func (c *Client) TicketPolicy(ctx context.Context, id string) (TicketPolicy, error) {
	var out TicketPolicy
	e := c.jobRequest(ctx, "GET", "/api/v1/tickets/policies/"+url.PathEscape(id), nil, &out)
	return out, e
}
func (c *Client) SaveTicketPolicy(ctx context.Context, id string, in TicketPolicyInput) (TicketPolicy, error) {
	var out TicketPolicy
	method, path := "POST", "/api/v1/tickets/policies"
	if id != "" {
		method = "PUT"
		path += "/" + url.PathEscape(id)
	}
	e := c.jobRequest(ctx, method, path, in, &out)
	return out, e
}
func (c *Client) DeleteTicketPolicy(ctx context.Context, id string, revision int) error {
	return c.jobRequest(ctx, "DELETE", "/api/v1/tickets/policies/"+url.PathEscape(id), map[string]int{"revision": revision}, nil)
}
func (c *Client) TicketCatalog(ctx context.Context, id, search string, offset, limit int) (tickets.Page[TicketRef], error) {
	var out tickets.Page[TicketRef]
	e := c.jobRequest(ctx, "GET", "/api/v1/tickets/policies/"+url.PathEscape(id)+"/catalog?"+rotationPaging(offset, limit)+"&search="+url.QueryEscape(search), nil, &out)
	return out, e
}
func (c *Client) Tickets(ctx context.Context, view, state, search string, offset, limit int) (tickets.Page[Ticket], error) {
	var out tickets.Page[Ticket]
	e := c.jobRequest(ctx, "GET", "/api/v1/tickets/requests?"+rotationPaging(offset, limit)+"&view="+url.QueryEscape(view)+"&state="+url.QueryEscape(state)+"&search="+url.QueryEscape(search), nil, &out)
	return out, e
}
func (c *Client) Ticket(ctx context.Context, id string) (Ticket, error) {
	var out Ticket
	e := c.jobRequest(ctx, "GET", "/api/v1/tickets/requests/"+url.PathEscape(id), nil, &out)
	return out, e
}
func (c *Client) SubmitTicket(ctx context.Context, in TicketInput) (Ticket, error) {
	var out Ticket
	e := c.jobRequest(ctx, "POST", "/api/v1/tickets/requests", in, &out)
	return out, e
}
func (c *Client) AmendTicket(ctx context.Context, id string, in TicketAmendment) (Ticket, error) {
	var out Ticket
	e := c.jobRequest(ctx, "PUT", "/api/v1/tickets/requests/"+url.PathEscape(id), in, &out)
	return out, e
}
func (c *Client) DecideTicket(ctx context.Context, id string, in TicketDecision) (Ticket, error) {
	var out Ticket
	e := c.jobRequest(ctx, "POST", "/api/v1/tickets/requests/"+url.PathEscape(id)+"/decisions", in, &out)
	return out, e
}
func (c *Client) CommentTicket(ctx context.Context, id, text string) (Ticket, error) {
	var out Ticket
	e := c.jobRequest(ctx, "POST", "/api/v1/tickets/requests/"+url.PathEscape(id)+"/comments", map[string]string{"text": text}, &out)
	return out, e
}
func (c *Client) CancelTicket(ctx context.Context, id string, revision int) (Ticket, error) {
	var out Ticket
	e := c.jobRequest(ctx, "POST", "/api/v1/tickets/requests/"+url.PathEscape(id)+"/cancel", map[string]int{"revision": revision}, &out)
	return out, e
}
func (c *Client) TicketAudit(ctx context.Context, offset, limit int) (tickets.Page[TicketAudit], error) {
	var out tickets.Page[TicketAudit]
	e := c.jobRequest(ctx, "GET", "/api/v1/tickets/audit?"+rotationPaging(offset, limit), nil, &out)
	return out, e
}
