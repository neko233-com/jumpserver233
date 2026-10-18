package sessionclient

import (
	"context"
	"errors"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"net/url"
	"strings"
)

type ManagedUser = coreauth.ManagedUser
type UserUpdate = coreauth.UserUpdate
type UserChange = coreauth.UserChange
type UserPage struct {
	Results []ManagedUser `json:"results"`
	Total   int           `json:"total"`
}
type UserAuditPage struct {
	Results []coreauth.UserEvent `json:"results"`
	Total   int                  `json:"total"`
}

func (c *Client) ManagedUsers(ctx context.Context, scope, query string, offset, limit int) (UserPage, error) {
	var out UserPage
	q, e := operationPage(offset, limit)
	if e != nil {
		return out, e
	}
	if scope != "current" && scope != "archived" && scope != "all" || len(query) > 128 {
		return out, errors.New("invalid user filters")
	}
	e = c.jobRequest(ctx, "GET", "/api/v1/users/management"+q+"&scope="+scope+"&q="+url.QueryEscape(query), nil, &out)
	return out, e
}
func userResource(id string) (string, error) {
	if len(id) < 1 || len(id) > 128 || strings.ContainsAny(id, "/\\?# ") {
		return "", errors.New("invalid user ID")
	}
	return "/api/v1/users/" + url.PathEscape(id), nil
}
func (c *Client) ManagedUser(ctx context.Context, id string) (ManagedUser, error) {
	var out ManagedUser
	p, e := userResource(id)
	if e == nil {
		e = c.jobRequest(ctx, "GET", p, nil, &out)
	}
	return out, e
}
func (c *Client) ChangeUsers(ctx context.Context, in []UserChange) ([]ManagedUser, error) {
	var out struct {
		Results []ManagedUser `json:"results"`
	}
	if len(in) < 1 || len(in) > 100 {
		return nil, errors.New("invalid user batch")
	}
	seen := map[string]bool{}
	for _, v := range in {
		if _, e := userResource(v.ID); e != nil {
			return nil, e
		}
		if v.Revision < 1 || seen[v.ID] || v.Action != "update" && v.Action != "archive" && v.Action != "restore" && v.Action != "revoke" {
			return nil, errors.New("invalid user change")
		}
		seen[v.ID] = true
	}
	e := c.jobRequest(ctx, "POST", "/api/v1/users/actions", map[string]any{"changes": in}, &out)
	return out.Results, e
}
func (c *Client) UpdateUser(ctx context.Context, id string, in UserUpdate) ([]ManagedUser, error) {
	return c.ChangeUsers(ctx, []UserChange{{ID: id, Action: "update", UserUpdate: in}})
}
func (c *Client) UserAction(ctx context.Context, id, action string, revision int) ([]ManagedUser, error) {
	if action != "archive" && action != "restore" && action != "revoke" {
		return nil, errors.New("invalid user action")
	}
	if revision < 1 {
		return nil, errors.New("invalid user revision")
	}
	return c.ChangeUsers(ctx, []UserChange{{ID: id, Action: action, UserUpdate: UserUpdate{Revision: revision}}})
}
func (c *Client) UserAudit(ctx context.Context, id string, offset, limit int) (UserAuditPage, error) {
	var out UserAuditPage
	q, e := operationPage(offset, limit)
	if e == nil {
		e = c.jobRequest(ctx, "GET", "/api/v1/users/audit"+q+"&user_id="+url.QueryEscape(id), nil, &out)
	}
	return out, e
}
