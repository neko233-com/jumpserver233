package sessionclient

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/core/sessionshares"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
)

type ShareInput struct {
	Mode    string   `json:"mode"`
	Minutes int      `json:"minutes"`
	Users   []string `json:"users"`
}

func (c *Client) CreateShare(ctx context.Context, id string, in ShareInput) (sessionshares.Created, error) {
	var out sessionshares.Created
	e := c.jobRequest(ctx, http.MethodPost, "/api/v1/sessions/"+url.PathEscape(id)+"/shares", in, &out)
	return out, e
}
func (c *Client) ShareState(ctx context.Context, id string) (gateway.ShareState, error) {
	var out gateway.ShareState
	e := c.jobRequest(ctx, http.MethodGet, "/api/v1/sessions/"+url.PathEscape(id)+"/shares", nil, &out)
	return out, e
}
func (c *Client) RevokeShare(ctx context.Context, id string) error {
	return c.jobRequest(ctx, http.MethodDelete, "/api/v1/session-shares/"+url.PathEscape(id), nil, nil)
}
func (c *Client) KickShareMember(ctx context.Context, id string) error {
	return c.jobRequest(ctx, http.MethodDelete, "/api/v1/session-share-members/"+url.PathEscape(id), nil, nil)
}
func (c *Client) ReclaimShare(ctx context.Context, id string) error {
	return c.jobRequest(ctx, http.MethodPost, "/api/v1/sessions/"+url.PathEscape(id)+"/share-control", map[string]string{"member_id": ""}, nil)
}
func (c *Client) JoinShare(ctx context.Context, id, code string) (gateway.SharedSession, error) {
	var out gateway.SharedSession
	e := c.jobRequest(ctx, http.MethodPost, "/api/v1/session-shares/"+url.PathEscape(id)+"/join", map[string]string{"code": code}, &out)
	return out, e
}
func (c *Client) DialSharedTerminal(ctx context.Context, s gateway.SharedSession) (*websocket.Conn, error) {
	conn, e := c.dialTerminal(ctx, s.CreatedSession, gateway.ShareSubprotocol)
	if e == nil {
		conn.SetReadLimit(64 * 1024)
	}
	return conn, e
}

type ShareEvents struct {
	Results []sessionshares.Event `json:"results"`
	Total   int                   `json:"total"`
	Offset  int                   `json:"offset"`
	Limit   int                   `json:"limit"`
}

func (c *Client) ShareEvents(ctx context.Context, id string, offset, limit int) (ShareEvents, error) {
	var out ShareEvents
	e := c.jobRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/sessions/%s/share-events?offset=%d&limit=%d", url.PathEscape(id), offset, limit), nil, &out)
	return out, e
}
