package sessionclient

import (
	"context"
	"fmt"
	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/desktop"
	"net/http"
	"net/url"
	"strings"
)

func (c *Client) CreateDesktop(ctx context.Context, asset string) (desktop.Created, error) {
	var out desktop.Created
	e := c.DatabaseRequest(ctx, http.MethodPost, "/api/v1/assets/"+url.PathEscape(asset)+"/rdp/sessions", "", nil, &out)
	return out, e
}
func (c *Client) CloseDesktop(ctx context.Context, id string) error {
	return c.DatabaseRequest(ctx, http.MethodDelete, "/api/v1/desktop-sessions/"+url.PathEscape(id), "", nil, nil)
}
func (c *Client) DialDesktop(ctx context.Context, created desktop.Created) (*websocket.Conn, error) {
	reference, e := url.Parse(created.URL)
	if e != nil || reference.IsAbs() || reference.Host != "" || reference.Fragment != "" || !strings.HasPrefix(reference.Path, "/ws/desktop/") {
		return nil, fmt.Errorf("invalid desktop URL")
	}
	endpoint := *c.serverURL
	if endpoint.Scheme == "https" {
		endpoint.Scheme = "wss"
	} else {
		endpoint.Scheme = "ws"
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + reference.Path
	endpoint.RawQuery = reference.RawQuery
	socket, _, e := websocket.Dial(ctx, endpoint.String(), &websocket.DialOptions{Subprotocols: []string{desktop.Subprotocol, desktop.TicketPrefix + created.Ticket}})
	if e != nil {
		return nil, fmt.Errorf("connect to desktop: %w", e)
	}
	if socket.Subprotocol() != desktop.Subprotocol {
		socket.CloseNow()
		return nil, fmt.Errorf("unsupported desktop protocol")
	}
	socket.SetReadLimit((40 << 20) + 8)
	return socket, nil
}
