package sessionclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/connector/kubeclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
)

type Client struct {
	serverURL    *url.URL
	organization string
	token        string
	keyID        string
	secret       string
	http         *http.Client
}

type AccessReviewPendingError struct {
	ReviewID string
}

func (e *AccessReviewPendingError) Error() string {
	return "SSH login is waiting for administrator review"
}

type AccessReview struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

func (c *Client) WithOrganization(id string) (*Client, error) {
	if id != "" && !organizations.ValidID(id) {
		return nil, fmt.Errorf("JMS_ORG_ID must be an organization UUID")
	}
	copy := *c
	copy.organization = id
	return &copy, nil
}

func New(serverURL, token string) (*Client, error) {
	return newClient(serverURL, token, "", "")
}

func NewWithAccessKey(serverURL, keyID, secret string) (*Client, error) {
	if strings.TrimSpace(keyID) == "" || strings.TrimSpace(secret) == "" {
		return nil, fmt.Errorf("JMS_ACCESS_KEY_ID and JMS_ACCESS_KEY_SECRET must both be set")
	}
	return newClient(serverURL, "", keyID, secret)
}

func newClient(serverURL, token, keyID, secret string) (*Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("JMS_SERVER_URL must be an http or https URL")
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return &Client{serverURL: parsed, token: token, keyID: keyID, secret: secret, http: http.DefaultClient}, nil
}

func (c *Client) CreateSession(ctx context.Context, request gateway.CreateRequest) (gateway.CreatedSession, error) {
	endpoint := *c.serverURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/api/v1/sessions"
	var payload any = request
	if request.Protocol != "" && request.Protocol != "ssh" && request.Protocol != "telnet" {
		return gateway.CreatedSession{}, errors.New("unsupported terminal protocol")
	}
	if request.Protocol == "telnet" {
		if request.Kubernetes != nil {
			return gateway.CreatedSession{}, errors.New("conflicting terminal protocols")
		}
		endpoint.Path = strings.TrimRight(c.serverURL.Path, "/") + "/api/v1/assets/" + url.PathEscape(request.AssetID) + "/telnet/sessions"
		payload = struct {
			Cols int `json:"cols"`
			Rows int `json:"rows"`
		}{request.Cols, request.Rows}
	}
	if request.Kubernetes != nil {
		endpoint.Path = strings.TrimRight(c.serverURL.Path, "/") + "/api/v1/assets/" + url.PathEscape(request.AssetID) + "/kubernetes/sessions"
		payload = struct {
			kubeclient.Selection
			Cols int `json:"cols"`
			Rows int `json:"rows"`
		}{*request.Kubernetes, request.Cols, request.Rows}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return gateway.CreatedSession{}, fmt.Errorf("encode terminal request: %w", err)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader(string(body)))
	if err != nil {
		return gateway.CreatedSession{}, fmt.Errorf("create terminal request: %w", err)
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	if err := c.authorizeRequest(httpRequest); err != nil {
		return gateway.CreatedSession{}, err
	}
	response, err := c.http.Do(httpRequest)
	if err != nil {
		return gateway.CreatedSession{}, fmt.Errorf("create SSH session: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusAccepted {
		var pending struct {
			ReviewID string `json:"review_id"`
		}
		if err := json.NewDecoder(io.LimitReader(response.Body, 64*1024)).Decode(&pending); err != nil || pending.ReviewID == "" {
			return gateway.CreatedSession{}, fmt.Errorf("server returned an invalid access review request")
		}
		return gateway.CreatedSession{}, &AccessReviewPendingError{ReviewID: pending.ReviewID}
	}
	if response.StatusCode != http.StatusCreated {
		var problem struct {
			Detail string `json:"detail"`
		}
		_ = json.NewDecoder(io.LimitReader(response.Body, 64*1024)).Decode(&problem)
		if problem.Detail == "" {
			problem.Detail = response.Status
		}
		return gateway.CreatedSession{}, fmt.Errorf("create SSH session: %s", problem.Detail)
	}
	var session gateway.CreatedSession
	if err := json.NewDecoder(io.LimitReader(response.Body, 64*1024)).Decode(&session); err != nil {
		return gateway.CreatedSession{}, fmt.Errorf("read SSH session response: %w", err)
	}
	if session.SessionID == "" || session.Ticket == "" || !strings.HasPrefix(session.WebSocketURL, "/ws/") {
		return gateway.CreatedSession{}, fmt.Errorf("server returned an incomplete SSH session")
	}
	return session, nil
}

func (c *Client) WaitForAccessReview(ctx context.Context, reviewID string) (string, error) {
	if strings.TrimSpace(reviewID) == "" {
		return "", fmt.Errorf("access review ID is required")
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		review, err := c.GetAccessReview(ctx, reviewID)
		if err != nil {
			return "", err
		}
		if review.State != "pending" {
			return review.State, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
		}
	}
}

func (c *Client) GetAccessReview(ctx context.Context, reviewID string) (AccessReview, error) {
	endpoint := *c.serverURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/api/v1/access-reviews/" + url.PathEscape(reviewID)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return AccessReview{}, fmt.Errorf("create access review request: %w", err)
	}
	if err := c.authorizeRequest(request); err != nil {
		return AccessReview{}, err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return AccessReview{}, fmt.Errorf("read SSH login review: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		var problem struct {
			Detail string `json:"detail"`
		}
		_ = json.NewDecoder(io.LimitReader(response.Body, 64*1024)).Decode(&problem)
		if problem.Detail == "" {
			problem.Detail = response.Status
		}
		return AccessReview{}, fmt.Errorf("read SSH login review: %s", problem.Detail)
	}
	var review AccessReview
	if err := json.NewDecoder(io.LimitReader(response.Body, 64*1024)).Decode(&review); err != nil {
		return AccessReview{}, fmt.Errorf("decode SSH login review: %w", err)
	}
	switch review.State {
	case "pending", "approved", "denied", "expired", "consumed":
		return review, nil
	default:
		return AccessReview{}, fmt.Errorf("server returned an invalid SSH login review state")
	}
}

func (c *Client) DialTerminal(ctx context.Context, session gateway.CreatedSession) (*websocket.Conn, error) {
	endpoint := *c.serverURL
	if endpoint.Scheme == "https" {
		endpoint.Scheme = "wss"
	} else {
		endpoint.Scheme = "ws"
	}
	reference, err := url.Parse(session.WebSocketURL)
	if err != nil || reference.IsAbs() || reference.Host != "" || reference.Fragment != "" || !strings.HasPrefix(reference.Path, "/ws/") {
		return nil, fmt.Errorf("invalid terminal URL")
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + reference.Path
	endpoint.RawQuery = reference.RawQuery
	conn, _, err := websocket.Dial(ctx, endpoint.String(), &websocket.DialOptions{
		Subprotocols: []string{gateway.TerminalSubprotocol, gateway.TicketSubprotocol(session.Ticket)},
	})
	if err != nil {
		return nil, fmt.Errorf("connect to SSH terminal: %w", err)
	}
	if conn.Subprotocol() != gateway.TerminalSubprotocol {
		_ = conn.CloseNow()
		return nil, fmt.Errorf("server selected an unsupported terminal protocol")
	}
	return conn, nil
}

func (c *Client) CloseSession(ctx context.Context, sessionID string) error {
	endpoint := *c.serverURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/api/v1/sessions/" + url.PathEscape(sessionID)
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint.String(), nil)
	if err != nil {
		return fmt.Errorf("create terminal close request: %w", err)
	}
	if err := c.authorizeRequest(request); err != nil {
		return err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("close SSH session: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusNotFound {
		return fmt.Errorf("close SSH session: %s", response.Status)
	}
	return nil
}
