package sessionclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/neko233-com/jumpserver233/server/internal/core/databasequery"
)

func (c *Client) DatabaseRequest(ctx context.Context, method, path, session string, input, output any) error {
	endpoint := *c.serverURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + path
	var body io.Reader
	if input != nil {
		raw, e := json.Marshal(input)
		if e != nil {
			return e
		}
		body = strings.NewReader(string(raw))
	}
	req, e := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	if session != "" {
		req.Header.Set("X-JMS-DB-SESSION", session)
	}
	if e = c.authorizeRequest(req); e != nil {
		return e
	}
	response, e := c.http.Do(req)
	if e != nil {
		return fmt.Errorf("database API request failed: %w", e)
	}
	defer response.Body.Close()
	if response.StatusCode == 202 {
		var pending struct {
			ReviewID string `json:"review_id"`
		}
		if json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&pending) != nil || pending.ReviewID == "" {
			return fmt.Errorf("invalid database login review response")
		}
		return &AccessReviewPendingError{ReviewID: pending.ReviewID}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("database API returned HTTP %d", response.StatusCode)
	}
	if output != nil {
		return json.NewDecoder(io.LimitReader(response.Body, 8*1024*1024)).Decode(output)
	}
	return nil
}
func (c *Client) CreateDatabaseSession(ctx context.Context, asset string) (databasequery.SessionResponse, error) {
	var out databasequery.SessionResponse
	e := c.DatabaseRequest(ctx, http.MethodPost, "/api/v1/assets/"+url.PathEscape(asset)+"/database-sessions", "", nil, &out)
	return out, e
}
func (c *Client) SubmitDatabaseQuery(ctx context.Context, asset, token string, input databasequery.Input) (databasequery.Job, error) {
	var out databasequery.Job
	e := c.DatabaseRequest(ctx, http.MethodPost, "/api/v1/assets/"+url.PathEscape(asset)+"/database-queries", token, input, &out)
	return out, e
}
func (c *Client) GetDatabaseQuery(ctx context.Context, id string) (databasequery.Response, error) {
	var out databasequery.Response
	e := c.DatabaseRequest(ctx, http.MethodGet, "/api/v1/database-queries/"+url.PathEscape(id), "", nil, &out)
	return out, e
}
