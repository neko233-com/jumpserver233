package sessionclient

import (
	"context"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/loginaudit"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type LoginAuditRecord = loginaudit.Record
type LoginAuditPage = loginaudit.Page
type LoginAuditSummary = loginaudit.Summary
type LoginAuditHealth = loginaudit.Health
type LoginAuditFilter struct {
	All                                      bool
	Offset, Limit                            int
	Method, Outcome, Query, SourceIP, UserID string
	From, To                                 time.Time
}
type LoginAuditDetail struct {
	LoginAuditRecord
	ReviewState     string    `json:"review_state"`
	CanReview       bool      `json:"can_review"`
	ReviewExpiresAt time.Time `json:"review_expires_at"`
}

func loginAuditQuery(f LoginAuditFilter) string {
	limit := f.Limit
	if limit == 0 {
		limit = 25
	}
	q := url.Values{"offset": {strconv.Itoa(f.Offset)}, "limit": {strconv.Itoa(limit)}, "method": {f.Method}, "outcome": {f.Outcome}, "q": {f.Query}, "source_ip": {f.SourceIP}, "user_id": {f.UserID}}
	if f.All {
		q.Set("scope", "all")
	}
	if !f.From.IsZero() {
		q.Set("from", f.From.Format(time.RFC3339Nano))
	}
	if !f.To.IsZero() {
		q.Set("to", f.To.Format(time.RFC3339Nano))
	}
	return q.Encode()
}
func (c *Client) LoginAudits(ctx context.Context, f LoginAuditFilter) (LoginAuditPage, error) {
	var v LoginAuditPage
	e := c.jobRequest(ctx, "GET", "/api/v1/audits/logins?"+loginAuditQuery(f), nil, &v)
	return v, e
}
func (c *Client) LoginAuditEvent(ctx context.Context, id string) (LoginAuditDetail, error) {
	var v LoginAuditDetail
	if !validMonitorID(id) {
		return v, errors.New("invalid login audit ID")
	}
	e := c.jobRequest(ctx, "GET", "/api/v1/audits/logins/"+url.PathEscape(id), nil, &v)
	return v, e
}
func (c *Client) LoginAuditTotals(ctx context.Context, f LoginAuditFilter) (LoginAuditSummary, error) {
	var v LoginAuditSummary
	e := c.jobRequest(ctx, "GET", "/api/v1/audits/logins/summary?"+loginAuditQuery(f), nil, &v)
	return v, e
}
func (c *Client) LoginAuditStatus(ctx context.Context) (LoginAuditHealth, error) {
	var v LoginAuditHealth
	e := c.jobRequest(ctx, "GET", "/api/v1/audits/logins/health", nil, &v)
	return v, e
}
func (c *Client) ReviewPlatformLogin(ctx context.Context, id string, approve bool) error {
	if !validMonitorID(id) {
		return errors.New("invalid platform login review ID")
	}
	action := "deny"
	if approve {
		action = "approve"
	}
	return c.jobRequest(ctx, "POST", "/api/v1/login-reviews/"+url.PathEscape(id)+"/"+action, nil, nil)
}
func (c *Client) ExportLoginAudits(ctx context.Context, f LoginAuditFilter, out io.Writer) error {
	endpoint := *c.serverURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/api/v1/audits/logins/export.csv"
	endpoint.RawQuery = loginAuditQuery(f)
	req, e := http.NewRequestWithContext(ctx, "GET", endpoint.String(), nil)
	if e != nil {
		return e
	}
	if e = c.authorizeRequest(req); e != nil {
		return e
	}
	resp, e := c.http.Do(req)
	if e != nil {
		return errors.New("login audit export unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return &APIError{StatusCode: resp.StatusCode, Detail: resp.Status}
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv") {
		return errors.New("invalid login audit export")
	}
	const limit = 128 << 20
	n, e := io.Copy(out, io.LimitReader(resp.Body, limit+1))
	if e != nil {
		return e
	}
	if n > limit {
		return errors.New("login audit export exceeds limit")
	}
	return nil
}
