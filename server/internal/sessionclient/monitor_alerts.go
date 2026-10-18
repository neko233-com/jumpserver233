package sessionclient

import (
	"context"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/monitoralerts"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type MonitorRule = monitoralerts.Rule
type MonitorRuleInput = monitoralerts.Input
type MonitorAlert = monitoralerts.Alert
type MonitorAudit = monitoralerts.Audit
type MonitorHealth = monitoralerts.Health
type MonitorAlertPage = monitoralerts.Page[monitoralerts.Alert]
type MonitorAuditPage = monitoralerts.Page[monitoralerts.Audit]

func validMonitorID(id string) bool {
	return len(id) > 0 && len(id) <= 128 && strings.Trim(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") == ""
}

func (c *Client) MonitorRules(ctx context.Context) ([]MonitorRule, error) {
	var v []MonitorRule
	e := c.jobRequest(ctx, "GET", "/api/v1/monitoring/rules", nil, &v)
	return v, e
}
func (c *Client) SaveMonitorRule(ctx context.Context, id string, in MonitorRuleInput) (MonitorRule, error) {
	var v MonitorRule
	if id != "" && !validMonitorID(id) {
		return v, errors.New("invalid monitoring ID")
	}
	p := "/api/v1/monitoring/rules"
	method := "POST"
	if id != "" {
		p += "/" + url.PathEscape(id)
		method = "PUT"
	}
	e := c.jobRequest(ctx, method, p, in, &v)
	return v, e
}
func (c *Client) DeleteMonitorRule(ctx context.Context, id string, revision int) error {
	if !validMonitorID(id) {
		return errors.New("invalid monitoring ID")
	}
	return c.jobRequest(ctx, "DELETE", "/api/v1/monitoring/rules/"+url.PathEscape(id)+"?revision="+strconv.Itoa(revision), nil, nil)
}
func (c *Client) MuteMonitorRule(ctx context.Context, id string, revision int, until time.Time, reason string) (MonitorRule, error) {
	var v MonitorRule
	if !validMonitorID(id) {
		return v, errors.New("invalid monitoring ID")
	}
	in := struct {
		Revision int       `json:"revision"`
		Until    time.Time `json:"until"`
		Reason   string    `json:"reason"`
	}{revision, until, reason}
	e := c.jobRequest(ctx, "POST", "/api/v1/monitoring/rules/"+url.PathEscape(id)+"/mute", in, &v)
	return v, e
}
func (c *Client) MonitorAlerts(ctx context.Context, offset, limit int, state, query string) (MonitorAlertPage, error) {
	var v MonitorAlertPage
	q := url.Values{"offset": {strconv.Itoa(offset)}, "limit": {strconv.Itoa(limit)}, "state": {state}, "q": {query}}
	e := c.jobRequest(ctx, "GET", "/api/v1/monitoring/alerts?"+q.Encode(), nil, &v)
	return v, e
}
func (c *Client) MonitorAlert(ctx context.Context, id string) (MonitorAlert, error) {
	var v MonitorAlert
	if !validMonitorID(id) {
		return v, errors.New("invalid monitoring ID")
	}
	e := c.jobRequest(ctx, "GET", "/api/v1/monitoring/alerts/"+url.PathEscape(id), nil, &v)
	return v, e
}
func (c *Client) AcknowledgeMonitorAlert(ctx context.Context, id string, revision int, comment string) (MonitorAlert, error) {
	var v MonitorAlert
	if !validMonitorID(id) {
		return v, errors.New("invalid monitoring ID")
	}
	in := struct {
		Revision int    `json:"revision"`
		Comment  string `json:"comment"`
	}{revision, comment}
	e := c.jobRequest(ctx, "POST", "/api/v1/monitoring/alerts/"+url.PathEscape(id)+"/acknowledge", in, &v)
	return v, e
}
func (c *Client) MonitorAudit(ctx context.Context, offset, limit int) (MonitorAuditPage, error) {
	var v MonitorAuditPage
	e := c.jobRequest(ctx, "GET", "/api/v1/monitoring/audit?"+rotationPaging(offset, limit), nil, &v)
	return v, e
}
func (c *Client) MonitorHealth(ctx context.Context) (MonitorHealth, error) {
	var v MonitorHealth
	e := c.jobRequest(ctx, "GET", "/api/v1/monitoring/health", nil, &v)
	return v, e
}
