package sessionclient

import (
	"context"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/core/notifications"
	"net/url"
	"strings"
	"time"
)

type NotificationSourceDetails struct {
	ReviewID  string    `json:"review_id,omitempty"`
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Name      string    `json:"name"`
	State     string    `json:"state"`
	AssetID   string    `json:"asset_id,omitempty"`
	Account   string    `json:"account,omitempty"`
	Owner     string    `json:"owner,omitempty"`
	Command   string    `json:"command,omitempty"`
	Rule      string    `json:"rule,omitempty"`
	Method    string    `json:"method,omitempty"`
	At        time.Time `json:"at"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	CanReview bool      `json:"can_review"`
	Accounts  int       `json:"accounts,omitempty"`
	Open      int       `json:"open,omitempty"`
	Resolved  int       `json:"resolved,omitempty"`
}

func (c *Client) NotificationSource(ctx context.Context, kind, id string) (NotificationSourceDetails, error) {
	var out NotificationSourceDetails
	switch kind {
	case "access-reviews", "job-security", "command-reviews", "command-alerts", "agent-events", "account-risks":
	default:
		return out, fmt.Errorf("invalid notification source kind")
	}
	if len(id) == 0 || len(id) > 128 || strings.Trim(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != "" {
		return out, fmt.Errorf("invalid notification source ID")
	}
	e := c.jobRequest(ctx, "GET", "/api/v1/notifications/sources/"+kind+"/"+url.PathEscape(id), nil, &out)
	return out, e
}

type Notification = notifications.Message
type NotificationDelivery = notifications.Delivery
type NotificationPreferences = notifications.Preferences
type NotificationPreferencesInput = notifications.PreferencesInput
type NotificationSettings = notifications.Settings
type NotificationSettingsInput = notifications.SettingsInput
type NotificationInbox struct {
	Results []Notification `json:"results"`
	Total   int            `json:"total"`
	Unread  int            `json:"unread"`
}

func (c *Client) Notifications(ctx context.Context, unread bool, offset, limit int) (NotificationInbox, error) {
	var v NotificationInbox
	q := rotationPaging(offset, limit)
	if unread {
		q += "&unread=true"
	}
	e := c.jobRequest(ctx, "GET", "/api/v1/notifications/inbox?"+q, nil, &v)
	return v, e
}
func (c *Client) ReadNotification(ctx context.Context, id string, all bool) error {
	return c.jobRequest(ctx, "POST", "/api/v1/notifications/read", map[string]any{"id": id, "all": all}, nil)
}
func (c *Client) NotificationPreferences(ctx context.Context) (NotificationPreferences, error) {
	var v NotificationPreferences
	e := c.jobRequest(ctx, "GET", "/api/v1/notifications/preferences", nil, &v)
	return v, e
}
func (c *Client) SaveNotificationPreferences(ctx context.Context, in NotificationPreferencesInput) (NotificationPreferences, error) {
	var v NotificationPreferences
	e := c.jobRequest(ctx, "PUT", "/api/v1/notifications/preferences", in, &v)
	return v, e
}
func (c *Client) NotificationSettings(ctx context.Context) (NotificationSettings, error) {
	var v NotificationSettings
	e := c.jobRequest(ctx, "GET", "/api/v1/notifications/settings", nil, &v)
	return v, e
}
func (c *Client) SaveNotificationSettings(ctx context.Context, in NotificationSettingsInput) (NotificationSettings, error) {
	var v NotificationSettings
	e := c.jobRequest(ctx, "PUT", "/api/v1/notifications/settings", in, &v)
	return v, e
}
func (c *Client) RequestContactVerification(ctx context.Context, channel string) (NotificationPreferences, error) {
	var v NotificationPreferences
	e := c.jobRequest(ctx, "POST", "/api/v1/notifications/verification/request", map[string]string{"channel": channel}, &v)
	return v, e
}
func (c *Client) VerifyNotificationContact(ctx context.Context, channel, code string) (NotificationPreferences, error) {
	var v NotificationPreferences
	e := c.jobRequest(ctx, "POST", "/api/v1/notifications/verification/confirm", map[string]string{"channel": channel, "code": code}, &v)
	return v, e
}
func (c *Client) TestNotification(ctx context.Context, requestID string) (Notification, error) {
	var v Notification
	e := c.jobRequest(ctx, "POST", "/api/v1/notifications/test", map[string]string{"request_id": requestID}, &v)
	return v, e
}
func (c *Client) NotificationDeliveries(ctx context.Context, state string, offset, limit int) (notifications.Page[NotificationDelivery], error) {
	var v notifications.Page[NotificationDelivery]
	e := c.jobRequest(ctx, "GET", "/api/v1/notifications/deliveries?"+rotationPaging(offset, limit)+"&state="+url.QueryEscape(state), nil, &v)
	return v, e
}
func (c *Client) RetryNotification(ctx context.Context, id string, revision int, acknowledge bool) (NotificationDelivery, error) {
	var v NotificationDelivery
	e := c.jobRequest(ctx, "POST", "/api/v1/notifications/deliveries/"+url.PathEscape(id)+"/retry", map[string]any{"revision": revision, "acknowledge_uncertain": acknowledge}, &v)
	return v, e
}
func (c *Client) NotificationAudit(ctx context.Context, offset, limit int) (notifications.Page[notifications.Audit], error) {
	var v notifications.Page[notifications.Audit]
	e := c.jobRequest(ctx, "GET", "/api/v1/notifications/audit?"+rotationPaging(offset, limit), nil, &v)
	return v, e
}
func (c *Client) NotificationHealth(ctx context.Context) (notifications.Health, error) {
	var v notifications.Health
	e := c.jobRequest(ctx, "GET", "/api/v1/notifications/health", nil, &v)
	return v, e
}
