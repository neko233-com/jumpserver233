package sessionclient

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/notifications"
	"net/url"
)

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
