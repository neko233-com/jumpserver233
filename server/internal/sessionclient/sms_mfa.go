package sessionclient

import (
	"context"
	"time"
)

type SMSFactorStatus struct {
	Active        bool      `json:"active"`
	Purpose       string    `json:"purpose"`
	MaskedPhone   string    `json:"masked_phone"`
	DeliveryState string    `json:"delivery_state"`
	ExpiresAt     time.Time `json:"expires_at"`
	RetryAt       time.Time `json:"retry_at,omitzero"`
	NeedsPhone    bool      `json:"needs_phone"`
}
type SMSMFASettings struct {
	Enabled  bool     `json:"enabled"`
	Policy   string   `json:"policy"`
	UserIDs  []string `json:"user_ids"`
	Revision int      `json:"revision"`
}
type SMSMFAInput struct {
	SMSMFASettings
	RequestID string `json:"request_id"`
}
type SMSMFAAudit struct {
	At       time.Time `json:"at"`
	ActorID  string    `json:"actor_id"`
	UserID   string    `json:"user_id,omitempty"`
	Action   string    `json:"action"`
	Revision int       `json:"revision"`
}
type SMSProfile struct {
	Available   bool   `json:"available"`
	Enabled     bool   `json:"enabled"`
	Forced      bool   `json:"forced"`
	MaskedPhone string `json:"masked_phone"`
}
type SMSBindingResult struct {
	FactorToken string          `json:"factor_token"`
	Status      SMSFactorStatus `json:"status"`
}

func (c *Client) SMSProfile(ctx context.Context) (SMSProfile, error) {
	var out SMSProfile
	e := c.jobRequest(ctx, "GET", "/api/v1/users/me/sms-mfa", nil, &out)
	return out, e
}
func (c *Client) BeginSMSBinding(ctx context.Context, phone, password, otp string) (SMSBindingResult, error) {
	var out SMSBindingResult
	e := c.jobRequest(ctx, "POST", "/api/v1/users/me/sms-mfa/enroll", map[string]string{"phone": phone, "password": password, "otp": otp}, &out)
	return out, e
}
func (c *Client) SMSMFASettings(ctx context.Context) (SMSMFASettings, error) {
	var out SMSMFASettings
	e := c.jobRequest(ctx, "GET", "/api/v1/settings/security/sms-mfa", nil, &out)
	return out, e
}
func (c *Client) SaveSMSMFASettings(ctx context.Context, in SMSMFAInput) (SMSMFASettings, error) {
	var out SMSMFASettings
	e := c.jobRequest(ctx, "PUT", "/api/v1/settings/security/sms-mfa", in, &out)
	return out, e
}
func (c *Client) SMSMFAAudit(ctx context.Context) ([]SMSMFAAudit, error) {
	var out []SMSMFAAudit
	e := c.jobRequest(ctx, "GET", "/api/v1/settings/security/sms-mfa/audit", nil, &out)
	return out, e
}
