package sessionclient

import (
	"context"
	"errors"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
)

type PasswordPolicy = coreauth.PasswordPolicy
type PasswordPolicyPage struct {
	Results []coreauth.PasswordPolicyEvent `json:"results"`
	Total   int                            `json:"total"`
}
type PasswordResetInput struct {
	Revision    int    `json:"revision"`
	NewPassword string `json:"new_password"`
	ForceChange *bool  `json:"force_change,omitempty"`
}

func (c *Client) PasswordPolicy(ctx context.Context) (PasswordPolicy, error) {
	var out PasswordPolicy
	e := c.jobRequest(ctx, "GET", "/api/v1/settings/security/passwords", nil, &out)
	return out, e
}
func (c *Client) SavePasswordPolicy(ctx context.Context, in PasswordPolicy) (PasswordPolicy, error) {
	var out PasswordPolicy
	e := c.jobRequest(ctx, "PUT", "/api/v1/settings/security/passwords", in, &out)
	return out, e
}
func (c *Client) PasswordPolicyAudit(ctx context.Context, offset, limit int) (PasswordPolicyPage, error) {
	var out PasswordPolicyPage
	q, e := operationPage(offset, limit)
	if e == nil {
		e = c.jobRequest(ctx, "GET", "/api/v1/settings/security/passwords/audit"+q, nil, &out)
	}
	return out, e
}
func (c *Client) ResetPassword(ctx context.Context, id string, in PasswordResetInput) (ManagedUser, error) {
	var out ManagedUser
	p, e := userResource(id)
	if e != nil {
		return out, e
	}
	if in.Revision < 1 || len(in.NewPassword) < 12 || len(in.NewPassword) > 256 {
		return out, errors.New("invalid password reset input")
	}
	e = c.jobRequest(ctx, "POST", p+"/password/reset", in, &out)
	return out, e
}
func (c *Client) ResetMFA(ctx context.Context, id string, revision int) (ManagedUser, error) {
	var out ManagedUser
	p, e := userResource(id)
	if e != nil {
		return out, e
	}
	if revision < 1 {
		return out, errors.New("invalid user revision")
	}
	e = c.jobRequest(ctx, "POST", p+"/mfa/reset", map[string]int{"revision": revision}, &out)
	return out, e
}
func (c *Client) ChangePassword(ctx context.Context, current, password string) error {
	if len(current) > 256 || len(password) < 12 || len(password) > 256 {
		return errors.New("invalid password input")
	}
	return c.jobRequest(ctx, "POST", "/api/v1/users/me/password/change", map[string]string{"current_password": current, "new_password": password}, nil)
}
