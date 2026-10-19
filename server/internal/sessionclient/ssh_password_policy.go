package sessionclient

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/credentialpolicy"
)

type SSHPasswordPolicySettings = credentialpolicy.Settings
type SSHPasswordPolicyInput = credentialpolicy.Input
type SSHPasswordPolicyState struct {
	Policy credentialpolicy.Settings `json:"policy"`
	Audit  []credentialpolicy.Audit  `json:"audit"`
}

func (c *Client) SSHPasswordPolicy(ctx context.Context) (SSHPasswordPolicyState, error) {
	var out SSHPasswordPolicyState
	e := c.jobRequest(ctx, "GET", "/api/v1/accounts/password-policy", nil, &out)
	return out, e
}
func (c *Client) SaveSSHPasswordPolicy(ctx context.Context, in SSHPasswordPolicyInput) (SSHPasswordPolicyState, error) {
	var out SSHPasswordPolicyState
	e := c.jobRequest(ctx, "PUT", "/api/v1/accounts/password-policy", in, &out)
	return out, e
}
