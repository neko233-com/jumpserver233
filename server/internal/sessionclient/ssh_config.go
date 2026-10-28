package sessionclient

import (
	"context"
	"net/http"
)

// SSHConfigAccount contains only inventory metadata needed for native SSH aliases.
type SSHConfigAccount struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Active      bool     `json:"active"`
	Permissions []string `json:"permissions"`
}

// SSHConfigAsset is the currently visible SSH inventory and its authorized accounts.
type SSHConfigAsset struct {
	ID       string             `json:"id"`
	Name     string             `json:"name"`
	Protocol string             `json:"protocol"`
	Accounts []SSHConfigAccount `json:"accounts"`
}

// SSHConfigInventory reads the authenticated platform identity and authorized inventory.
func (c *Client) SSHConfigInventory(ctx context.Context) (string, []SSHConfigAsset, error) {
	var user struct {
		Username string `json:"username"`
	}
	if err := c.jobRequest(ctx, http.MethodGet, "/api/v1/users/me", nil, &user); err != nil {
		return "", nil, err
	}
	var assets []SSHConfigAsset
	if err := c.jobRequest(ctx, http.MethodGet, "/api/v1/assets", nil, &assets); err != nil {
		return "", nil, err
	}
	return user.Username, assets, nil
}
