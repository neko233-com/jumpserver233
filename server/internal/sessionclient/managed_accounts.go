package sessionclient

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type ManagedAccount struct {
	ID                      string                   `json:"id"`
	AssetID                 string                   `json:"asset_id"`
	Name                    string                   `json:"name"`
	Username                string                   `json:"username"`
	Remark                  string                   `json:"remark"`
	DiscoveryID             string                   `json:"discovery_id,omitempty"`
	Default                 bool                     `json:"default"`
	Active                  bool                     `json:"active"`
	CredentialType          string                   `json:"credential_type"`
	CredentialRevision      uint64                   `json:"credential_revision"`
	KeyFingerprint          string                   `json:"key_fingerprint,omitempty"`
	Version                 string                   `json:"version"`
	PasswordRotationEnabled bool                     `json:"password_rotation_enabled"`
	KeyRotationEnabled      bool                     `json:"key_rotation_enabled"`
	PasswordRotation        *ManagedPasswordRotation `json:"password_rotation,omitempty"`
	SSHKeyRotation          *ManagedKeyRotation      `json:"ssh_key_rotation,omitempty"`
	Permissions             []string                 `json:"permissions"`
	CreatedAt               time.Time                `json:"created_at"`
	UpdatedAt               time.Time                `json:"updated_at"`
}
type ManagedPasswordRotation struct {
	State          string     `json:"state"`
	Shared         bool       `json:"shared,omitempty"`
	LastRotatedAt  time.Time  `json:"last_rotated_at"`
	NextRotationAt time.Time  `json:"next_rotation_at"`
	LastAttemptAt  *time.Time `json:"last_attempt_at,omitempty"`
	ErrorCode      string     `json:"error_code,omitempty"`
}
type ManagedKeyRotation struct {
	State            string     `json:"state"`
	Enabled          bool       `json:"enabled"`
	Shared           bool       `json:"shared,omitempty"`
	Pending          bool       `json:"pending"`
	CanCancel        bool       `json:"can_cancel"`
	RequestID        string     `json:"request_id,omitempty"`
	OperationID      string     `json:"operation_id,omitempty"`
	ExpectedRevision uint64     `json:"expected_revision,omitempty"`
	LastRotatedAt    *time.Time `json:"last_rotated_at,omitempty"`
	NextRotationAt   *time.Time `json:"next_rotation_at,omitempty"`
	LastAttemptAt    *time.Time `json:"last_attempt_at,omitempty"`
	ErrorCode        string     `json:"error_code,omitempty"`
}
type ManagedAccountInput struct {
	Name                    *string `json:"name,omitempty"`
	Username                string  `json:"username,omitempty"`
	Remark                  *string `json:"remark,omitempty"`
	DiscoveryID             *string `json:"discovery_id,omitempty"`
	Active                  *bool   `json:"active,omitempty"`
	PasswordRotationEnabled *bool   `json:"password_rotation_enabled,omitempty"`
	KeyRotationEnabled      *bool   `json:"key_rotation_enabled,omitempty"`
	CredentialType          string  `json:"credential_type,omitempty"`
	Password                string  `json:"password,omitempty"`
	PrivateKey              string  `json:"private_key,omitempty"`
	PrivateKeyPassphrase    string  `json:"private_key_passphrase,omitempty"`
	Version                 string  `json:"version"`
}
type ManagedAccountPage struct {
	Results []ManagedAccount `json:"results"`
	Total   int              `json:"total"`
	Version string           `json:"version"`
}

func validAccountSelector(v string) bool {
	return v != "" && len(v) <= 128 && utf8.ValidString(v) && strings.IndexFunc(v, unicode.IsControl) < 0 && !strings.ContainsAny(v, " /\\?#")
}
func (c *Client) WithManagedAccount(selector string) (*Client, error) {
	if selector != "" && !validAccountSelector(selector) {
		return nil, errors.New("managed account selector must be a username or endpoint ID")
	}
	copy := *c
	copy.managedAccount = selector
	return &copy, nil
}
func (c *Client) managedRequest(ctx context.Context, method, path string, input, output any) error {
	e := c.jobRequest(ctx, method, path, input, output)
	if e == nil {
		return nil
	}
	var remote *APIError
	if errors.As(e, &remote) {
		switch remote.Detail {
		case "account_username_exists", "account_activity_full", "credential_changed_during_verification", "shared_credential_conflict", "password_rotation_in_progress", "ssh_key_change_conflict":
			return fmt.Errorf("managed account API: %s", remote.Detail)
		}
		return fmt.Errorf("managed account API returned HTTP %d", remote.StatusCode)
	}
	// A remote error or redirect must never echo submitted credential material.
	return errors.New("managed account API request failed")
}
func (c *Client) ManagedAccounts(ctx context.Context, asset string, offset, limit int, username string) (ManagedAccountPage, error) {
	var page ManagedAccountPage
	q := url.Values{"offset": {strconv.Itoa(offset)}, "limit": {strconv.Itoa(limit)}}
	if username != "" {
		q.Set("username", username)
	}
	e := c.managedRequest(ctx, http.MethodGet, "/api/v1/assets/"+url.PathEscape(asset)+"/accounts?"+q.Encode(), nil, &page)
	return page, e
}
func (c *Client) ManagedAccount(ctx context.Context, asset, id string) (ManagedAccount, error) {
	var a ManagedAccount
	e := c.managedRequest(ctx, http.MethodGet, "/api/v1/assets/"+url.PathEscape(asset)+"/accounts/"+url.PathEscape(id), nil, &a)
	return a, e
}
func (c *Client) CreateManagedAccount(ctx context.Context, asset string, in ManagedAccountInput) (ManagedAccount, error) {
	var a ManagedAccount
	e := c.managedRequest(ctx, http.MethodPost, "/api/v1/assets/"+url.PathEscape(asset)+"/accounts", in, &a)
	return a, e
}
func (c *Client) UpdateManagedAccount(ctx context.Context, asset, id string, in ManagedAccountInput) (ManagedAccount, error) {
	var a ManagedAccount
	e := c.managedRequest(ctx, http.MethodPut, "/api/v1/assets/"+url.PathEscape(asset)+"/accounts/"+url.PathEscape(id), in, &a)
	return a, e
}
func (c *Client) DeleteManagedAccount(ctx context.Context, asset, id, version string) error {
	return c.managedRequest(ctx, http.MethodDelete, "/api/v1/assets/"+url.PathEscape(asset)+"/accounts/"+url.PathEscape(id), map[string]string{"version": version}, nil)
}

type ManagedAccountAudit struct {
	At     time.Time `json:"at"`
	Action string    `json:"action"`
	Actor  struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"actor"`
	AccountID string `json:"account_id"`
	Username  string `json:"username"`
	Before    string `json:"before,omitempty"`
	After     string `json:"after,omitempty"`
}
type ManagedAccountActivityPage struct {
	Results []ManagedAccountAudit `json:"results"`
	Total   int                   `json:"total"`
}

func (c *Client) ManagedAccountActivity(ctx context.Context, asset, id string, offset, limit int) (ManagedAccountActivityPage, error) {
	var out ManagedAccountActivityPage
	e := c.managedRequest(ctx, http.MethodGet, "/api/v1/assets/"+url.PathEscape(asset)+"/accounts/"+url.PathEscape(id)+"/activity?offset="+strconv.Itoa(offset)+"&limit="+strconv.Itoa(limit), nil, &out)
	return out, e
}
func (c *Client) ResolveManagedAccount(ctx context.Context, asset, selector string) (ManagedAccount, error) {
	if !validAccountSelector(asset) || !validAccountSelector(selector) {
		return ManagedAccount{}, errors.New("invalid managed account selector")
	}
	suffix := strings.TrimPrefix(selector, "account-"+asset+"-")
	decoded, decodeErr := hex.DecodeString(suffix)
	if selector == asset || suffix != selector && decodeErr == nil && len(decoded) == 16 && suffix == strings.ToLower(suffix) {
		a, e := c.ManagedAccount(ctx, asset, selector)
		if e != nil {
			return a, e
		}
		if a.ID != selector || a.AssetID != asset {
			return ManagedAccount{}, errors.New("invalid managed account response")
		}
		return a, nil
	}
	page, e := c.ManagedAccounts(ctx, asset, 0, 2, selector)
	if e != nil {
		return ManagedAccount{}, e
	}
	if len(page.Results) != 1 || page.Total != 1 || page.Results[0].AssetID != asset || page.Results[0].Username != selector || page.Results[0].ID == "" {
		return ManagedAccount{}, errors.New("managed account is unavailable or ambiguous")
	}
	return page.Results[0], nil
}
func (c *Client) selectedAsset(ctx context.Context, id string) (string, error) {
	if c.managedAccount == "" {
		return id, nil
	}
	parent := id
	if strings.HasPrefix(id, "account-") {
		if len(id) <= 8+33 || id[len(id)-33] != '-' {
			return "", errors.New("invalid managed account endpoint")
		}
		if b, e := hex.DecodeString(id[len(id)-32:]); e != nil || len(b) != 16 {
			return "", errors.New("invalid managed account endpoint")
		}
		parent = id[8 : len(id)-33]
	}
	a, e := c.ResolveManagedAccount(ctx, parent, c.managedAccount)
	if e != nil {
		return "", e
	}
	if !a.Active {
		return "", errors.New("managed account is disabled")
	}
	if parent != id && a.ID != id {
		return "", errors.New("account selector conflicts with the explicit endpoint")
	}
	return a.ID, nil
}
func (c *Client) selectedAccountPath(ctx context.Context, path string) (string, error) {
	if c.managedAccount == "" {
		return path, nil
	}
	u, e := url.Parse(path)
	if e != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(u.Path, "/api/v1/assets/") {
		return path, nil
	}
	parts := strings.SplitN(strings.TrimPrefix(u.Path, "/api/v1/assets/"), "/", 2)
	if len(parts) != 2 || parts[1] == "accounts" || strings.HasPrefix(parts[1], "accounts/") {
		return path, nil
	}
	id, e := c.selectedAsset(ctx, parts[0])
	if e != nil {
		return "", e
	}
	u.Path, u.RawPath = "/api/v1/assets/"+id+"/"+parts[1], ""
	return u.RequestURI(), nil
}
