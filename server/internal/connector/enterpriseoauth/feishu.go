package enterpriseoauth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

type oauthToken struct {
	Code    *int   `json:"code"`
	Error   string `json:"error"`
	Token   string `json:"access_token"`
	Type    string `json:"token_type"`
	Expires int    `json:"expires_in"`
}

func (o oauthToken) valid() bool {
	return (o.Code == nil || *o.Code == 0) && o.Error == "" && validToken(o.Token) && strings.EqualFold(o.Type, "Bearer") && o.Expires >= 60 && o.Expires <= 86400
}
func (c *Client) feishu(ctx context.Context, h *http.Client, config Config, secret, code, verifier string) (Identity, error) {
	if len(verifier) < 43 || len(verifier) > 128 {
		return Identity{}, ErrIdentity
	}
	endpoint := feishuAccounts(config) + "/oauth/v3/token"
	if config.OAuthVersion == "v2" {
		endpoint = feishuAPI(config) + "/open-apis/authen/v2/oauth/token"
	}
	var token oauthToken
	e := send(ctx, h, "POST", endpoint, nil, map[string]string{"grant_type": "authorization_code", "client_id": config.ClientID, "client_secret": secret, "code": code, "redirect_uri": config.CallbackURL, "code_verifier": verifier}, nil, &token)
	if e != nil {
		return Identity{}, e
	}
	if !token.valid() {
		return Identity{}, ErrIdentity
	}
	var profile struct {
		Code *int `json:"code"`
		Data struct {
			OpenID    string `json:"open_id"`
			TenantKey string `json:"tenant_key"`
			UserID    string `json:"user_id"`
		} `json:"data"`
	}
	e = send(ctx, h, "GET", feishuAPI(config)+"/open-apis/authen/v1/user_info", nil, nil, http.Header{"Authorization": {"Bearer " + token.Token}}, &profile)
	if e != nil {
		return Identity{}, e
	}
	if profile.Code == nil || *profile.Code != 0 || profile.Data.TenantKey != config.TenantID || !identifier.MatchString(profile.Data.OpenID) || !identifier.MatchString(profile.Data.UserID) {
		return Identity{}, ErrIdentity
	}
	app, e := c.appToken(ctx, h, config, secret)
	if e != nil {
		return Identity{}, e
	}
	var member struct {
		Code *int `json:"code"`
		Data struct {
			User struct {
				OpenID string `json:"open_id"`
				UserID string `json:"user_id"`
				Status struct {
					Activated *bool `json:"is_activated"`
					Frozen    *bool `json:"is_frozen"`
					Resigned  *bool `json:"is_resigned"`
					Exited    *bool `json:"is_exited"`
					Unjoined  *bool `json:"is_unjoin"`
				} `json:"status"`
			} `json:"user"`
		} `json:"data"`
	}
	e = send(ctx, h, "GET", feishuAPI(config)+"/open-apis/contact/v3/users/"+url.PathEscape(profile.Data.OpenID), url.Values{"user_id_type": {"open_id"}}, nil, http.Header{"Authorization": {"Bearer " + app}}, &member)
	if e != nil {
		return Identity{}, e
	}
	status := member.Data.User.Status
	if member.Code == nil || *member.Code != 0 || member.Data.User.OpenID != profile.Data.OpenID || member.Data.User.UserID != profile.Data.UserID || status.Activated == nil || !*status.Activated || status.Frozen == nil || *status.Frozen || status.Resigned == nil || *status.Resigned || status.Exited == nil || *status.Exited || status.Unjoined == nil || *status.Unjoined {
		return Identity{}, ErrIdentity
	}
	return Identity{profile.Data.OpenID}, nil
}
