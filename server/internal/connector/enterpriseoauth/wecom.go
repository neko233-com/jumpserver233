package enterpriseoauth

import (
	"context"
	"net/http"
	"net/url"
)

func (c *Client) wecom(ctx context.Context, h *http.Client, config Config, secret, code string) (Identity, error) {
	if len(code) > 512 {
		return Identity{}, ErrIdentity
	}
	token, e := c.appToken(ctx, h, config, secret)
	if e != nil {
		return Identity{}, e
	}
	var identity struct {
		Code   *int   `json:"errcode"`
		UserID string `json:"userid"`
		OpenID string `json:"openid"`
		CorpID string `json:"corpid"`
	}
	e = send(ctx, h, "GET", "https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo", url.Values{"access_token": {token}, "code": {code}}, nil, nil, &identity)
	if e != nil {
		return Identity{}, e
	}
	if identity.Code == nil || *identity.Code != 0 || !identifier.MatchString(identity.UserID) || identity.OpenID != "" || identity.CorpID != "" && identity.CorpID != config.TenantID {
		return Identity{}, ErrIdentity
	}
	var member struct {
		Code   *int   `json:"errcode"`
		UserID string `json:"userid"`
		Status *int   `json:"status"`
		Enable *int   `json:"enable"`
	}
	e = send(ctx, h, "GET", "https://qyapi.weixin.qq.com/cgi-bin/user/get", url.Values{"access_token": {token}, "userid": {identity.UserID}}, nil, nil, &member)
	if e != nil {
		return Identity{}, e
	}
	if member.Code == nil || *member.Code != 0 || member.UserID != identity.UserID || member.Status == nil || *member.Status != 1 || member.Enable != nil && *member.Enable != 1 {
		return Identity{}, ErrIdentity
	}
	return Identity{identity.UserID}, nil
}
