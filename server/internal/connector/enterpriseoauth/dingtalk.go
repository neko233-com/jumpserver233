package enterpriseoauth

import (
	"context"
	"net/http"
	"net/url"
)

func (c *Client) dingtalk(ctx context.Context, h *http.Client, config Config, secret, code string) (Identity, error) {
	var result struct {
		Token   string `json:"accessToken"`
		Expires int    `json:"expireIn"`
		CorpID  string `json:"corpId"`
	}
	e := send(ctx, h, "POST", "https://api.dingtalk.com/v1.0/oauth2/userAccessToken", nil, map[string]string{"clientId": config.ClientID, "clientSecret": secret, "code": code, "grantType": "authorization_code"}, nil, &result)
	if e != nil {
		return Identity{}, e
	}
	if !validToken(result.Token) || result.Expires < 60 || result.Expires > 86400 || result.CorpID != "" && result.CorpID != config.TenantID {
		return Identity{}, ErrIdentity
	}
	var me struct {
		UnionID string `json:"unionId"`
		Visitor *bool  `json:"visitor"`
	}
	e = send(ctx, h, "GET", "https://api.dingtalk.com/v1.0/contact/users/me", nil, nil, http.Header{"X-Acs-Dingtalk-Access-Token": {result.Token}}, &me)
	if e != nil {
		return Identity{}, e
	}
	if !identifier.MatchString(me.UnionID) || me.Visitor != nil && *me.Visitor {
		return Identity{}, ErrIdentity
	}
	app, e := c.appToken(ctx, h, config, secret)
	if e != nil {
		return Identity{}, e
	}
	var lookup struct {
		Code   *int `json:"errcode"`
		Result struct {
			UserID      string `json:"userid"`
			ContactType *int   `json:"contact_type"`
		} `json:"result"`
	}
	e = send(ctx, h, "POST", "https://oapi.dingtalk.com/topapi/user/getbyunionid", url.Values{"access_token": {app}}, map[string]string{"unionid": me.UnionID}, nil, &lookup)
	if e != nil {
		return Identity{}, e
	}
	if lookup.Code == nil || *lookup.Code != 0 || !identifier.MatchString(lookup.Result.UserID) || lookup.Result.ContactType == nil || *lookup.Result.ContactType != 0 {
		return Identity{}, ErrIdentity
	}
	var member struct {
		Code   *int `json:"errcode"`
		Result struct {
			UserID  string `json:"userid"`
			UnionID string `json:"unionid"`
			Active  *bool  `json:"active"`
		} `json:"result"`
	}
	e = send(ctx, h, "POST", "https://oapi.dingtalk.com/topapi/v2/user/get", url.Values{"access_token": {app}}, map[string]string{"userid": lookup.Result.UserID}, nil, &member)
	if e != nil {
		return Identity{}, e
	}
	if member.Code == nil || *member.Code != 0 || member.Result.UserID != lookup.Result.UserID || member.Result.UnionID != me.UnionID || member.Result.Active == nil || !*member.Result.Active {
		return Identity{}, ErrIdentity
	}
	return Identity{me.UnionID}, nil
}
