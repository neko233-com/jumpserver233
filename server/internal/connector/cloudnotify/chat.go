package cloudnotify

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
)

func (c *Client) SendChat(ctx context.Context, kind, token, secret, ca, id, message string, check func() error) Outcome {
	if !ChatKind(kind) || !botToken.MatchString(token) || secret != "" && !validSecret(secret) || kind == "dingtalk" && secret == "" {
		return fail("invalid_configuration")
	}
	limit := 3500
	if kind == "wecom" {
		limit = 2048
	}
	if len(message) > limit || message == "" {
		return fail("invalid_payload")
	}
	endpoint := ""
	payload := map[string]any{}
	stamp := strconv.FormatInt(c.Now().Unix(), 10)
	switch kind {
	case "wecom":
		endpoint = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?" + url.Values{"key": {token}}.Encode()
		payload = map[string]any{"msgtype": "text", "text": map[string]string{"content": message}}
	case "dingtalk":
		q := url.Values{"access_token": {token}}
		if secret != "" {
			ms := strconv.FormatInt(c.Now().UnixMilli(), 10)
			q.Set("timestamp", ms)
			q.Set("sign", base64.StdEncoding.EncodeToString(mac([]byte(secret), ms+"\n"+secret)))
		}
		endpoint = "https://oapi.dingtalk.com/robot/send?" + q.Encode()
		payload = map[string]any{"msgtype": "text", "text": map[string]string{"content": message}}
	case "feishu", "lark":
		host := "open.feishu.cn"
		if kind == "lark" {
			host = "open.larksuite.com"
		}
		endpoint = "https://" + host + "/open-apis/bot/v2/hook/" + url.PathEscape(token)
		payload = map[string]any{"msg_type": "text", "content": map[string]string{"text": message}}
		if secret != "" {
			payload["timestamp"] = stamp
			payload["sign"] = base64.StdEncoding.EncodeToString(mac([]byte(stamp+"\n"+secret), ""))
		}
	}
	raw, e := json.Marshal(payload)
	if e != nil {
		return fail("invalid_payload")
	}
	req, e := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(raw))
	if e != nil {
		return fail("invalid_configuration")
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	return c.request(ctx, req, ca, check, func(raw []byte) Outcome {
		var v struct {
			Code    *int `json:"code"`
			ErrCode *int `json:"errcode"`
			Status  *int `json:"StatusCode"`
		}
		if json.Unmarshal(raw, &v) != nil {
			return uncertain("receipt_unavailable")
		}
		code := v.ErrCode
		if kind == "feishu" || kind == "lark" {
			code = v.Code
			if code == nil {
				code = v.Status
			}
		}
		if code == nil {
			return uncertain("receipt_unavailable")
		}
		if *code != 0 {
			return fail("provider_rejected")
		}
		return accepted(id)
	})
}
