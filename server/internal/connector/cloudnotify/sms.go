package cloudnotify

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func (c *Client) SendSMS(ctx context.Context, kind string, cfg SMSConfig, secret, ca, to, id string, verification bool, fields map[string]string, check func() error) Outcome {
	if ValidateSMS(kind, cfg) != nil || !validSecret(secret) || !phonePattern.MatchString(to) || len(id) > 128 {
		return fail("invalid_configuration")
	}
	t := cfg.Notification
	if verification {
		t = cfg.Verification
	}
	parameters := make([]string, 0, len(t.Parameters))
	named := map[string]string{}
	for _, key := range t.Parameters {
		value, ok := fields[key]
		if !ok || len(value) > 2048 {
			return fail("invalid_payload")
		}
		parameters = append(parameters, value)
		named[key] = value
	}
	if verification {
		value := fields["code"]
		if len(value) != 6 || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return fail("invalid_payload")
		}
	}
	if kind == "cmpp" {
		body := t.ID
		for key, value := range named {
			body = strings.ReplaceAll(body, "{"+key+"}", value)
		}
		return c.sendCMPP(ctx, cfg, secret, ca, to, "【"+cfg.SignName+"】"+body, check)
	}
	var request *http.Request
	var e error
	switch kind {
	case "aliyun":
		// The native 2017-05-25 RPC API supports ACS3 request signing.
		values := url.Values{"PhoneNumbers": {strings.TrimPrefix(to, "+")}, "SignName": {cfg.SignName}, "TemplateCode": {t.ID}, "OutId": {id}}
		if !strings.HasPrefix(to, "+86") {
			return fail("unsupported_destination")
		}
		values.Set("PhoneNumbers", strings.TrimPrefix(to, "+86"))
		raw, _ := json.Marshal(named)
		values.Set("TemplateParam", string(raw))
		encoded := values.Encode()
		request, e = http.NewRequestWithContext(ctx, "POST", "https://dysmsapi.aliyuncs.com/", strings.NewReader(encoded))
		if e != nil {
			return fail("invalid_configuration")
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		var nonce [16]byte
		if _, e = io.ReadFull(rand.Reader, nonce[:]); e != nil {
			return fail("unavailable")
		}
		request.Header.Set("X-Acs-Action", "SendSms")
		request.Header.Set("X-Acs-Version", "2017-05-25")
		request.Header.Set("X-Acs-Date", c.Now().UTC().Format("2006-01-02T15:04:05Z"))
		request.Header.Set("X-Acs-Signature-Nonce", hex.EncodeToString(nonce[:]))
		request.Header.Set("X-Acs-Content-Sha256", sum(encoded))
		headers := "content-type:application/x-www-form-urlencoded\nhost:" + request.URL.Host + "\nx-acs-action:SendSms\nx-acs-content-sha256:" + sum(encoded) + "\nx-acs-date:" + request.Header.Get("X-Acs-Date") + "\nx-acs-signature-nonce:" + request.Header.Get("X-Acs-Signature-Nonce") + "\nx-acs-version:2017-05-25\n"
		signed := "content-type;host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version"
		canonical := "POST\n/\n\n" + headers + "\n" + signed + "\n" + sum(encoded)
		signature := hex.EncodeToString(mac([]byte(secret), "ACS3-HMAC-SHA256\n"+sum(canonical)))
		request.Header.Set("Authorization", "ACS3-HMAC-SHA256 Credential="+cfg.AccessKeyID+",SignedHeaders="+signed+",Signature="+signature)
	case "tencent":
		body, _ := json.Marshal(map[string]any{"PhoneNumberSet": []string{to}, "SmsSdkAppId": cfg.AppID, "SignName": cfg.SignName, "TemplateId": t.ID, "TemplateParamSet": parameters, "SessionContext": id})
		request, e = http.NewRequestWithContext(ctx, "POST", "https://sms.tencentcloudapi.com/", bytes.NewReader(body))
		if e != nil {
			return fail("invalid_configuration")
		}
		c.signTencent(request, string(body), cfg, secret)
	case "huawei":
		params, _ := json.Marshal(parameters)
		values := url.Values{"from": {cfg.Sender}, "to": {to}, "templateId": {t.ID}, "templateParas": {string(params)}, "signature": {cfg.SignName}, "extend": {id}}
		request, e = http.NewRequestWithContext(ctx, "POST", strings.TrimRight(cfg.Endpoint, "/")+"/sms/batchSendSms/v1", strings.NewReader(values.Encode()))
		if e != nil {
			return fail("invalid_configuration")
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		c.signHuawei(request, values.Encode(), cfg, secret)
	}
	return c.request(ctx, request, ca, check, func(raw []byte) Outcome { return smsReceipt(kind, raw, to) })
}
func (c *Client) signTencent(r *http.Request, body string, cfg SMSConfig, secret string) {
	now := c.Now()
	stamp := strconv.FormatInt(now.Unix(), 10)
	day := now.UTC().Format("2006-01-02")
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	r.Header.Set("X-TC-Action", "SendSms")
	r.Header.Set("X-TC-Version", "2021-01-11")
	r.Header.Set("X-TC-Timestamp", stamp)
	r.Header.Set("X-TC-Region", cfg.Region)
	signed := "content-type;host"
	canonical := "POST\n/\n\ncontent-type:" + r.Header.Get("Content-Type") + "\nhost:" + r.URL.Host + "\n\n" + signed + "\n" + sum(body)
	scope := day + "/sms/tc3_request"
	key := mac([]byte("TC3"+secret), day)
	key = mac(key, "sms")
	key = mac(key, "tc3_request")
	signature := hex.EncodeToString(mac(key, "TC3-HMAC-SHA256\n"+stamp+"\n"+scope+"\n"+sum(canonical)))
	r.Header.Set("Authorization", "TC3-HMAC-SHA256 Credential="+cfg.AccessKeyID+"/"+scope+", SignedHeaders="+signed+", Signature="+signature)
}
func (c *Client) signHuawei(r *http.Request, body string, cfg SMSConfig, secret string) {
	stamp := c.Now().UTC().Format("20060102T150405Z")
	r.Header.Set("X-Sdk-Date", stamp)
	signed := "content-type;host;x-sdk-date"
	canonical := "POST\n/sms/batchSendSms/v1/\n\ncontent-type:application/x-www-form-urlencoded\nhost:" + r.URL.Host + "\nx-sdk-date:" + stamp + "\n\n" + signed + "\n" + sum(body)
	signature := hex.EncodeToString(mac([]byte(secret), "SDK-HMAC-SHA256\n"+stamp+"\n"+sum(canonical)))
	r.Header.Set("Authorization", "SDK-HMAC-SHA256 Access="+cfg.AccessKeyID+", SignedHeaders="+signed+", Signature="+signature)
}
func smsReceipt(kind string, raw []byte, to string) Outcome {
	switch kind {
	case "aliyun":
		var v struct {
			Code  string
			BizID string `json:"BizId"`
		}
		if json.Unmarshal(raw, &v) != nil || v.Code == "" {
			return uncertain("receipt_unavailable")
		}
		if v.Code != "OK" {
			return fail("provider_rejected")
		}
		return accepted(v.BizID)
	case "tencent":
		var v struct {
			Response struct {
				Error         *json.RawMessage
				SendStatusSet []struct{ Code, SerialNo, PhoneNumber string }
			}
		}
		if json.Unmarshal(raw, &v) != nil {
			return uncertain("receipt_unavailable")
		}
		if v.Response.Error != nil {
			return fail("provider_rejected")
		}
		if len(v.Response.SendStatusSet) != 1 {
			return uncertain("receipt_unavailable")
		}
		row := v.Response.SendStatusSet[0]
		if row.Code == "" {
			return uncertain("receipt_unavailable")
		}
		if row.Code != "Ok" {
			return fail("provider_rejected")
		}
		if row.PhoneNumber != to {
			return uncertain("receipt_unavailable")
		}
		return accepted(row.SerialNo)
	case "huawei":
		var v struct {
			Code   string `json:"code"`
			Result []struct{ Status, SmsMsgID, OriginTo string }
		}
		if json.Unmarshal(raw, &v) != nil || v.Code == "" {
			return uncertain("receipt_unavailable")
		}
		if v.Code != "000000" {
			return fail("provider_rejected")
		}
		if len(v.Result) != 1 {
			return uncertain("receipt_unavailable")
		}
		row := v.Result[0]
		if row.Status != "000000" {
			return fail("provider_rejected")
		}
		if row.OriginTo != to {
			return uncertain("receipt_unavailable")
		}
		return accepted(row.SmsMsgID)
	}
	return uncertain("receipt_unavailable")
}
