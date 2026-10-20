package enterpriseprovider

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/cloudnotify"
)

const SMSKey = "synthetic-sms-access-key"
const NotifySecret = "synthetic-native-notification-secret"
const BotToken = "synthetic-bot-token"

type NotificationCapture struct {
	Provider string `json:"provider"`
	ID       string `json:"id"`
	To       string `json:"to"`
	Code     string `json:"code"`
	Text     string `json:"text"`
}

func (s *Server) NotificationCaptures() []NotificationCapture {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]NotificationCapture{}, s.notifications...)
	return out
}
func (s *Server) NativeClient() *cloudnotify.Client {
	c := cloudnotify.New()
	c.Transport = func(tc *tls.Config) http.RoundTripper {
		return &http.Transport{TLSClientConfig: tc, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, e := net.SplitHostPort(address)
			if e != nil || port != "443" || !official(host) {
				return nil, cloudnotify.ErrConfig
			}
			return (&net.Dialer{}).DialContext(ctx, network, s.TLS.Listener.Addr().String())
		}, DisableCompression: true, DisableKeepAlives: true}
	}
	return c
}
func SMSConfig(kind string) cloudnotify.SMSConfig {
	c := cloudnotify.SMSConfig{AccessKeyID: SMSKey, SignName: "Synthetic", Verification: cloudnotify.Template{ID: "verification-001", Parameters: []string{"code"}}, Notification: cloudnotify.Template{ID: "notification-001", Parameters: []string{"title", "state"}}}
	if kind == "tencent" {
		c.AppID = "1400000000"
		c.Region = "ap-guangzhou"
	}
	if kind == "huawei" {
		c.Endpoint = "https://smsapi.cn-north-4.myhuaweicloud.com"
		c.Sender = "csms100000001"
	}
	if kind == "cmpp" {
		c.AccessKeyID = "123456"
		c.Sender = "106900001"
		c.ServiceID = "test"
		c.Verification.ID = "Code {code}"
		c.Notification.ID = "{state}"
	}
	return c
}
func nativeMAC(key []byte, value string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = io.WriteString(h, value)
	return h.Sum(nil)
}
func nativeHash(v string) string { sum := sha256.Sum256([]byte(v)); return hex.EncodeToString(sum[:]) }
func verifyNativeSignature(r *http.Request, raw []byte, kind string) bool {
	auth := r.Header.Get("Authorization")
	canonical := ""
	stringToSign := ""
	var key []byte
	switch kind {
	case "aliyun":
		names := []string{"content-type", "host", "x-acs-action", "x-acs-content-sha256", "x-acs-date", "x-acs-signature-nonce", "x-acs-version"}
		if r.Header.Get("X-Acs-Action") != "SendSms" || r.Header.Get("X-Acs-Version") != "2017-05-25" || r.Header.Get("X-Acs-Content-Sha256") != nativeHash(string(raw)) {
			return false
		}
		headers := ""
		for _, name := range names {
			value := r.Header.Get(name)
			if name == "host" {
				value = r.Host
			}
			headers += name + ":" + value + "\n"
		}
		canonical = "POST\n/\n\n" + headers + "\n" + strings.Join(names, ";") + "\n" + nativeHash(string(raw))
		stringToSign = "ACS3-HMAC-SHA256\n" + nativeHash(canonical)
		key = []byte(NotifySecret)
		prefix := "ACS3-HMAC-SHA256 Credential=" + SMSKey + ",SignedHeaders=" + strings.Join(names, ";") + ",Signature="
		if !strings.HasPrefix(auth, prefix) {
			return false
		}
		auth = strings.TrimPrefix(auth, prefix)
	case "tencent":
		unix, e := strconv.ParseInt(r.Header.Get("X-TC-Timestamp"), 10, 64)
		if e != nil || r.Header.Get("X-TC-Action") != "SendSms" || r.Header.Get("X-TC-Version") != "2021-01-11" {
			return false
		}
		day := time.Unix(unix, 0).UTC().Format("2006-01-02")
		scope := day + "/sms/tc3_request"
		canonical = "POST\n/\n\ncontent-type:" + r.Header.Get("Content-Type") + "\nhost:" + r.Host + "\n\ncontent-type;host\n" + nativeHash(string(raw))
		key = nativeMAC([]byte("TC3"+NotifySecret), day)
		key = nativeMAC(key, "sms")
		key = nativeMAC(key, "tc3_request")
		stringToSign = "TC3-HMAC-SHA256\n" + r.Header.Get("X-TC-Timestamp") + "\n" + scope + "\n" + nativeHash(canonical)
		prefix := "TC3-HMAC-SHA256 Credential=" + SMSKey + "/" + scope + ", SignedHeaders=content-type;host, Signature="
		if !strings.HasPrefix(auth, prefix) {
			return false
		}
		auth = strings.TrimPrefix(auth, prefix)
	case "huawei":
		canonical = "POST\n/sms/batchSendSms/v1/\n\ncontent-type:application/x-www-form-urlencoded\nhost:" + r.Host + "\nx-sdk-date:" + r.Header.Get("X-Sdk-Date") + "\n\ncontent-type;host;x-sdk-date\n" + nativeHash(string(raw))
		stringToSign = "SDK-HMAC-SHA256\n" + r.Header.Get("X-Sdk-Date") + "\n" + nativeHash(canonical)
		key = []byte(NotifySecret)
		prefix := "SDK-HMAC-SHA256 Access=" + SMSKey + ", SignedHeaders=content-type;host;x-sdk-date, Signature="
		if !strings.HasPrefix(auth, prefix) {
			return false
		}
		auth = strings.TrimPrefix(auth, prefix)
	}
	got, e := hex.DecodeString(auth)
	return e == nil && hmac.Equal(got, nativeMAC(key, stringToSign))
}
func (s *Server) serveNativeNotification(w http.ResponseWriter, r *http.Request) bool {
	host := r.URL.Hostname()
	if host == "" {
		host = strings.Split(r.Host, ":")[0]
	}
	kind := ""
	switch {
	case host == "dysmsapi.aliyuncs.com":
		kind = "aliyun"
	case host == "sms.tencentcloudapi.com":
		kind = "tencent"
	case host == "smsapi.cn-north-4.myhuaweicloud.com":
		kind = "huawei"
	case r.URL.Path == "/cgi-bin/webhook/send":
		kind = "wecom"
	case r.URL.Path == "/robot/send":
		kind = "dingtalk"
	case strings.HasPrefix(r.URL.Path, "/open-apis/bot/v2/hook/"):
		kind = "feishu"
		if host == "open.larksuite.com" {
			kind = "lark"
		}
	default:
		return false
	}
	if r.Method != "POST" {
		http.Error(w, "synthetic method rejected", 405)
		return true
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, 32769))
	if e != nil || len(raw) > 32768 {
		http.Error(w, "synthetic body rejected", 400)
		return true
	}
	capture := NotificationCapture{Provider: kind}
	valid := true
	var payload map[string]json.RawMessage
	_ = json.Unmarshal(raw, &payload)
	if cloudnotify.SMSKind(kind) {
		valid = verifyNativeSignature(r, raw, kind)
		if kind == "aliyun" || kind == "huawei" {
			form, _ := url.ParseQuery(string(raw))
			capture.ID = form.Get("OutId")
			capture.To = "+86" + form.Get("PhoneNumbers")
			var vars map[string]string
			if kind == "aliyun" {
				_ = json.Unmarshal([]byte(form.Get("TemplateParam")), &vars)
				capture.Code = vars["code"]
			} else {
				capture.ID = form.Get("extend")
				capture.To = form.Get("to")
				var fields []string
				_ = json.Unmarshal([]byte(form.Get("templateParas")), &fields)
				if form.Get("templateId") == "verification-001" && len(fields) == 1 {
					capture.Code = fields[0]
				}
			}
		} else {
			var v struct {
				SessionContext                   string
				PhoneNumberSet, TemplateParamSet []string
				TemplateID                       string
			}
			_ = json.Unmarshal(raw, &v)
			capture.ID = v.SessionContext
			if len(v.PhoneNumberSet) == 1 {
				capture.To = v.PhoneNumberSet[0]
			}
			if v.TemplateID == "verification-001" && len(v.TemplateParamSet) == 1 {
				capture.Code = v.TemplateParamSet[0]
			}
		}
	} else {
		var v struct {
			Text            struct{ Content string }
			Content         struct{ Text string }
			Timestamp, Sign string
		}
		_ = json.Unmarshal(raw, &v)
		capture.Text = v.Text.Content
		if v.Content.Text != "" {
			capture.Text = v.Content.Text
		}
		if kind == "wecom" {
			valid = r.URL.Query().Get("key") == BotToken
		} else if kind == "dingtalk" {
			q := r.URL.Query()
			valid = q.Get("access_token") == BotToken && hmac.Equal([]byte(q.Get("sign")), []byte(base64.StdEncoding.EncodeToString(nativeMAC([]byte(NotifySecret), q.Get("timestamp")+"\n"+NotifySecret))))
		} else {
			valid = strings.TrimPrefix(r.URL.Path, "/open-apis/bot/v2/hook/") == BotToken && hmac.Equal([]byte(v.Sign), []byte(base64.StdEncoding.EncodeToString(nativeMAC([]byte(v.Timestamp+"\n"+NotifySecret), ""))))
		}
	}
	if !valid {
		http.Error(w, "synthetic signature rejected", 403)
		return true
	}
	s.mu.Lock()
	s.notifications = append(s.notifications, capture)
	if len(s.notifications) > 512 {
		s.notifications = s.notifications[len(s.notifications)-512:]
	}
	s.mu.Unlock()
	switch kind {
	case "aliyun":
		write(w, map[string]any{"Code": "OK", "BizId": "synthetic-ali-receipt"})
	case "tencent":
		write(w, map[string]any{"Response": map[string]any{"SendStatusSet": []any{map[string]string{"Code": "Ok", "SerialNo": "synthetic-tencent-receipt", "PhoneNumber": capture.To}}}})
	case "huawei":
		write(w, map[string]any{"code": "000000", "result": []any{map[string]string{"status": "000000", "smsMsgId": "synthetic-huawei-receipt", "originTo": capture.To}}})
	case "wecom", "dingtalk":
		write(w, map[string]int{"errcode": 0})
	default:
		write(w, map[string]int{"code": 0})
	}
	return true
}
