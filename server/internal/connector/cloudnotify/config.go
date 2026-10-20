// Package cloudnotify implements native SMS and enterprise chat transports.
// It owns no goroutines or persistence; the caller owns delivery and retries.
package cloudnotify

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

var ErrConfig = errors.New("invalid native notification configuration")
var namePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
var phonePattern = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)
var botToken = regexp.MustCompile(`^[A-Za-z0-9_-]{8,256}$`)
var sourcePattern = regexp.MustCompile(`^[0-9]{6}$`)

type Template struct {
	ID         string   `json:"id"`
	Parameters []string `json:"parameters"`
}
type SMSConfig struct {
	AccessKeyID  string   `json:"access_key_id"`
	Region       string   `json:"region"`
	AppID        string   `json:"app_id"`
	Endpoint     string   `json:"endpoint"`
	Sender       string   `json:"sender"`
	ServiceID    string   `json:"service_id"`
	SignName     string   `json:"sign_name"`
	Verification Template `json:"verification"`
	Notification Template `json:"notification"`
}
type Outcome struct{ State, Code, Receipt string }

func text(v string, n int) bool {
	return len(v) <= n && utf8.ValidString(v) && strings.IndexFunc(v, unicode.IsControl) < 0
}
func SMSKind(kind string) bool {
	return slices.Contains([]string{"aliyun", "tencent", "huawei", "cmpp"}, kind)
}
func ChatKind(kind string) bool {
	return slices.Contains([]string{"wecom", "dingtalk", "feishu", "lark"}, kind)
}
func ValidateTemplate(kind string, t Template, verification bool) error {
	if t.ID == "" || !text(t.ID, 512) || len(t.Parameters) > 8 {
		return ErrConfig
	}
	if kind != "cmpp" && !namePattern.MatchString(t.ID) {
		return ErrConfig
	}
	seen := map[string]bool{}
	for _, v := range t.Parameters {
		if seen[v] || !slices.Contains([]string{"code", "title", "state", "id", "time", "link"}, v) || verification && v != "code" || !verification && v == "code" {
			return ErrConfig
		}
		seen[v] = true
	}
	if verification && (!seen["code"] || kind == "cmpp" && !strings.Contains(t.ID, "{code}")) {
		return ErrConfig
	}
	if kind == "cmpp" {
		value := t.ID
		for _, p := range t.Parameters {
			value = strings.ReplaceAll(value, "{"+p+"}", "")
		}
		if strings.ContainsAny(value, "{}") {
			return ErrConfig
		}
	}
	return nil
}
func ValidateSMS(kind string, c SMSConfig) error {
	if !SMSKind(kind) || !namePattern.MatchString(c.AccessKeyID) || !text(c.SignName, 64) || c.SignName == "" || !text(c.Sender, 32) || !text(c.ServiceID, 10) || ValidateTemplate(kind, c.Verification, true) != nil || ValidateTemplate(kind, c.Notification, false) != nil {
		return ErrConfig
	}
	switch kind {
	case "aliyun":
		if c.Region != "" && c.Region != "cn-hangzhou" || c.Endpoint != "" || c.AppID != "" {
			return ErrConfig
		}
	case "tencent":
		if !namePattern.MatchString(c.Region) || !namePattern.MatchString(c.AppID) || c.Endpoint != "" {
			return ErrConfig
		}
	case "huawei":
		u, e := url.Parse(c.Endpoint)
		if e != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || u.Path != "" && u.Path != "/" || !strings.HasPrefix(u.Hostname(), "smsapi.") || !strings.HasSuffix(u.Hostname(), ".myhuaweicloud.com") || u.Port() != "" && u.Port() != "443" || c.Sender == "" {
			return ErrConfig
		}
	case "cmpp":
		u, e := url.Parse(c.Endpoint)
		if e != nil || u.Scheme != "tls" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || !sourcePattern.MatchString(c.AccessKeyID) || c.Sender == "" || len(c.Sender) > 21 || !ascii(c.Sender) || !ascii(c.ServiceID) || len(c.SignName) > 32 {
			return ErrConfig
		}
		_, port, parseErr := net.SplitHostPort(u.Host)
		n, portErr := strconv.Atoi(port)
		if parseErr != nil || portErr != nil || n < 1 || n > 65535 || u.Hostname() == "" {
			return ErrConfig
		}
	}
	return nil
}
func ascii(v string) bool {
	for _, r := range v {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}
func validSecret(v string) bool { return v != "" && text(v, 4096) }
func TLSConfig(ca string) (*tls.Config, error) {
	if len(ca) > 65536 {
		return nil, ErrConfig
	}
	roots, e := x509.SystemCertPool()
	if e != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	raw := bytes.TrimSpace([]byte(ca))
	for len(raw) > 0 {
		if !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, ErrConfig
		}
		p, rest := pem.Decode(raw)
		if p == nil || p.Type != "CERTIFICATE" || len(p.Headers) > 0 {
			return nil, ErrConfig
		}
		cert, e := x509.ParseCertificate(p.Bytes)
		if e != nil {
			return nil, ErrConfig
		}
		roots.AddCert(cert)
		raw = bytes.TrimSpace(rest)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, nil
}
