// Package enterpriseoauth implements the native enterprise QR/OAuth transports.
// Endpoints are fixed by provider and region; administrators cannot redirect
// provider credentials to a configurable token or user-info URL.
package enterpriseoauth

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

var ErrConfig = errors.New("invalid enterprise login configuration")
var ErrIdentity = errors.New("enterprise identity rejected")
var ErrUnavailable = errors.New("enterprise identity provider unavailable")
var ErrCapacity = errors.New("enterprise identity provider capacity reached")

type Config struct {
	Provider          string   `json:"provider"`
	ClientID          string   `json:"client_id"`
	TenantID          string   `json:"tenant_id"`
	AgentID           string   `json:"agent_id"`
	Region            string   `json:"region"`
	OAuthVersion      string   `json:"oauth_version"`
	CallbackURL       string   `json:"callback_url"`
	Scopes            []string `json:"scopes"`
	CAPEM             string   `json:"ca_pem"`
	AllowLoopbackHTTP bool     `json:"allow_loopback_http"`
}
type Identity struct{ Subject string }
type Provider interface {
	Begin(Config, string, string) (string, error)
	Exchange(context.Context, Config, string, string, string) (Identity, error)
	Check(context.Context, Config, string) error
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9_:.@-]{1,256}$`)
var scopePattern = regexp.MustCompile(`^[A-Za-z0-9_:.-]{1,128}$`)
var agentPattern = regexp.MustCompile(`^[0-9]{1,32}$`)

func Kind(kind string) bool { return kind == "wecom" || kind == "dingtalk" || kind == "feishu" }
func Normalize(c Config) Config {
	c.ClientID = strings.TrimSpace(c.ClientID)
	c.TenantID = strings.TrimSpace(c.TenantID)
	c.AgentID = strings.TrimSpace(c.AgentID)
	c.CallbackURL = strings.TrimSpace(c.CallbackURL)
	if c.Region == "" {
		c.Region = "cn"
	}
	if c.OAuthVersion == "" {
		c.OAuthVersion = "v3"
	}
	if c.Provider == "wecom" && c.TenantID == "" {
		c.TenantID = c.ClientID
	}
	c.Scopes = slices.Clone(c.Scopes)
	if c.Scopes == nil {
		c.Scopes = []string{}
	}
	slices.Sort(c.Scopes)
	return c
}
func Validate(c Config) error {
	if !Kind(c.Provider) || !identifier.MatchString(c.ClientID) || !identifier.MatchString(c.TenantID) || len(c.CallbackURL) > 2048 || len(c.Scopes) > 16 || c.Region != "cn" && c.Region != "global" || c.OAuthVersion != "v2" && c.OAuthVersion != "v3" {
		return ErrConfig
	}
	if c.Provider != "feishu" && (c.Region != "cn" || len(c.Scopes) > 0) {
		return ErrConfig
	}
	if c.Provider == "wecom" {
		if c.TenantID != c.ClientID || !agentPattern.MatchString(c.AgentID) {
			return ErrConfig
		}
	} else if c.AgentID != "" {
		return ErrConfig
	}
	for i, s := range c.Scopes {
		if !scopePattern.MatchString(s) || s == "offline_access" || i > 0 && c.Scopes[i-1] >= s {
			return ErrConfig
		}
	}
	u, e := url.Parse(c.CallbackURL)
	if e != nil || u.Host == "" || u.User != nil || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" {
		return ErrConfig
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if !c.AllowLoopbackHTTP || u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return ErrConfig
		}
	}
	if _, e = tlsConfig(c); e != nil {
		return e
	}
	return nil
}
func tlsConfig(c Config) (*tls.Config, error) {
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	if len(c.CAPEM) > 262144 || c.CAPEM != "" && !roots.AppendCertsFromPEM([]byte(c.CAPEM)) {
		return nil, ErrConfig
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ClientSessionCache: tls.NewLRUClientSessionCache(32)}, nil
}
func callbackValues(c Config, state string) url.Values {
	return url.Values{"redirect_uri": {c.CallbackURL}, "state": {state}}
}
func authorizationURL(c Config, state, verifier string) (string, error) {
	if Validate(c) != nil || len(state) < 32 || len(state) > 128 {
		return "", ErrConfig
	}
	q := callbackValues(c, state)
	endpoint := ""
	switch c.Provider {
	case "wecom":
		endpoint = "https://login.work.weixin.qq.com/wwlogin/sso/login"
		q.Set("login_type", "CorpApp")
		q.Set("appid", c.ClientID)
		q.Set("agentid", c.AgentID)
	case "dingtalk":
		endpoint = "https://login.dingtalk.com/oauth2/auth"
		q.Set("client_id", c.ClientID)
		q.Set("response_type", "code")
		q.Set("scope", "openid")
		q.Set("prompt", "consent")
	case "feishu":
		endpoint = feishuAccounts(c) + "/open-apis/authen/v1/authorize"
		if len(verifier) < 43 || len(verifier) > 128 {
			return "", ErrConfig
		}
		challenge := sha256.Sum256([]byte(verifier))
		q.Set("client_id", c.ClientID)
		q.Set("response_type", "code")
		q.Set("code_challenge_method", "S256")
		q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
		if len(c.Scopes) > 0 {
			q.Set("scope", strings.Join(c.Scopes, " "))
		}
		q.Set("prompt", "consent")
	}
	return endpoint + "?" + q.Encode(), nil
}
func feishuAPI(c Config) string {
	if c.Region == "global" {
		return "https://open.larksuite.com"
	}
	return "https://open.feishu.cn"
}
func feishuAccounts(c Config) string {
	if c.Region == "global" {
		return "https://accounts.larksuite.com"
	}
	return "https://accounts.feishu.cn"
}
