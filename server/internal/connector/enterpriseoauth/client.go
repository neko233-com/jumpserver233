package enterpriseoauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
)

type cachedToken struct {
	Token         string
	Expires, Used time.Time
}
type Client struct {
	mu        sync.Mutex
	tokens    map[[32]byte]cachedToken
	flights   map[[32]byte]chan struct{}
	slots     chan struct{}
	now       func() time.Time
	transport func(Config) (http.RoundTripper, func(), error)
}

func NewClient() *Client {
	return &Client{tokens: map[[32]byte]cachedToken{}, flights: map[[32]byte]chan struct{}{}, slots: make(chan struct{}, 16), now: time.Now, transport: transport}
}

// NewClientWithTransport supports embedders and isolated protocol fixtures. The
// application never exposes this injection point through provider configuration.
func NewClientWithTransport(factory func(Config) (http.RoundTripper, func(), error)) *Client {
	c := NewClient()
	if factory != nil {
		c.transport = factory
	}
	return c
}
func transport(c Config) (http.RoundTripper, func(), error) {
	tc, e := tlsConfig(c)
	if e != nil {
		return nil, nil, e
	}
	t := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: tc, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16384, MaxIdleConns: 4, MaxIdleConnsPerHost: 2, DisableCompression: true}
	return t, t.CloseIdleConnections, nil
}
func (c *Client) Begin(config Config, state, verifier string) (string, error) {
	return authorizationURL(config, state, verifier)
}
func clientFor(round http.RoundTripper) *http.Client {
	return &http.Client{Transport: round, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func validSecret(value string) bool {
	return value != "" && len(value) <= 4096 && strings.IndexFunc(value, unicode.IsControl) < 0
}
func validToken(value string) bool {
	return value != "" && len(value) <= 16384 && strings.IndexFunc(value, unicode.IsControl) < 0 && strings.TrimSpace(value) == value
}

// Detect duplicate JSON keys before typed decoding. Unknown profile fields are
// ignored, while malformed/ambiguous provider identity envelopes are rejected.
func unambiguous(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	var value func(int) bool
	value = func(depth int) bool {
		nodes++
		if depth > 16 || nodes > 8192 {
			return false
		}
		t, e := d.Token()
		if e != nil {
			return false
		}
		if delimiter, ok := t.(json.Delim); ok {
			switch delimiter {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					key, ok := k.(string)
					if e != nil || !ok || seen[key] {
						return false
					}
					seen[key] = true
					if !value(depth + 1) {
						return false
					}
				}
				end, e := d.Token()
				return e == nil && end == json.Delim('}')
			case '[':
				for d.More() {
					if !value(depth + 1) {
						return false
					}
				}
				end, e := d.Token()
				return e == nil && end == json.Delim(']')
			default:
				return false
			}
		}
		return true
	}
	if !value(0) {
		return false
	}
	_, e := d.Token()
	return e == io.EOF
}
func send(ctx context.Context, h *http.Client, method, endpoint string, query url.Values, body any, headers http.Header, out any) error {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" {
		return ErrConfig
	}
	if query != nil {
		u.RawQuery = query.Encode()
	}
	var data []byte
	if body != nil {
		data, e = json.Marshal(body)
		if e != nil || len(data) > 32768 {
			return ErrConfig
		}
	}
	request, e := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(data))
	if e != nil {
		return ErrUnavailable
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for key, values := range headers {
		request.Header[key] = slices.Clone(values)
	}
	response, e := h.Do(request)
	if e != nil {
		return ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return ErrUnavailable
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 131073))
	if e != nil || len(raw) > 131072 || !unambiguous(raw) || json.Unmarshal(raw, out) != nil {
		return ErrUnavailable
	}
	return nil
}
func (c *Client) Exchange(ctx context.Context, config Config, secret, code, verifier string) (Identity, error) {
	if Validate(config) != nil || !validSecret(secret) || code == "" || len(code) > 2048 || strings.IndexFunc(code, unicode.IsControl) >= 0 {
		return Identity{}, ErrConfig
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	case <-ctx.Done():
		return Identity{}, ErrUnavailable
	default:
		return Identity{}, ErrCapacity
	}
	round, close, e := c.transport(config)
	if e != nil {
		return Identity{}, e
	}
	defer close()
	h := clientFor(round)
	switch config.Provider {
	case "wecom":
		return c.wecom(ctx, h, config, secret, code)
	case "dingtalk":
		return c.dingtalk(ctx, h, config, secret, code)
	case "feishu":
		return c.feishu(ctx, h, config, secret, code, verifier)
	}
	return Identity{}, ErrConfig
}
func (c *Client) Check(ctx context.Context, config Config, secret string) error {
	if Validate(config) != nil || !validSecret(secret) {
		return ErrConfig
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		return ErrCapacity
	}
	round, close, e := c.transport(config)
	if e != nil {
		return e
	}
	defer close()
	_, e = c.appToken(ctx, clientFor(round), config, secret)
	return e
}
func (c *Client) appToken(ctx context.Context, h *http.Client, config Config, secret string) (string, error) {
	raw, _ := json.Marshal([]string{config.Provider, config.Region, config.OAuthVersion, config.ClientID, config.TenantID, config.AgentID, config.CAPEM, secret})
	key := sha256.Sum256(raw)
	for {
		c.mu.Lock()
		if cached, ok := c.tokens[key]; ok && c.now().Before(cached.Expires) {
			cached.Used = c.now()
			c.tokens[key] = cached
			c.mu.Unlock()
			return cached.Token, nil
		}
		if flight, ok := c.flights[key]; ok {
			c.mu.Unlock()
			select {
			case <-flight:
				continue
			case <-ctx.Done():
				return "", ErrUnavailable
			}
		}
		if len(c.flights) >= 32 {
			c.mu.Unlock()
			return "", ErrCapacity
		}
		done := make(chan struct{})
		c.flights[key] = done
		c.mu.Unlock()
		token, seconds, e := c.fetchAppToken(ctx, h, config, secret)
		c.mu.Lock()
		delete(c.flights, key)
		if e == nil {
			if len(c.tokens) >= 256 {
				var oldest [32]byte
				at := time.Time{}
				for k, v := range c.tokens {
					if at.IsZero() || v.Used.Before(at) {
						oldest, at = k, v.Used
					}
				}
				delete(c.tokens, oldest)
			}
			now := c.now()
			c.tokens[key] = cachedToken{token, now.Add(time.Duration(seconds-min(60, seconds/10)) * time.Second), now}
		}
		close(done)
		c.mu.Unlock()
		return token, e
	}
}
func (c *Client) fetchAppToken(ctx context.Context, h *http.Client, config Config, secret string) (string, int, error) {
	switch config.Provider {
	case "wecom":
		var result struct {
			Code    *int   `json:"errcode"`
			Token   string `json:"access_token"`
			Expires int    `json:"expires_in"`
		}
		e := send(ctx, h, "GET", "https://qyapi.weixin.qq.com/cgi-bin/gettoken", url.Values{"corpid": {config.ClientID}, "corpsecret": {secret}}, nil, nil, &result)
		if e != nil {
			return "", 0, e
		}
		if result.Code == nil || *result.Code != 0 || !validToken(result.Token) || result.Expires < 60 || result.Expires > 86400 {
			return "", 0, ErrIdentity
		}
		return result.Token, result.Expires, nil
	case "dingtalk":
		var result struct {
			Token   string `json:"accessToken"`
			Expires int    `json:"expireIn"`
		}
		e := send(ctx, h, "POST", "https://api.dingtalk.com/v1.0/oauth2/accessToken", nil, map[string]string{"appKey": config.ClientID, "appSecret": secret}, nil, &result)
		if e != nil {
			return "", 0, e
		}
		if !validToken(result.Token) || result.Expires < 60 || result.Expires > 86400 {
			return "", 0, ErrIdentity
		}
		return result.Token, result.Expires, nil
	case "feishu":
		if config.OAuthVersion == "v3" {
			var result oauthToken
			e := send(ctx, h, "POST", feishuAccounts(config)+"/oauth/v3/token", nil, map[string]string{"grant_type": "client_credentials", "client_id": config.ClientID, "client_secret": secret}, nil, &result)
			if e != nil {
				return "", 0, e
			}
			if !result.valid() {
				return "", 0, ErrIdentity
			}
			return result.Token, result.Expires, nil
		}
		var result struct {
			Code    *int   `json:"code"`
			Token   string `json:"tenant_access_token"`
			Expires int    `json:"expire"`
		}
		e := send(ctx, h, "POST", feishuAPI(config)+"/open-apis/auth/v3/tenant_access_token/internal", nil, map[string]string{"app_id": config.ClientID, "app_secret": secret}, nil, &result)
		if e != nil {
			return "", 0, e
		}
		if result.Code == nil || *result.Code != 0 || !validToken(result.Token) || result.Expires < 60 || result.Expires > 86400 {
			return "", 0, ErrIdentity
		}
		return result.Token, result.Expires, nil
	}
	return "", 0, ErrConfig
}
