package cloudnotify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"
	"time"
)

type Client struct {
	Transport func(*tls.Config) http.RoundTripper
	DialTLS   func(context.Context, string, *tls.Config) (net.Conn, error)
	Now       func() time.Time
}

func New() *Client {
	return &Client{Now: time.Now, Transport: func(tc *tls.Config) http.RoundTripper {
		return &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSClientConfig: tc, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16384, DisableCompression: true, DisableKeepAlives: true}
	}, DialTLS: func(ctx context.Context, address string, tc *tls.Config) (net.Conn, error) {
		return (&tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: tc}).DialContext(ctx, "tcp", address)
	}}
}
func sum(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
func mac(key []byte, v string) []byte {
	m := hmac.New(sha256.New, key)
	_, _ = io.WriteString(m, v)
	return m.Sum(nil)
}
func fail(code string) Outcome      { return Outcome{State: "failed", Code: code} }
func uncertain(code string) Outcome { return Outcome{State: "uncertain", Code: code} }
func guard(ctx context.Context, check func() error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if check != nil {
		return check()
	}
	return nil
}
func (c *Client) request(ctx context.Context, request *http.Request, ca string, check func() error, decode func([]byte) Outcome) Outcome {
	if guard(ctx, check) != nil {
		return Outcome{State: "suppressed", Code: "permission_changed"}
	}
	tc, e := TLSConfig(ca)
	if e != nil {
		return fail("invalid_configuration")
	}
	round := c.Transport(tc)
	if closeable, ok := round.(interface{ CloseIdleConnections() }); ok {
		defer closeable.CloseIdleConnections()
	}
	h := &http.Client{Transport: round, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var wrote atomic.Bool
	request = request.WithContext(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteRequest: func(httptrace.WroteRequestInfo) { wrote.Store(true) }}))
	response, e := h.Do(request)
	if e != nil {
		if wrote.Load() {
			return uncertain("receipt_unavailable")
		}
		var ce *tls.CertificateVerificationError
		if errors.As(e, &ce) {
			return fail("tls_invalid")
		}
		return Outcome{State: "retry", Code: "provider_unavailable"}
	}
	defer response.Body.Close()
	if response.StatusCode == 429 {
		return Outcome{State: "retry", Code: "provider_rate_limited"}
	}
	if response.StatusCode >= 500 {
		return uncertain("provider_unavailable")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fail("provider_rejected")
	}
	if response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return uncertain("receipt_unavailable")
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 65537))
	if e != nil || len(raw) > 65536 || !uniqueJSON(raw) {
		return uncertain("receipt_unavailable")
	}
	return decode(raw)
}
func uniqueJSON(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	var read func(int) bool
	read = func(depth int) bool {
		nodes++
		if depth > 16 || nodes > 8192 {
			return false
		}
		v, e := d.Token()
		if e != nil {
			return false
		}
		if p, ok := v.(json.Delim); ok {
			switch p {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					v, e := d.Token()
					k, ok := v.(string)
					if e != nil || !ok || seen[k] {
						return false
					}
					seen[k] = true
					if !read(depth + 1) {
						return false
					}
				}
				v, e := d.Token()
				return e == nil && v == json.Delim('}')
			case '[':
				for d.More() {
					if !read(depth + 1) {
						return false
					}
				}
				v, e := d.Token()
				return e == nil && v == json.Delim(']')
			default:
				return false
			}
		}
		return true
	}
	if !read(0) {
		return false
	}
	_, e := d.Token()
	return e == io.EOF
}
func accepted(receipt string) Outcome {
	if receipt == "" || !text(receipt, 128) {
		return uncertain("receipt_unavailable")
	}
	return Outcome{State: "sent", Receipt: receipt}
}
