package replaystore

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"hash"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
)

type CloudConfig struct {
	Provider        string `json:"provider"`
	Endpoint        string `json:"endpoint"`
	Region          string `json:"region"`
	Bucket          string `json:"bucket"`
	PathStyle       bool   `json:"path_style"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
	SessionToken    string `json:"session_token,omitempty"`
	RootCAPEM       string `json:"root_ca_pem,omitempty"`
}
type Cloud struct {
	config    CloudConfig
	http      *http.Client
	transport *http.Transport
	now       func() time.Time
}

var bucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
var regionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

func cleanHeader(s string, max int) bool {
	return len(s) <= max && strings.IndexFunc(s, unicode.IsControl) < 0
}
func ValidateCloud(c CloudConfig, requireSecret bool) error {
	if c.Provider != "s3" && c.Provider != "oss" && c.Provider != "cos" && c.Provider != "obs" {
		return ErrInvalid
	}
	u, e := url.Parse(c.Endpoint)
	if e != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || len(c.Endpoint) > 2048 {
		return ErrInvalid
	}
	loop := u.Hostname() == "localhost"
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		loop = ip.IsLoopback()
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && loop) {
		return ErrInvalid
	}
	if (loop || net.ParseIP(u.Hostname()) != nil) && !c.PathStyle {
		return ErrInvalid
	}
	if !bucketPattern.MatchString(c.Bucket) || strings.Contains(c.Bucket, "..") || !regionPattern.MatchString(c.Region) || c.AccessKeyID == "" || !cleanHeader(c.AccessKeyID, 256) || !cleanHeader(c.SecretAccessKey, 8192) || !cleanHeader(c.SessionToken, 16384) || requireSecret && c.SecretAccessKey == "" || len(c.RootCAPEM) > 65536 {
		return ErrInvalid
	}
	if c.PathStyle && c.Provider != "s3" && !loop {
		return ErrInvalid
	}
	if c.RootCAPEM != "" {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(c.RootCAPEM)) {
			return ErrInvalid
		}
	}
	return nil
}
func NewCloud(c CloudConfig) (*Cloud, error) {
	if e := ValidateCloud(c, true); e != nil {
		return nil, e
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, MaxIdleConns: 4, MaxIdleConnsPerHost: 4, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	if c.RootCAPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(c.RootCAPEM)) {
			return nil, ErrInvalid
		}
		transport.TLSClientConfig.RootCAs = pool
	}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Cloud{config: c, http: client, transport: transport, now: time.Now}, nil
}
func (c *Cloud) endpoint(key string) (*url.URL, error) {
	if !ValidKey(key) {
		return nil, ErrInvalid
	}
	u, e := url.Parse(c.config.Endpoint)
	if e != nil {
		return nil, ErrInvalid
	}
	if c.config.PathStyle {
		u.Path = "/" + c.config.Bucket + "/" + key
	} else {
		if net.ParseIP(u.Hostname()) != nil || u.Hostname() == "localhost" {
			return nil, ErrInvalid
		}
		u.Host = c.config.Bucket + "." + u.Host
		u.Path = "/" + key
	}
	return u, nil
}
func (c *Cloud) request(ctx context.Context, method, key string, body io.Reader, size int64, digest string) (*http.Response, error) {
	u, e := c.endpoint(key)
	if e != nil {
		return nil, e
	}
	r, e := http.NewRequestWithContext(ctx, method, u.String(), body)
	if e != nil {
		return nil, ErrInvalid
	}
	r.ContentLength = size
	r.Header.Set("Content-Type", "application/octet-stream")
	if method == "PUT" {
		switch c.config.Provider {
		case "s3":
			r.Header.Set("If-None-Match", "*")
		case "oss":
			r.Header.Set("X-Oss-Forbid-Overwrite", "true")
		case "cos":
			r.Header.Set("X-Cos-Forbid-Overwrite", "true")
		case "obs":
			r.Header.Set("X-Obs-Forbid-Overwrite", "true")
		}
	}
	c.sign(r, key, digest, c.now())
	response, e := c.http.Do(r)
	if e != nil {
		return nil, ErrUnavailable
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return response, nil
	}
	_ = response.Body.Close()
	switch response.StatusCode {
	case 404:
		return nil, ErrNotFound
	case 409, 412:
		return nil, ErrExists
	}
	return nil, ErrUnavailable
}
func (c *Cloud) Put(ctx context.Context, key string, body io.Reader, size int64, digest string) error {
	if !ValidKey(key) || size < 1 || size > MaxObjectBytes || !ValidDigest(digest) || body == nil {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	tracked := &uploadBody{r: body, h: sha256.New(), done: make(chan struct{})}
	r, e := c.request(ctx, "PUT", key, tracked, size, digest)
	select {
	case <-tracked.done:
	case <-ctx.Done():
		if r != nil {
			_ = r.Body.Close()
		}
		return ErrUnavailable
	}
	if e != nil {
		return e
	}
	defer r.Body.Close()
	tracked.mu.Lock()
	valid := tracked.bytes == size && hex.EncodeToString(tracked.h.Sum(nil)) == digest
	tracked.mu.Unlock()
	if !valid {
		return ErrIntegrity
	}
	_, e = io.Copy(io.Discard, io.LimitReader(r.Body, 4096))
	if e != nil {
		return ErrUnavailable
	}
	return nil
}

type uploadBody struct {
	r     io.Reader
	mu    sync.Mutex
	h     hash.Hash
	bytes int64
	done  chan struct{}
	once  sync.Once
}

func (b *uploadBody) Read(p []byte) (int, error) {
	n, e := b.r.Read(p)
	if n > 0 {
		b.mu.Lock()
		b.bytes += int64(n)
		_, _ = b.h.Write(p[:n])
		b.mu.Unlock()
	}
	return n, e
}
func (b *uploadBody) Close() error { b.once.Do(func() { close(b.done) }); return nil }
func (c *Cloud) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	r, e := c.request(ctx, "GET", key, nil, 0, emptySHA256)
	if e != nil {
		return nil, e
	}
	return r.Body, nil
}
func (c *Cloud) Close() error { c.transport.CloseIdleConnections(); return nil }
