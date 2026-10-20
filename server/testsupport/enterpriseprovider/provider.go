// Package enterpriseprovider supplies synthetic native-provider HTTPS contracts.
// It is linked only by tests and the existing isolated OAuth QA fixture process.
package enterpriseprovider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/enterpriseoauth"
)

const Secret = "synthetic-enterprise-application-secret"
const Tenant = "synthetic-enterprise-tenant"
const WeComClient = "synthetic-wecom-corp"
const DingClient = "synthetic-dingtalk-app"
const FeishuClient = "cli_synthetic_feishu"
const WeComSubject = "wecom.operator"
const DingSubject = "ding-union-operator"
const FeishuSubject = "ou_synthetic_operator"

var hosts = []string{"qyapi.weixin.qq.com", "login.work.weixin.qq.com", "api.dingtalk.com", "oapi.dingtalk.com", "login.dingtalk.com", "open.feishu.cn", "accounts.feishu.cn", "open.larksuite.com", "accounts.larksuite.com"}

type claim struct{ Kind, Client, Callback, Challenge, Scenario string }
type Server struct {
	CAPEM       string
	TLS         *httptest.Server
	mu          sync.Mutex
	codes       map[string]claim
	users       map[string]claim
	connections map[net.Conn]bool
	proxy       sync.WaitGroup
	closed      bool
	AppTokens   atomic.Int32
	Exchanges   atomic.Int32
	Requests    atomic.Int32
}

func New() (*Server, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic enterprise OAuth CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	ca, e := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if e != nil {
		return nil, e
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: hosts, NotBefore: root.NotBefore, NotAfter: root.NotAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	cert, e := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, key)
	if e != nil {
		return nil, e
	}
	s := &Server{CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca})), codes: map[string]claim{}, users: map[string]claim{}, connections: map[net.Conn]bool{}}
	server := httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{cert, ca}, PrivateKey: key}}}
	server.StartTLS()
	s.TLS = server
	return s, nil
}
func (s *Server) Close() {
	s.mu.Lock()
	s.closed = true
	for c := range s.connections {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.TLS.Close()
	s.proxy.Wait()
}
func (s *Server) Client() *enterpriseoauth.Client {
	return enterpriseoauth.NewClientWithTransport(func(c enterpriseoauth.Config) (http.RoundTripper, func(), error) {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(c.CAPEM)) {
			return nil, nil, enterpriseoauth.ErrConfig
		}
		t := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, e := net.SplitHostPort(address)
			if e != nil || port != "443" || !official(host) {
				return nil, enterpriseoauth.ErrConfig
			}
			return (&net.Dialer{}).DialContext(ctx, network, s.TLS.Listener.Addr().String())
		}, DisableCompression: true}
		return t, t.CloseIdleConnections, nil
	})
}
func official(host string) bool {
	for _, value := range hosts {
		if value == host {
			return true
		}
	}
	return false
}
func Config(kind, callback string) enterpriseoauth.Config {
	c := enterpriseoauth.Config{Provider: kind, CallbackURL: callback, Region: "cn", OAuthVersion: "v3", Scopes: []string{}, TenantID: Tenant}
	switch kind {
	case "wecom":
		c.ClientID = WeComClient
		c.TenantID = WeComClient
		c.AgentID = "1000001"
	case "dingtalk":
		c.ClientID = DingClient
	case "feishu":
		c.ClientID = FeishuClient
	}
	return c
}
func value() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func (s *Server) Issue(kind, callback, verifier, scenario string) string {
	c := Config(kind, callback)
	challenge := sha256.Sum256([]byte(verifier))
	code := "synthetic-code-" + value()
	s.mu.Lock()
	s.codes[code] = claim{kind, c.ClientID, callback, base64.RawURLEncoding.EncodeToString(challenge[:]), scenario}
	s.mu.Unlock()
	return code
}
func (s *Server) take(code, kind, client string) (claim, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.codes[code]
	delete(s.codes, code)
	return v, ok && v.Kind == kind && v.Client == client
}
func (s *Server) userToken(c claim) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	token := "synthetic-user-token-" + value()
	s.users[token] = c
	return token
}
func (s *Server) user(token string) (claim, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.users[token]
	return v, ok
}
func write(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func (s *Server) Authorize(w http.ResponseWriter, r *http.Request, kind string) {
	if !enterpriseoauth.Kind(kind) {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	client := q.Get("client_id")
	if kind == "wecom" {
		client = q.Get("appid")
	}
	expected := Config(kind, q.Get("redirect_uri"))
	if client != expected.ClientID || len(q.Get("state")) < 32 || q.Get("redirect_uri") == "" || kind == "feishu" && q.Get("code_challenge_method") != "S256" {
		http.Error(w, "synthetic authorization parameters rejected", 400)
		return
	}
	callback, e := url.Parse(q.Get("redirect_uri"))
	if e != nil || callback == nil {
		http.Error(w, "invalid synthetic callback", 400)
		return
	}
	ip := net.ParseIP(callback.Hostname())
	if ip == nil || !ip.IsLoopback() || callback.Scheme != "http" {
		http.Error(w, "synthetic authorization requires loopback callback", 400)
		return
	}
	code := "synthetic-code-" + value()
	s.mu.Lock()
	s.codes[code] = claim{kind, client, callback.String(), q.Get("code_challenge"), ""}
	s.mu.Unlock()
	back := *callback
	query := back.Query()
	query.Set("state", q.Get("state"))
	query.Set("code", code)
	back.RawQuery = query.Encode()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintf(w, `<!doctype html><html lang="en"><meta charset="utf-8"><title>Synthetic enterprise authorization</title><h1>Synthetic %s authorization</h1><p>No real provider account is used.</p><a href="%s">Continue as synthetic enterprise operator</a></html>`, html.EscapeString(kind), html.EscapeString(back.String()))
}
func decode(r *http.Request) map[string]string {
	var in map[string]string
	_ = json.NewDecoder(io.LimitReader(r.Body, 32768)).Decode(&in)
	return in
}
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.Requests.Add(1)
	if !official(strings.Split(r.Host, ":")[0]) {
		http.NotFound(w, r)
		return
	}
	in := map[string]string{}
	if r.Method == "POST" {
		in = decode(r)
	}
	path := r.URL.Path
	switch path {
	case "/cgi-bin/gettoken":
		if r.Method != "GET" || r.URL.Query().Get("corpid") != WeComClient || r.URL.Query().Get("corpsecret") != Secret {
			write(w, map[string]any{"errcode": 40013})
			return
		}
		s.AppTokens.Add(1)
		write(w, map[string]any{"errcode": 0, "access_token": "synthetic-app-wecom", "expires_in": 7200})
	case "/cgi-bin/auth/getuserinfo":
		if r.URL.Query().Get("access_token") != "synthetic-app-wecom" {
			write(w, map[string]any{"errcode": 40014})
			return
		}
		c, ok := s.take(r.URL.Query().Get("code"), "wecom", WeComClient)
		s.Exchanges.Add(1)
		if !ok {
			write(w, map[string]any{"errcode": 40029})
			return
		}
		s.mu.Lock()
		s.users["wecom-member"] = c
		s.mu.Unlock()
		if c.Scenario == "external" {
			write(w, map[string]any{"errcode": 0, "openid": "synthetic-outsider"})
			return
		}
		if c.Scenario == "duplicate" {
			_, _ = w.Write([]byte(`{"errcode":0,"errcode":1,"userid":"wecom.operator"}`))
			return
		}
		write(w, map[string]any{"errcode": 0, "userid": WeComSubject, "corpid": WeComClient})
	case "/cgi-bin/user/get":
		c, _ := s.user("wecom-member")
		status := 1
		if c.Scenario == "inactive" {
			status = 2
		}
		write(w, map[string]any{"errcode": 0, "userid": WeComSubject, "status": status, "enable": 1})
	case "/v1.0/oauth2/accessToken":
		if in["appKey"] != DingClient || in["appSecret"] != Secret {
			http.Error(w, "synthetic application rejected", 401)
			return
		}
		s.AppTokens.Add(1)
		write(w, map[string]any{"accessToken": "synthetic-app-dingtalk", "expireIn": 7200})
	case "/v1.0/oauth2/userAccessToken":
		if in["clientSecret"] != Secret || in["grantType"] != "authorization_code" {
			http.Error(w, "synthetic credentials rejected", 401)
			return
		}
		c, ok := s.take(in["code"], "dingtalk", in["clientId"])
		s.Exchanges.Add(1)
		if !ok {
			http.Error(w, "synthetic code rejected", 401)
			return
		}
		tenant := Tenant
		if c.Scenario == "tenant" {
			tenant = "other-tenant"
		}
		write(w, map[string]any{"accessToken": s.userToken(c), "expireIn": 7200, "corpId": tenant})
	case "/v1.0/contact/users/me":
		c, ok := s.user(r.Header.Get("X-Acs-Dingtalk-Access-Token"))
		if !ok {
			http.Error(w, "synthetic token rejected", 401)
			return
		}
		s.mu.Lock()
		s.users["ding-member"] = c
		s.mu.Unlock()
		write(w, map[string]any{"unionId": DingSubject, "visitor": c.Scenario == "external"})
	case "/topapi/user/getbyunionid":
		if r.URL.Query().Get("access_token") != "synthetic-app-dingtalk" || in["unionid"] != DingSubject {
			write(w, map[string]any{"errcode": 40014})
			return
		}
		write(w, map[string]any{"errcode": 0, "result": map[string]any{"userid": "ding.member", "contact_type": 0}})
	case "/topapi/v2/user/get":
		c, _ := s.user("ding-member")
		write(w, map[string]any{"errcode": 0, "result": map[string]any{"userid": "ding.member", "unionid": DingSubject, "active": c.Scenario != "inactive"}})
	case "/oauth/v3/token", "/open-apis/authen/v2/oauth/token", "/open-apis/auth/v3/tenant_access_token/internal":
		if path == "/open-apis/auth/v3/tenant_access_token/internal" || in["grant_type"] == "client_credentials" {
			client, secret := in["client_id"], in["client_secret"]
			if path == "/open-apis/auth/v3/tenant_access_token/internal" {
				client, secret = in["app_id"], in["app_secret"]
			}
			if client != FeishuClient || secret != Secret {
				write(w, map[string]any{"code": 20005})
				return
			}
			s.AppTokens.Add(1)
			if path == "/open-apis/auth/v3/tenant_access_token/internal" {
				write(w, map[string]any{"code": 0, "tenant_access_token": "synthetic-app-feishu", "expire": 7200})
			} else {
				write(w, map[string]any{"access_token": "synthetic-app-feishu", "token_type": "Bearer", "expires_in": 7200})
			}
			return
		}
		c, ok := s.take(in["code"], "feishu", in["client_id"])
		s.Exchanges.Add(1)
		challenge := sha256.Sum256([]byte(in["code_verifier"]))
		if !ok || in["client_secret"] != Secret || in["grant_type"] != "authorization_code" || in["redirect_uri"] != c.Callback || base64.RawURLEncoding.EncodeToString(challenge[:]) != c.Challenge {
			write(w, map[string]any{"error": "invalid_grant"})
			return
		}
		if c.Scenario == "redirect" {
			http.Redirect(w, r, "https://untrusted.invalid/credential-sink", 302)
			return
		}
		write(w, map[string]any{"code": 0, "access_token": s.userToken(c), "token_type": "Bearer", "expires_in": 7200})
	case "/open-apis/authen/v1/user_info":
		c, ok := s.user(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if !ok {
			http.Error(w, "synthetic token rejected", 401)
			return
		}
		s.mu.Lock()
		s.users["feishu-member"] = c
		s.mu.Unlock()
		tenant := Tenant
		if c.Scenario == "tenant" {
			tenant = "other-tenant"
		}
		write(w, map[string]any{"code": 0, "data": map[string]any{"open_id": FeishuSubject, "user_id": "feishu.member", "tenant_key": tenant}})
	case "/open-apis/contact/v3/users/" + FeishuSubject:
		c, _ := s.user("feishu-member")
		if r.Header.Get("Authorization") != "Bearer synthetic-app-feishu" || r.URL.Query().Get("user_id_type") != "open_id" {
			http.Error(w, "synthetic member scope rejected", 401)
			return
		}
		write(w, map[string]any{"code": 0, "data": map[string]any{"user": map[string]any{"open_id": FeishuSubject, "user_id": "feishu.member", "status": map[string]bool{"is_activated": c.Scenario != "inactive", "is_frozen": false, "is_resigned": false, "is_exited": false, "is_unjoin": c.Scenario == "external"}}}})
	default:
		http.NotFound(w, r)
	}
}

// HandleProxy handles CONNECT on the existing loopback OAuth fixture listener.
// Only native-provider hosts are redirected; other HTTPS requests retain their
// ordinary destination so unrelated isolated cases keep their network behavior.
func (s *Server) HandleProxy(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != "CONNECT" {
		return false
	}
	host, port, e := net.SplitHostPort(r.Host)
	if e != nil || port != "443" {
		http.Error(w, "invalid synthetic tunnel", 400)
		return true
	}
	target := r.Host
	if official(host) {
		target = s.TLS.Listener.Addr().String()
	}
	upstream, e := net.DialTimeout("tcp", target, 5*time.Second)
	if e != nil {
		http.Error(w, "synthetic tunnel unavailable", 502)
		return true
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "synthetic tunnel unavailable", 500)
		return true
	}
	downstream, buffer, e := hijacker.Hijack()
	if e != nil {
		upstream.Close()
		return true
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		upstream.Close()
		downstream.Close()
		return true
	}
	s.connections[upstream] = true
	s.connections[downstream] = true
	s.proxy.Add(1)
	s.mu.Unlock()
	defer s.proxy.Done()
	defer func() {
		upstream.Close()
		downstream.Close()
		s.mu.Lock()
		delete(s.connections, upstream)
		delete(s.connections, downstream)
		s.mu.Unlock()
	}()
	_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if buffer.Flush() != nil {
		return true
	}
	done := make(chan struct{})
	go func() { _, _ = io.Copy(upstream, buffer); _ = upstream.Close(); close(done) }()
	_, _ = io.Copy(downstream, upstream)
	_ = downstream.Close()
	<-done
	return true
}
