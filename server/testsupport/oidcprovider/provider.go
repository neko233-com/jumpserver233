// Package oidcprovider is a loopback-only synthetic IdP for automated tests.
// Production server binaries never import this package.
package oidcprovider

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const ClientID = "synthetic-oidc-client"
const ClientSecret = "synthetic-oidc-client-secret-only"
const Subject = "synthetic-oidc-subject"

type Options struct {
	Subject         string
	IssuerOverride  string
	Audience        any
	AuthorizedParty string
	AuthMethod      string
	WrongNonce      bool
	Expired         bool
	FutureIssued    bool
	OldAuth         bool
	MissingAuthTime bool
	WrongSignature  bool
	BadAlgorithm    bool
}
type code struct {
	nonce, redirect, challenge string
	expires                    time.Time
}
type Provider struct {
	Issuer      string
	Options     Options
	mu          sync.Mutex
	key         *rsa.PrivateKey
	kid         string
	codes       map[string]code
	Exchanges   atomic.Int32
	PKCEChecked atomic.Bool
}

func New(issuer string, options Options) (*Provider, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &Provider{Issuer: issuer, Options: options, key: key, kid: "synthetic-key-1", codes: map[string]code{}}, nil
}
func (p *Provider) Rotate() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.key = key
	p.kid += "x"
	return nil
}
func (p *Provider) Issue(values url.Values) (string, error) {
	redirect, err := url.Parse(values.Get("redirect_uri"))
	if err != nil || net.ParseIP(redirect.Hostname()) == nil || !net.ParseIP(redirect.Hostname()).IsLoopback() || values.Get("client_id") != ClientID || values.Get("response_type") != "code" || values.Get("state") == "" || values.Get("nonce") == "" || values.Get("code_challenge_method") != "S256" || !strings.Contains(" "+values.Get("scope")+" ", " openid ") {
		return "", fmt.Errorf("invalid synthetic authorization")
	}
	var raw [24]byte
	if _, err = rand.Read(raw[:]); err != nil {
		return "", err
	}
	value := base64.RawURLEncoding.EncodeToString(raw[:])
	p.mu.Lock()
	p.codes[value] = code{nonce: values.Get("nonce"), redirect: values.Get("redirect_uri"), challenge: values.Get("code_challenge"), expires: time.Now().Add(time.Minute)}
	p.mu.Unlock()
	return value, nil
}
func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.URL.Path {
	case "/health":
		json.NewEncoder(w).Encode(map[string]string{"issuer": p.Issuer, "client_id": ClientID})
	case "/.well-known/openid-configuration":
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"issuer": p.Issuer, "authorization_endpoint": p.Issuer + "/authorize", "token_endpoint": p.Issuer + "/token", "jwks_uri": p.Issuer + "/keys", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"}})
	case "/keys":
		p.mu.Lock()
		key, kid := p.key, p.kid
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	case "/authorize":
		if r.Method == "GET" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			form := template.Must(template.New("auth").Parse(`<!doctype html><title>Synthetic OIDC provider</title><h1>Synthetic identity provider</h1><p>Local test fixture only. No real credentials are collected.</p><form method="post">{{range $key,$values := .}}{{range $values}}<input type="hidden" name="{{$key}}" value="{{.}}">{{end}}{{end}}<button type="submit">Continue as synthetic operator</button></form>`))
			_ = form.Execute(w, r.URL.Query())
			return
		}
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		_ = r.ParseForm()
		value, err := p.Issue(r.PostForm)
		if err != nil {
			http.Error(w, "invalid synthetic request", 400)
			return
		}
		location, _ := url.Parse(r.PostForm.Get("redirect_uri"))
		q := location.Query()
		q.Set("state", r.PostForm.Get("state"))
		q.Set("code", value)
		location.RawQuery = q.Encode()
		http.Redirect(w, r, location.String(), 303)
	case "/token":
		p.token(w, r)
	default:
		http.NotFound(w, r)
	}
}
func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	if r.ParseForm() != nil {
		w.WriteHeader(400)
		return
	}
	client, secret, ok := r.BasicAuth()
	if ok {
		client, _ = url.QueryUnescape(client)
		secret, _ = url.QueryUnescape(secret)
	} else {
		client = r.Form.Get("client_id")
		secret = r.Form.Get("client_secret")
	}
	method := p.Options.AuthMethod
	if method == "" {
		method = "client_secret_basic"
	}
	if client != ClientID || (method != "none" && secret != ClientSecret) || (method == "client_secret_basic" && !ok) || (method == "client_secret_post" && ok) || (method == "none" && secret != "") {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
		return
	}
	p.mu.Lock()
	record, exists := p.codes[r.Form.Get("code")]
	delete(p.codes, r.Form.Get("code"))
	key, kid := p.key, p.kid
	p.mu.Unlock()
	challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	if !exists || !time.Now().Before(record.expires) || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("redirect_uri") != record.redirect || base64.RawURLEncoding.EncodeToString(challenge[:]) != record.challenge {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}
	p.PKCEChecked.Store(true)
	p.Exchanges.Add(1)
	now := time.Now().Unix()
	subject := p.Options.Subject
	if subject == "" {
		subject = Subject
	}
	claims := map[string]any{"iss": p.Issuer, "sub": subject, "aud": ClientID, "iat": now, "exp": now + 300, "auth_time": now, "nonce": record.nonce, "preferred_username": "admin", "email": "admin@example.invalid", "roles": []string{"admin"}}
	if p.Options.IssuerOverride != "" {
		claims["iss"] = p.Options.IssuerOverride
	}
	if p.Options.Audience != nil {
		claims["aud"] = p.Options.Audience
	}
	if p.Options.AuthorizedParty != "" {
		claims["azp"] = p.Options.AuthorizedParty
	}
	if p.Options.WrongNonce {
		claims["nonce"] = "wrong-nonce"
	}
	if p.Options.Expired {
		claims["exp"] = now - 60
	}
	if p.Options.FutureIssued {
		claims["iat"] = now + 3600
	}
	if p.Options.OldAuth {
		claims["auth_time"] = now - 3600
	}
	if p.Options.MissingAuthTime {
		delete(claims, "auth_time")
	}
	signing := jose.SigningKey{Algorithm: jose.RS256, Key: key}
	if p.Options.WrongSignature {
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		signing.Key = other
	}
	if p.Options.BadAlgorithm {
		signing = jose.SigningKey{Algorithm: jose.HS256, Key: []byte(ClientSecret)}
	}
	signer, err := jose.NewSigner(signing, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		w.WriteHeader(500)
		return
	}
	payload, _ := json.Marshal(claims)
	signed, err := signer.Sign(payload)
	if err != nil {
		w.WriteHeader(500)
		return
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		w.WriteHeader(500)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"id_token": compact, "access_token": "synthetic-provider-access-token", "token_type": "Bearer", "expires_in": 300})
}
