package oidclogin

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/neko233-com/jumpserver233/server/internal/core/identityscope"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"golang.org/x/oauth2"
)

var (
	ErrInvalid  = errors.New("invalid OIDC configuration")
	ErrConflict = errors.New("OIDC configuration revision changed")
	ErrDisabled = errors.New("OIDC is disabled")
	ErrFlow     = errors.New("OIDC browser flow is invalid or expired")
	ErrProvider = errors.New("OIDC provider validation failed")
	ErrCapacity = errors.New("OIDC flow or audit capacity reached")
)

type Config struct {
	Enabled           bool   `json:"enabled"`
	Issuer            string `json:"issuer"`
	ClientID          string `json:"client_id"`
	RedirectURL       string `json:"redirect_url"`
	TokenAuthMethod   string `json:"token_auth_method"`
	AllowLoopbackHTTP bool   `json:"allow_loopback_http"`
	ProvisionNew      bool   `json:"provision_new"`
	Revision          int    `json:"revision"`
}
type Input struct {
	Config
	ClientSecret string `json:"client_secret"`
	ClearSecret  bool   `json:"clear_secret"`
}
type Snapshot struct {
	Config
	HasClientSecret bool `json:"has_client_secret"`
}
type Audit struct {
	At      time.Time `json:"at"`
	ActorID string    `json:"actor_id"`
	Actor   string    `json:"actor"`
	Config  Config    `json:"config"`
}
type persisted struct {
	Config       Config  `json:"config"`
	ClientSecret string  `json:"client_secret"`
	Audit        []Audit `json:"audit"`
}
type envelope struct {
	Version    int    `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}
type runtime struct {
	revision int
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	client   *http.Client
	created  time.Time
}
type flow struct {
	nonce, verifier string
	proof           [32]byte
	revision        int
	expires         time.Time
}
type Pending struct {
	AuthGeneration int
	UserID         string
	SetupToken     string
	Revision       int
	Expires        time.Time
	Attempts       int
}
type Identity struct {
	Issuer, Subject string
	Provision       bool
	Revision        int
}
type Start struct {
	URL, Proof string
	Expires    time.Time
}
type Service struct {
	mu                           sync.Mutex
	discoverMu                   sync.Mutex
	path, publicURL, routePrefix string
	documents                    *storage.Documents
	aead                         cipher.AEAD
	data                         persisted
	runtime                      *runtime
	flows                        map[[32]byte]flow
	pending                      map[[32]byte]Pending
	now                          func() time.Time
}

const callbackPath = "/api/v1/authentication/oidc/callback"

func Open(path string, key []byte, documents *storage.Documents, publicURL string, prefixes ...string) (*Service, error) {
	if len(prefixes) > 1 {
		return nil, ErrInvalid
	}
	prefix := ""
	if len(prefixes) == 1 {
		prefix = prefixes[0]
	}
	if !identityscope.ValidPrefix(prefix) {
		return nil, ErrInvalid
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s := &Service{path: path, publicURL: publicURL, documents: documents, aead: aead, flows: map[[32]byte]flow{}, pending: map[[32]byte]Pending{}, now: time.Now, data: persisted{Config: Config{TokenAuthMethod: "client_secret_basic"}, Audit: []Audit{}}}
	s.routePrefix = prefix
	var raw []byte
	if documents != nil {
		raw, err = documents.LoadOrImport("oidc-config", path)
	} else {
		raw, err = os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
	}
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return s, nil
	}
	var e envelope
	if json.Unmarshal(raw, &e) != nil || e.Version != 1 || len(e.Nonce) != aead.NonceSize() {
		return nil, ErrInvalid
	}
	plain, err := aead.Open(nil, e.Nonce, e.Ciphertext, []byte("jms233/oidc/config/v1"))
	if err != nil {
		return nil, ErrInvalid
	}
	if json.Unmarshal(plain, &s.data) != nil || len(s.data.Audit) > 1000 || s.data.Config.Revision < 1 || s.validate(s.data.Config, s.data.ClientSecret) != nil {
		return nil, ErrInvalid
	}
	return s, nil
}
func endpoint(value string, loopback bool) bool {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || len(value) > 2048 {
		return false
	}
	return u.Scheme == "https" || (loopback && u.Scheme == "http" && net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).IsLoopback())
}
func origin(value string) string {
	u, err := url.Parse(value)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
func (s *Service) validate(c Config, secret string) error {
	if !slices.Contains([]string{"client_secret_basic", "client_secret_post", "none"}, c.TokenAuthMethod) || len(c.ClientID) > 256 || len(secret) > 4096 || strings.IndexFunc(secret, unicode.IsControl) >= 0 {
		return ErrInvalid
	}
	if !c.Enabled && c.Issuer == "" && c.RedirectURL == "" && c.ClientID == "" {
		return nil
	}
	if !endpoint(c.Issuer, c.AllowLoopbackHTTP) || !endpoint(c.RedirectURL, c.AllowLoopbackHTTP) || strings.TrimSpace(c.ClientID) == "" {
		return ErrInvalid
	}
	issuer, _ := url.Parse(c.Issuer)
	redirect, _ := url.Parse(c.RedirectURL)
	if issuer.RawQuery != "" || redirect.Path != s.routePrefix+callbackPath || redirect.RawQuery != "" {
		return ErrInvalid
	}
	if s.publicURL != "" {
		if origin(c.RedirectURL) != s.publicURL {
			return ErrInvalid
		}
	} else if ip := net.ParseIP(redirect.Hostname()); ip == nil || !ip.IsLoopback() {
		return ErrInvalid
	}
	if c.Enabled && c.TokenAuthMethod != "none" && secret == "" {
		return ErrInvalid
	}
	if c.TokenAuthMethod == "none" && secret != "" {
		return ErrInvalid
	}
	return nil
}
func (s *Service) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Snapshot{Config: s.data.Config, HasClientSecret: s.data.ClientSecret != ""}
}
func (s *Service) IssuerAllowed(issuer string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Config.Enabled && s.data.Config.Issuer == issuer
}
func (s *Service) Save(in Input, actorID, actor string) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.Revision != s.data.Config.Revision {
		return Snapshot{}, ErrConflict
	}
	if len(s.data.Audit) >= 1000 {
		return Snapshot{}, ErrCapacity
	}
	in.Issuer = strings.TrimSpace(in.Issuer)
	in.ClientID = strings.TrimSpace(in.ClientID)
	in.RedirectURL = strings.TrimSpace(in.RedirectURL)
	if in.TokenAuthMethod == "" {
		in.TokenAuthMethod = "client_secret_basic"
	}
	secret := s.data.ClientSecret
	if in.ClearSecret {
		secret = ""
	}
	if in.ClientSecret != "" {
		secret = in.ClientSecret
	}
	if err := s.validate(in.Config, secret); err != nil {
		return Snapshot{}, err
	}
	next := persisted{Config: in.Config, ClientSecret: secret, Audit: append([]Audit{}, s.data.Audit...)}
	next.Config.Revision++
	next.Audit = append(next.Audit, Audit{At: s.now().UTC(), ActorID: actorID, Actor: actor, Config: next.Config})
	if err := s.persist(next); err != nil {
		return Snapshot{}, err
	}
	s.data = next
	s.runtime = nil
	s.flows = map[[32]byte]flow{}
	s.pending = map[[32]byte]Pending{}
	return Snapshot{Config: next.Config, HasClientSecret: secret != ""}, nil
}
func (s *Service) Audit() []Audit {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]Audit{}, s.data.Audit...)
	slices.Reverse(out)
	return out
}

type guardedTransport struct {
	base     http.RoundTripper
	loopback bool
}
type limitedBody struct {
	io.Reader
	io.Closer
}

func (t guardedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !endpoint(r.URL.String(), t.loopback) {
		return nil, ErrProvider
	}
	response, err := t.base.RoundTrip(r)
	if err == nil {
		response.Body = limitedBody{Reader: io.LimitReader(response.Body, (1<<20)+1), Closer: response.Body}
	}
	return response, err
}
func (s *Service) getRuntime(ctx context.Context, allowDisabled ...bool) (*runtime, error) {
	permittedDisabled := len(allowDisabled) > 0 && allowDisabled[0]
	s.discoverMu.Lock()
	defer s.discoverMu.Unlock()
	s.mu.Lock()
	c, secret := s.data.Config, s.data.ClientSecret
	if !c.Enabled && !permittedDisabled {
		s.mu.Unlock()
		return nil, ErrDisabled
	}
	if s.runtime != nil && s.runtime.revision == c.Revision && s.now().Sub(s.runtime.created) < 5*time.Minute {
		r := s.runtime
		s.mu.Unlock()
		return r, nil
	}
	s.mu.Unlock()
	client := &http.Client{Timeout: 10 * time.Second, Transport: guardedTransport{base: http.DefaultTransport, loopback: c.AllowLoopbackHTTP}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	clientCtx := oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(clientCtx, c.Issuer)
	if err != nil {
		return nil, ErrProvider
	}
	var metadata struct {
		JWKS      string   `json:"jwks_uri"`
		Responses []string `json:"response_types_supported"`
		Methods   []string `json:"token_endpoint_auth_methods_supported"`
	}
	if provider.Claims(&metadata) != nil {
		return nil, ErrProvider
	}
	ep := provider.Endpoint()
	if !endpoint(ep.AuthURL, c.AllowLoopbackHTTP) || !endpoint(ep.TokenURL, c.AllowLoopbackHTTP) || !endpoint(metadata.JWKS, c.AllowLoopbackHTTP) || (len(metadata.Responses) > 0 && !slices.Contains(metadata.Responses, "code")) || (len(metadata.Methods) > 0 && !slices.Contains(metadata.Methods, c.TokenAuthMethod)) {
		return nil, ErrProvider
	}
	ep.AuthStyle = oauth2.AuthStyleInHeader
	if c.TokenAuthMethod == "client_secret_post" || c.TokenAuthMethod == "none" {
		ep.AuthStyle = oauth2.AuthStyleInParams
	}
	r := &runtime{revision: c.Revision, created: s.now(), client: client, oauth: oauth2.Config{ClientID: c.ClientID, ClientSecret: secret, Endpoint: ep, RedirectURL: c.RedirectURL, Scopes: []string{oidc.ScopeOpenID, "profile"}}, verifier: provider.VerifierContext(oidc.ClientContext(context.Background(), client), &oidc.Config{ClientID: c.ClientID, SupportedSigningAlgs: []string{oidc.RS256, oidc.RS384, oidc.RS512, oidc.ES256, oidc.ES384, oidc.ES512, "EdDSA"}})}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Config.Revision != c.Revision || (!s.data.Config.Enabled && !permittedDisabled) {
		return nil, ErrConflict
	}
	s.runtime = r
	return r, nil
}
func (s *Service) Check(ctx context.Context) error { _, err := s.getRuntime(ctx, true); return err }
func randomValue() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
func (s *Service) pruneLocked() {
	now := s.now()
	for key, f := range s.flows {
		if !now.Before(f.expires) {
			delete(s.flows, key)
		}
	}
	for key, p := range s.pending {
		if !now.Before(p.Expires) {
			delete(s.pending, key)
		}
	}
}
func (s *Service) Begin(ctx context.Context) (Start, error) {
	r, err := s.getRuntime(ctx)
	if err != nil {
		return Start{}, err
	}
	values := make([]string, 4)
	for i := range values {
		values[i], err = randomValue()
		if err != nil {
			return Start{}, err
		}
	}
	state, proof, nonce, verifier := values[0], values[1], values[2], values[3]
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	if !s.data.Config.Enabled || s.data.Config.Revision != r.revision {
		return Start{}, ErrConflict
	}
	if len(s.flows) >= 4096 {
		return Start{}, ErrCapacity
	}
	expires := s.now().Add(10 * time.Minute)
	s.flows[sha256.Sum256([]byte(state))] = flow{nonce: nonce, verifier: verifier, proof: sha256.Sum256([]byte(proof)), revision: r.revision, expires: expires}
	return Start{URL: r.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("max_age", "300")), Proof: proof, Expires: expires}, nil
}
func (s *Service) Finish(ctx context.Context, state, proof, code string) (Identity, error) {
	if state == "" || len(state) > 128 || proof == "" || len(proof) > 128 || code == "" || len(code) > 8192 {
		return Identity{}, ErrFlow
	}
	key := sha256.Sum256([]byte(state))
	s.mu.Lock()
	f, ok := s.flows[key]
	delete(s.flows, key)
	c := s.data.Config
	s.mu.Unlock()
	provided := sha256.Sum256([]byte(proof))
	if !ok || !s.now().Before(f.expires) || !c.Enabled || c.Revision != f.revision || subtle.ConstantTimeCompare(provided[:], f.proof[:]) != 1 {
		return Identity{}, ErrFlow
	}
	r, err := s.getRuntime(ctx)
	if err != nil || r.revision != f.revision {
		return Identity{}, ErrFlow
	}
	token, err := r.oauth.Exchange(oidc.ClientContext(ctx, r.client), code, oauth2.VerifierOption(f.verifier))
	if err != nil {
		return Identity{}, ErrProvider
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || len(raw) > 1<<20 {
		return Identity{}, ErrProvider
	}
	id, err := r.verifier.Verify(ctx, raw)
	if err != nil {
		return Identity{}, ErrProvider
	}
	var claims struct {
		AuthorizedParty string `json:"azp"`
		AuthTime        int64  `json:"auth_time"`
	}
	if id.Claims(&claims) != nil {
		return Identity{}, ErrProvider
	}
	now := s.now()
	if id.Issuer != c.Issuer || id.Subject == "" || len(id.Subject) > 1024 || id.Nonce != f.nonce || id.IssuedAt.IsZero() || id.IssuedAt.After(now.Add(30*time.Second)) || id.IssuedAt.Before(now.Add(-10*time.Minute)) || claims.AuthTime == 0 || time.Unix(claims.AuthTime, 0).After(now.Add(30*time.Second)) || time.Unix(claims.AuthTime, 0).Before(now.Add(-330*time.Second)) || (len(id.Audience) > 1 && claims.AuthorizedParty != c.ClientID) || (claims.AuthorizedParty != "" && claims.AuthorizedParty != c.ClientID) {
		return Identity{}, ErrProvider
	}
	if id.AccessTokenHash != "" && id.VerifyAccessToken(token.AccessToken) != nil {
		return Identity{}, ErrProvider
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.data.Config.Enabled || s.data.Config.Revision != f.revision {
		return Identity{}, ErrConflict
	}
	return Identity{Issuer: c.Issuer, Subject: id.Subject, Provision: c.ProvisionNew, Revision: c.Revision}, nil
}
func (s *Service) NewPending(userID string, revision int, generation ...int) (string, error) {
	ticket, err := randomValue()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	if !s.data.Config.Enabled || revision != s.data.Config.Revision {
		return "", ErrConflict
	}
	if len(s.pending) >= 4096 {
		return "", ErrCapacity
	}
	g := 0
	if len(generation) == 1 {
		g = generation[0]
	}
	s.pending[sha256.Sum256([]byte(ticket))] = Pending{AuthGeneration: g, UserID: userID, Revision: revision, Expires: s.now().Add(5 * time.Minute)}
	return ticket, nil
}
func (s *Service) Pending(ticket string, attempt bool) (Pending, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sha256.Sum256([]byte(ticket))
	p, ok := s.pending[key]
	if !ok || len(ticket) > 128 || !s.now().Before(p.Expires) || !s.data.Config.Enabled || p.Revision != s.data.Config.Revision || p.Attempts >= 5 {
		delete(s.pending, key)
		return Pending{}, ErrFlow
	}
	if attempt {
		p.Attempts++
		s.pending[key] = p
	}
	return p, nil
}
func (s *Service) SetSetup(ticket, setup string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sha256.Sum256([]byte(ticket))
	p, ok := s.pending[key]
	if !ok || !s.now().Before(p.Expires) || p.Revision != s.data.Config.Revision {
		return ErrFlow
	}
	p.SetupToken = setup
	s.pending[key] = p
	return nil
}
func (s *Service) ConsumePending(ticket string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sha256.Sum256([]byte(ticket))
	p, ok := s.pending[key]
	delete(s.pending, key)
	return ok && s.data.Config.Enabled && p.Revision == s.data.Config.Revision && s.now().Before(p.Expires)
}
func (s *Service) ReturnURL(path string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	path = identityscope.ReturnPath(s.routePrefix, path)
	if s.data.Config.RedirectURL == "" {
		return path
	}
	return origin(s.data.Config.RedirectURL) + path
}
func (s *Service) SecureCookies() bool {
	u, err := url.Parse(s.Snapshot().RedirectURL)
	return err == nil && u.Scheme == "https"
}
func (s *Service) persist(next persisted) error {
	plain, err := json.Marshal(next)
	if err != nil {
		return err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	raw, err := json.Marshal(envelope{Version: 1, Nonce: nonce, Ciphertext: s.aead.Seal(nil, nonce, plain, []byte("jms233/oidc/config/v1"))})
	if err != nil {
		return err
	}
	if s.documents != nil {
		return s.documents.Save("oidc-config", raw)
	}
	if err = os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".oidc-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), s.path)
}
