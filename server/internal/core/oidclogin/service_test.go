package oidclogin

import (
	"context"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
	fixture "github.com/neko233-com/jumpserver233/server/testsupport/oidcprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setup(t *testing.T, options fixture.Options) (*Service, *fixture.Provider) {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	issuer := "http://" + server.Listener.Addr().String()
	provider, err := fixture.New(issuer, options)
	require.NoError(t, err)
	server.Config.Handler = provider
	server.Start()
	t.Cleanup(server.Close)
	s, err := Open(filepath.Join(t.TempDir(), "oidc.json"), make([]byte, 32), nil, "")
	require.NoError(t, err)
	secret := fixture.ClientSecret
	method := options.AuthMethod
	if method == "" {
		method = "client_secret_basic"
	}
	if method == "none" {
		secret = ""
	}
	_, err = s.Save(Input{Config: Config{Enabled: true, Issuer: issuer, ClientID: fixture.ClientID, RedirectURL: "http://127.0.0.1:5177" + callbackPath, AllowLoopbackHTTP: true, TokenAuthMethod: method}, ClientSecret: secret}, "admin", "admin")
	require.NoError(t, err)
	return s, provider
}
func startCode(t *testing.T, s *Service, p *fixture.Provider) (Start, string, string) {
	t.Helper()
	start, err := s.Begin(context.Background())
	require.NoError(t, err)
	u, err := url.Parse(start.URL)
	require.NoError(t, err)
	q := u.Query()
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.Equal(t, "300", q.Get("max_age"))
	assert.NotEmpty(t, q.Get("nonce"))
	code, err := p.Issue(q)
	require.NoError(t, err)
	return start, q.Get("state"), code
}
func TestVerifiedOIDCCodePKCEKeyRotationAndClientAuthModes(t *testing.T) {
	for _, method := range []string{"client_secret_basic", "client_secret_post", "none"} {
		t.Run(method, func(t *testing.T) {
			s, p := setup(t, fixture.Options{AuthMethod: method})
			for i := 0; i < 2; i++ {
				if i == 1 {
					require.NoError(t, p.Rotate())
				}
				start, state, code := startCode(t, s, p)
				identity, err := s.Finish(context.Background(), state, start.Proof, code)
				require.NoError(t, err)
				assert.Equal(t, p.Issuer, identity.Issuer)
				assert.Equal(t, fixture.Subject, identity.Subject)
				assert.False(t, identity.Provision)
				assert.True(t, p.PKCEChecked.Load())
				_, err = s.Finish(context.Background(), state, start.Proof, code)
				assert.ErrorIs(t, err, ErrFlow)
			}
		})
	}
}
func TestRejectsInvalidSignedIdentityClaimsAndSignatures(t *testing.T) {
	cases := map[string]fixture.Options{"issuer": {IssuerOverride: "https://other.example.invalid"}, "audience": {Audience: "other-client"}, "authorized-party": {Audience: []string{fixture.ClientID, "other"}, AuthorizedParty: "other"}, "missing-authorized-party": {Audience: []string{fixture.ClientID, "other"}}, "nonce": {WrongNonce: true}, "expiry": {Expired: true}, "future-issued": {FutureIssued: true}, "old-primary-auth": {OldAuth: true}, "missing-primary-auth": {MissingAuthTime: true}, "signature": {WrongSignature: true}, "HMAC-confusion": {BadAlgorithm: true}}
	for name, options := range cases {
		t.Run(name, func(t *testing.T) {
			s, p := setup(t, options)
			start, state, code := startCode(t, s, p)
			_, err := s.Finish(context.Background(), state, start.Proof, code)
			assert.ErrorIs(t, err, ErrProvider)
		})
	}
}
func TestBrowserProofExpiryPKCEAndConfigChangesInvalidateFlows(t *testing.T) {
	s, p := setup(t, fixture.Options{})
	start, state, code := startCode(t, s, p)
	_, err := s.Finish(context.Background(), state, "another-browser", code)
	assert.ErrorIs(t, err, ErrFlow)
	assert.Zero(t, p.Exchanges.Load())
	start, state, code = startCode(t, s, p)
	s.mu.Lock()
	for k, f := range s.flows {
		f.expires = time.Now().Add(-time.Second)
		s.flows[k] = f
	}
	s.mu.Unlock()
	_, err = s.Finish(context.Background(), state, start.Proof, code)
	assert.ErrorIs(t, err, ErrFlow)
	start, err = s.Begin(context.Background())
	require.NoError(t, err)
	u, _ := url.Parse(start.URL)
	q := u.Query()
	q.Set("code_challenge", "wrong")
	code, err = p.Issue(q)
	require.NoError(t, err)
	_, err = s.Finish(context.Background(), q.Get("state"), start.Proof, code)
	assert.ErrorIs(t, err, ErrProvider)
	start, state, code = startCode(t, s, p)
	cfg := s.Snapshot().Config
	cfg.ProvisionNew = true
	_, err = s.Save(Input{Config: cfg}, "admin", "admin")
	require.NoError(t, err)
	_, err = s.Finish(context.Background(), state, start.Proof, code)
	assert.ErrorIs(t, err, ErrFlow)
}
func TestEncryptedConfigurationWriteOnlySecretRevisionAndPendingTickets(t *testing.T) {
	s, _ := setup(t, fixture.Options{})
	snapshot := s.Snapshot()
	assert.True(t, snapshot.HasClientSecret)
	raw, err := os.ReadFile(s.path)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), fixture.ClientSecret)
	assert.NotContains(t, string(raw), snapshot.Issuer)
	restored, err := Open(s.path, make([]byte, 32), nil, "")
	require.NoError(t, err)
	assert.True(t, restored.Snapshot().HasClientSecret)
	_, err = s.Save(Input{Config: Config{Revision: 0}}, "a", "a")
	assert.ErrorIs(t, err, ErrConflict)
	ticket, err := s.NewPending("user", snapshot.Revision)
	require.NoError(t, err)
	p, err := s.Pending(ticket, false)
	require.NoError(t, err)
	assert.Equal(t, "user", p.UserID)
	require.NoError(t, s.SetSetup(ticket, "setup-only-token"))
	p, err = s.Pending(ticket, false)
	require.NoError(t, err)
	assert.Equal(t, "setup-only-token", p.SetupToken)
	assert.True(t, s.ConsumePending(ticket))
	assert.False(t, s.ConsumePending(ticket))
	ticket, err = s.NewPending("user", snapshot.Revision)
	require.NoError(t, err)
	for range 5 {
		_, err = s.Pending(ticket, true)
		require.NoError(t, err)
	}
	_, err = s.Pending(ticket, true)
	assert.ErrorIs(t, err, ErrFlow)
	snapshot.Enabled = false
	_, err = s.Save(Input{Config: snapshot.Config}, "admin", "admin")
	require.NoError(t, err)
	assert.False(t, s.IssuerAllowed(snapshot.Issuer))
	assert.Len(t, s.Audit(), 2)
}
func TestPublicOriginAndTransportConfigurationFailClosed(t *testing.T) {
	s, _ := setup(t, fixture.Options{})
	cfg := s.Snapshot().Config
	for name, value := range map[string]string{"plaintext": "http://idp.example.invalid", "credentials": "https://u:p@idp.example.invalid", "fragment": "https://idp.example.invalid/#bad"} {
		t.Run(name, func(t *testing.T) {
			bad := cfg
			bad.Issuer = value
			_, err := s.Save(Input{Config: bad}, "a", "a")
			assert.ErrorIs(t, err, ErrInvalid)
		})
	}
	bad := cfg
	bad.RedirectURL = "https://attacker.example.invalid" + callbackPath
	_, err := s.Save(Input{Config: bad}, "a", "a")
	assert.ErrorIs(t, err, ErrInvalid)
	bad = cfg
	bad.AllowLoopbackHTTP = false
	_, err = s.Save(Input{Config: bad}, "a", "a")
	assert.ErrorIs(t, err, ErrInvalid)
	s.publicURL = "https://console.example.invalid"
	bad = cfg
	bad.RedirectURL = s.publicURL + callbackPath
	_, err = s.Save(Input{Config: bad}, "a", "a")
	require.NoError(t, err)
	bad.RedirectURL = "https://other.example.invalid" + callbackPath
	bad.Revision++
	_, err = s.Save(Input{Config: bad}, "a", "a")
	assert.ErrorIs(t, err, ErrInvalid)
}
func TestOIDCPostgresEncryptedConfigReload(t *testing.T) {
	value := os.Getenv("JMS_TEST_DATABASE_URL")
	if value == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for OIDC PostgreSQL integration")
	}
	docs, err := storage.OpenPostgres(context.Background(), value, "oidc-test-"+time.Now().Format("150405.000000000"))
	require.NoError(t, err)
	defer docs.Close()
	defer docs.Delete("oidc-config")
	s, err := Open(filepath.Join(t.TempDir(), "oidc.json"), make([]byte, 32), docs, "")
	require.NoError(t, err)
	_, err = s.Save(Input{Config: Config{TokenAuthMethod: "client_secret_basic"}, ClientSecret: fixture.ClientSecret}, "admin", "admin")
	require.NoError(t, err)
	raw, err := docs.Load("oidc-config")
	require.NoError(t, err)
	assert.NotContains(t, string(raw), fixture.ClientSecret)
	next, err := Open(filepath.Join(t.TempDir(), "oidc.json"), make([]byte, 32), docs, "")
	require.NoError(t, err)
	assert.True(t, next.Snapshot().HasClientSecret)
	assert.Len(t, next.Audit(), 1)
}
