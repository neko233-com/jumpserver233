package casclient

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/neko233-com/jumpserver233/server/testsupport/casprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const service = "https://127.0.0.1:5177/api/v1/authentication/cas/callback?state=synthetic-state"

func tlsFixture(t *testing.T, o casprovider.Options) (*casprovider.Provider, Config) {
	t.Helper()
	p := casprovider.New("", o)
	server := httptest.NewTLSServer(p)
	t.Cleanup(server.Close)
	p.BaseURL = server.URL + "/cas"
	return p, Config{BaseURL: p.BaseURL, Protocol: "3", CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))}
}
func TestCAS2And3VerifyTLSServiceRenewAndOneUseTickets(t *testing.T) {
	for _, version := range []string{"2", "3"} {
		t.Run(version, func(t *testing.T) {
			p, c := tlsFixture(t, casprovider.Options{})
			c.Protocol = version
			require.NoError(t, (Client{}).Check(t.Context(), c))
			ticket, e := p.Issue(service)
			require.NoError(t, e)
			subject, e := (Client{}).Validate(t.Context(), c, service, ticket)
			require.NoError(t, e)
			assert.Equal(t, casprovider.Subject, subject)
			assert.True(t, p.ValidatedWithRenew.Load())
			_, e = (Client{}).Validate(t.Context(), c, service, ticket)
			assert.ErrorIs(t, e, ErrProvider)
			ticket, e = p.Issue(service)
			require.NoError(t, e)
			_, e = (Client{}).Validate(t.Context(), c, service+"-other", ticket)
			assert.ErrorIs(t, e, ErrProvider)
		})
	}
}
func TestCASTransportAndPrimaryAuthenticationRejectFailures(t *testing.T) {
	p, c := tlsFixture(t, casprovider.Options{})
	ticket, e := p.Issue(service)
	require.NoError(t, e)
	untrusted := c
	untrusted.CAPEM = ""
	_, e = (Client{}).Validate(t.Context(), untrusted, service, ticket)
	assert.ErrorIs(t, e, ErrProvider)
	_, e = (Client{}).Validate(t.Context(), c, service, "PT-proxy-ticket")
	assert.ErrorIs(t, e, ErrProvider)
	assert.Zero(t, p.Validations.Load())
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, e = (Client{}).Validate(ctx, c, service, ticket)
	assert.Error(t, e)
	p, c = tlsFixture(t, casprovider.Options{NotPrimary: true})
	ticket, e = p.Issue(service)
	require.NoError(t, e)
	_, e = (Client{}).Validate(t.Context(), c, service, ticket)
	assert.ErrorIs(t, e, ErrProvider)
	p, c = tlsFixture(t, casprovider.Options{ResponseOverride: strings.Repeat("x", (1<<20)+1)})
	ticket, e = p.Issue(service)
	require.NoError(t, e)
	_, e = (Client{}).Validate(t.Context(), c, service, ticket)
	assert.ErrorIs(t, e, ErrProvider)
}
func TestCASNeverFollowsValidationRedirects(t *testing.T) {
	hit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer server.Close()
	_, e := (Client{}).Validate(t.Context(), Config{BaseURL: server.URL, Protocol: "3", AllowLoopbackHTTP: true}, "http://127.0.0.1:5177/api/v1/authentication/cas/callback?state=x", "ST-test")
	assert.ErrorIs(t, e, ErrProvider)
	assert.False(t, hit)
}
func TestCASXMLRejectsAmbiguousOrUntrustedAssertions(t *testing.T) {
	wrap := func(body string) string {
		return `<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">` + body + `</cas:serviceResponse>`
	}
	success := `<cas:authenticationSuccess><cas:user>subject</cas:user></cas:authenticationSuccess>`
	cases := map[string]string{
		"CAS1": "yes\nsubject\n", "wrong namespace": `<serviceResponse><authenticationSuccess><user>subject</user></authenticationSuccess></serviceResponse>`,
		"two outcomes": wrap(success + `<cas:authenticationFailure code="INVALID_TICKET"/>`), "two successes": wrap(success + success),
		"two users":    wrap(`<cas:authenticationSuccess><cas:user>one</cas:user><cas:user>two</cas:user></cas:authenticationSuccess>`),
		"nested user":  wrap(`<cas:authenticationSuccess><cas:user><cas:value>subject</cas:value></cas:user></cas:authenticationSuccess>`),
		"empty user":   wrap(`<cas:authenticationSuccess><cas:user> </cas:user></cas:authenticationSuccess>`),
		"missing user": wrap(`<cas:authenticationSuccess/>`), "trailing document": wrap(success) + wrap(success),
		"directive": `<!DOCTYPE cas:serviceResponse>` + wrap(success), "entity": wrap(strings.Replace(success, "subject", "&unknown;", 1)),
		"proxy credentials": wrap(`<cas:authenticationSuccess><cas:user>subject</cas:user><cas:proxyGrantingTicket>secret</cas:proxyGrantingTicket></cas:authenticationSuccess>`),
		"proxy chain":       wrap(`<cas:authenticationSuccess><cas:user>subject</cas:user><cas:proxies><cas:proxy>other</cas:proxy></cas:proxies></cas:authenticationSuccess>`),
		"deep attributes":   wrap(`<cas:authenticationSuccess><cas:user>subject</cas:user>` + strings.Repeat(`<a>`, 35) + strings.Repeat(`</a>`, 35) + `</cas:authenticationSuccess>`),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) { _, e := parseResponse([]byte(raw)); assert.ErrorIs(t, e, ErrProvider) })
	}
	value, e := parseResponse([]byte(wrap(strings.Replace(success, "subject", "case&amp;exact", 1))))
	require.NoError(t, e)
	assert.Equal(t, "case&exact", value)
}
func TestCASConfigurationAllowsOnlyVerifiedHTTPSOrExplicitLoopback(t *testing.T) {
	c := Config{BaseURL: "https://cas.example.invalid/cas", Protocol: "3"}
	require.NoError(t, ValidateConfig(c))
	for _, raw := range []string{"http://cas.example.invalid/cas", "http://localhost/cas", "https://user:pass@cas.example.invalid/cas", "https://cas.example.invalid/cas?query=x", "https://cas.example.invalid/cas/../other"} {
		next := c
		next.BaseURL = raw
		next.AllowLoopbackHTTP = true
		assert.Error(t, ValidateConfig(next), raw)
	}
	c.BaseURL = "http://127.0.0.1:12345/cas"
	assert.Error(t, ValidateConfig(c))
	c.AllowLoopbackHTTP = true
	require.NoError(t, ValidateConfig(c))
	c.Protocol = "1"
	assert.Error(t, ValidateConfig(c))
}
