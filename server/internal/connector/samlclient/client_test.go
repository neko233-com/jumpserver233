package samlclient_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/neko233-com/jumpserver233/server/internal/connector/samlclient"
	"github.com/neko233-com/jumpserver233/server/testsupport/samlprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSAMLSignaturesAndStrictAssertionProfile(t *testing.T) {
	p, e := samlprovider.New("https://idp.example.invalid")
	require.NoError(t, e)
	key, e := samlclient.GenerateKey()
	require.NoError(t, e)
	cfg := samlclient.Config{EntityID: "https://console.example.invalid/sp", ACSURL: "https://console.example.invalid" + samlclient.ACSPath, MetadataXML: p.Metadata()}
	c, e := samlclient.New(cfg, key)
	require.NoError(t, e)
	id, location, e := c.Begin("browser-state")
	require.NoError(t, e)
	u, e := url.Parse(location)
	require.NoError(t, e)
	q := u.Query()
	assert.Equal(t, "browser-state", q.Get("RelayState"))
	assert.Contains(t, q.Get("SigAlg"), "rsa-sha256")
	query := "SAMLRequest=" + url.QueryEscape(q.Get("SAMLRequest")) + "&RelayState=browser-state&SigAlg=" + url.QueryEscape(q.Get("SigAlg"))
	hash := sha256.Sum256([]byte(query))
	signature, e := base64.StdEncoding.DecodeString(q.Get("Signature"))
	require.NoError(t, e)
	block, _ := pem.Decode(key.Certificate)
	cert, e := x509.ParseCertificate(block.Bytes)
	require.NoError(t, e)
	assert.NoError(t, rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hash[:], signature))
	req, state, e := samlprovider.Request(location)
	require.NoError(t, e)
	assert.Equal(t, "browser-state", state)
	assert.Equal(t, id, req.ID)
	raw, e := p.Response(req, nil)
	require.NoError(t, e)
	identity, e := c.Validate(raw, id)
	require.NoError(t, e)
	assert.Equal(t, samlprovider.Subject, identity.Subject)
	assert.NotEmpty(t, identity.AssertionID)
	metadata, e := c.Metadata()
	require.NoError(t, e)
	assert.Contains(t, string(metadata), cfg.ACSURL)
	assert.NotContains(t, string(metadata), "PRIVATE KEY")
	cases := map[string]func(*saml.Assertion, *saml.Response){
		"wrong issuer":          func(a *saml.Assertion, r *saml.Response) { a.Issuer.Value = "https://other.invalid" },
		"wrong response issuer": func(a *saml.Assertion, r *saml.Response) { r.Issuer.Value = "https://other.invalid" },
		"wrong audience": func(a *saml.Assertion, r *saml.Response) {
			a.Conditions.AudienceRestrictions[0].Audience.Value = "other"
		},
		"no audience":       func(a *saml.Assertion, r *saml.Response) { a.Conditions.AudienceRestrictions = nil },
		"wrong destination": func(a *saml.Assertion, r *saml.Response) { r.Destination = "https://other.invalid/acs" },
		"no destination":    func(a *saml.Assertion, r *saml.Response) { r.Destination = "" },
		"wrong request":     func(a *saml.Assertion, r *saml.Response) { r.InResponseTo = "foreign" },
		"wrong confirmation request": func(a *saml.Assertion, r *saml.Response) {
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = "foreign"
		},
		"bearer confirmation not-before": func(a *saml.Assertion, r *saml.Response) {
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotBefore = time.Now().Add(time.Hour)
		},
		"no confirmation data": func(a *saml.Assertion, r *saml.Response) {
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData = nil
		},
		"no confirmations": func(a *saml.Assertion, r *saml.Response) { a.Subject.SubjectConfirmations = nil },
		"no nameid":        func(a *saml.Assertion, r *saml.Response) { a.Subject.NameID = nil },
		"transient nameid": func(a *saml.Assertion, r *saml.Response) {
			a.Subject.NameID.Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
		},
		"wrong qualifier": func(a *saml.Assertion, r *saml.Response) { a.Subject.NameID.SPNameQualifier = "foreign" },
		"old authentication": func(a *saml.Assertion, r *saml.Response) {
			a.AuthnStatements[0].AuthnInstant = time.Now().Add(-time.Hour)
		},
		"future authentication": func(a *saml.Assertion, r *saml.Response) {
			a.AuthnStatements[0].AuthnInstant = time.Now().Add(time.Hour)
		},
		"no authentication": func(a *saml.Assertion, r *saml.Response) { a.AuthnStatements = nil },
		"expired assertion": func(a *saml.Assertion, r *saml.Response) { a.Conditions.NotOnOrAfter = time.Now().Add(-time.Hour) },
		"future assertion":  func(a *saml.Assertion, r *saml.Response) { a.Conditions.NotBefore = time.Now().Add(time.Hour) },
		"long validity":     func(a *saml.Assertion, r *saml.Response) { a.Conditions.NotOnOrAfter = time.Now().Add(time.Hour) },
		"future issue":      func(a *saml.Assertion, r *saml.Response) { r.IssueInstant = time.Now().Add(time.Hour) },
	}
	for name, modify := range cases {
		t.Run(name, func(t *testing.T) {
			r, e := p.Response(req, modify)
			require.NoError(t, e)
			_, e = c.Validate(r, id)
			assert.ErrorIs(t, e, samlclient.ErrResponse)
		})
	}
	decoded, e := base64.StdEncoding.DecodeString(raw)
	require.NoError(t, e)
	for name, mutated := range map[string]string{
		"tampered subject":    strings.ReplaceAll(string(decoded), samlprovider.Subject, "attacker"),
		"duplicate assertion": strings.Replace(string(decoded), "</samlp:Response>", string(decoded[strings.Index(string(decoded), "<saml:Assertion"):strings.LastIndex(string(decoded), "</samlp:Response>")])+"</samlp:Response>", 1),
		"doctype":             "<!DOCTYPE Response>" + string(decoded),
		"weak algorithm":      strings.ReplaceAll(string(decoded), "rsa-sha256", "rsa-sha1"),
	} {
		t.Run(name, func(t *testing.T) {
			_, e := c.Validate(base64.StdEncoding.EncodeToString([]byte(mutated)), id)
			assert.ErrorIs(t, e, samlclient.ErrResponse)
		})
	}
	other, e := samlprovider.New(p.BaseURL)
	require.NoError(t, e)
	forged, e := other.Response(req, nil)
	require.NoError(t, e)
	_, e = c.Validate(forged, id)
	assert.ErrorIs(t, e, samlclient.ErrResponse)
	_, e = c.Validate(raw, "foreign")
	assert.Error(t, e)
	for _, bad := range []string{"", "<xml/>", strings.Repeat("A", 1400001)} {
		_, e := c.Validate(bad, id)
		assert.Error(t, e)
	}
	for _, bad := range []string{"http://public.example.invalid/acs", "https://user:pass@console.example.invalid/acs", "https://console.example.invalid/acs?query=1"} {
		cfg.ACSURL = bad
		_, e := samlclient.New(cfg, key)
		assert.Error(t, e)
	}
}
