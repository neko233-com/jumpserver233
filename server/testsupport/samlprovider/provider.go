// Package samlprovider is an isolated, credential-free SAML IdP fixture.
// It is never linked into the application server.
package samlprovider

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/neko233-com/jumpserver233/server/internal/connector/samlclient"
	dsig "github.com/russellhaering/goxmldsig"
)

const Subject = "synthetic-saml-subject"

type Provider struct {
	BaseURL     string
	Key         *rsa.PrivateKey
	Certificate *x509.Certificate
}

func New(baseURL string) (*Provider, error) {
	k, e := samlclient.GenerateKey()
	if e != nil {
		return nil, e
	}
	kb, _ := pem.Decode(k.PrivateKey)
	cb, _ := pem.Decode(k.Certificate)
	key, e := x509.ParsePKCS1PrivateKey(kb.Bytes)
	if e != nil {
		return nil, e
	}
	cert, e := x509.ParseCertificate(cb.Bytes)
	return &Provider{BaseURL: baseURL, Key: key, Certificate: cert}, e
}
func (p *Provider) Metadata() string {
	m := saml.EntityDescriptor{EntityID: p.BaseURL, IDPSSODescriptors: []saml.IDPSSODescriptor{{SSODescriptor: saml.SSODescriptor{RoleDescriptor: saml.RoleDescriptor{ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol", KeyDescriptors: []saml.KeyDescriptor{{Use: "signing", KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{X509Certificates: []saml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(p.Certificate.Raw)}}}}}}}}, SingleSignOnServices: []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: p.BaseURL + "/sso"}}}}}
	raw, _ := xml.Marshal(m)
	return string(raw)
}
func Request(location string) (saml.AuthnRequest, string, error) {
	u, e := url.Parse(location)
	if e != nil {
		return saml.AuthnRequest{}, "", e
	}
	q := u.Query()
	raw, e := base64.StdEncoding.DecodeString(q.Get("SAMLRequest"))
	if e != nil || len(raw) > 65536 {
		return saml.AuthnRequest{}, "", fmt.Errorf("invalid fixture request")
	}
	z := flate.NewReader(bytes.NewReader(raw))
	defer z.Close()
	plain, e := io.ReadAll(io.LimitReader(z, 65537))
	var r saml.AuthnRequest
	if e != nil || len(plain) > 65536 || xml.Unmarshal(plain, &r) != nil || r.ID == "" || r.Issuer == nil || r.ProtocolBinding != saml.HTTPPostBinding || r.ForceAuthn == nil || !*r.ForceAuthn {
		return r, "", fmt.Errorf("invalid fixture request")
	}
	return r, q.Get("RelayState"), nil
}
func (p *Provider) Response(req saml.AuthnRequest, modify func(*saml.Assertion, *saml.Response)) (string, error) {
	now := time.Now().UTC()
	var id [16]byte
	if _, e := rand.Read(id[:]); e != nil {
		return "", e
	}
	a := saml.Assertion{ID: "assertion-" + hex.EncodeToString(id[:]), Version: "2.0", IssueInstant: now, Issuer: saml.Issuer{Value: p.BaseURL}, Subject: &saml.Subject{NameID: &saml.NameID{Format: samlclient.Persistent, Value: Subject}, SubjectConfirmations: []saml.SubjectConfirmation{{Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer", SubjectConfirmationData: &saml.SubjectConfirmationData{InResponseTo: req.ID, Recipient: req.AssertionConsumerServiceURL, NotOnOrAfter: now.Add(2 * time.Minute)}}}}, Conditions: &saml.Conditions{NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(2 * time.Minute), AudienceRestrictions: []saml.AudienceRestriction{{Audience: saml.Audience{Value: req.Issuer.Value}}}}, AuthnStatements: []saml.AuthnStatement{{AuthnInstant: now, SessionIndex: "session-" + hex.EncodeToString(id[:]), AuthnContext: saml.AuthnContext{AuthnContextClassRef: &saml.AuthnContextClassRef{Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"}}}}}
	r := saml.Response{ID: "response-" + hex.EncodeToString(id[:]), Version: "2.0", IssueInstant: now, InResponseTo: req.ID, Destination: req.AssertionConsumerServiceURL, Issuer: &saml.Issuer{Value: p.BaseURL}, Status: saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}}}
	if modify != nil {
		modify(&a, &r)
	}
	sc, e := dsig.NewSigningContext(p.Key, [][]byte{p.Certificate.Raw})
	if e != nil {
		return "", e
	}
	sc.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if e = sc.SetSignatureMethod(dsig.RSASHA256SignatureMethod); e != nil {
		return "", e
	}
	signed, e := sc.SignEnveloped(a.Element())
	if e != nil {
		return "", e
	}
	root := r.Element()
	root.AddChild(signed)
	d := etree.NewDocument()
	d.SetRoot(root)
	raw, e := d.WriteToBytes()
	return base64.StdEncoding.EncodeToString(raw), e
}

var form = template.Must(template.New("post").Parse(`<!doctype html><html lang="en"><title>Synthetic SAML provider</title><h1>Synthetic SAML identity provider</h1><p>Local fixture only. No credentials are collected.</p><form method="post" action="{{.ACS}}"><input type="hidden" name="SAMLResponse" value="{{.Response}}"><input type="hidden" name="RelayState" value="{{.State}}"><button>Continue as synthetic SAML user</button></form></html>`))

func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	switch r.URL.Path {
	case "/health":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"metadata_xml": p.Metadata()})
	case "/metadata":
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write([]byte(p.Metadata()))
	case "/sso":
		if r.Method != "GET" {
			http.Error(w, "method", 405)
			return
		}
		req, state, e := Request(p.BaseURL + r.URL.RequestURI())
		u, _ := url.Parse(req.AssertionConsumerServiceURL)
		if e != nil || u == nil || !samlclient.Endpoint(req.AssertionConsumerServiceURL, true) || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() || u.Path != samlclient.ACSPath || !strings.HasPrefix(req.ID, "id-") {
			http.Error(w, "invalid fixture request", 400)
			return
		}
		response, e := p.Response(req, nil)
		if e != nil {
			http.Error(w, "fixture failure", 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = form.Execute(w, struct{ ACS, Response, State string }{req.AssertionConsumerServiceURL, response, state})
	default:
		http.NotFound(w, r)
	}
}
