// Package samlclient owns the SAML wire protocol. XML signature verification is
// delegated to crewjam/saml and the patched goxmldsig dependency.
package samlclient

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
)

var ErrConfig = errors.New("invalid SAML configuration")
var ErrResponse = errors.New("SAML response rejected")

const ACSPath = "/api/v1/authentication/saml/acs"
const MetadataPath = "/api/v1/authentication/saml/metadata"
const Persistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
const assertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"
const protocolNS = "urn:oasis:names:tc:SAML:2.0:protocol"
const metadataNS = "urn:oasis:names:tc:SAML:2.0:metadata"
const dsigNS = "http://www.w3.org/2000/09/xmldsig#"

type Config struct {
	EntityID          string `json:"entity_id"`
	ACSURL            string `json:"acs_url"`
	MetadataXML       string `json:"metadata_xml"`
	AllowLoopbackHTTP bool   `json:"allow_loopback_http"`
}
type IdentityKey struct{ PrivateKey, Certificate []byte }
type Client struct {
	sp          *saml.ServiceProvider
	metadata    *saml.EntityDescriptor
	fingerprint string
	roots       []*x509.Certificate
}
type Identity struct {
	Subject, AssertionID string
	Expires              time.Time
}

func Endpoint(raw string, loopback bool) bool {
	u, e := url.Parse(raw)
	if e != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.RawPath != "" || len(raw) > 1900 {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return loopback && u.Scheme == "http" && ip != nil && ip.IsLoopback()
}
func GenerateKey() (IdentityKey, error) {
	k, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		return IdentityKey{}, e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return IdentityKey{}, e
	}
	now := time.Now()
	t := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "jumpserver233 SAML SP"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(3, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, t, t, &k.PublicKey, k)
	if e != nil {
		return IdentityKey{}, e
	}
	return IdentityKey{PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}
func safeXML(raw []byte, limit int) (*etree.Element, error) {
	if len(raw) == 0 || len(raw) > limit || bytes.Contains(bytes.ToUpper(raw), []byte("<!DOCTYPE")) || bytes.Contains(bytes.ToUpper(raw), []byte("<!ENTITY")) || xrv.Validate(bytes.NewReader(raw)) != nil {
		return nil, ErrResponse
	}
	d := etree.NewDocument()
	if d.ReadFromBytes(raw) != nil || d.Root() == nil {
		return nil, ErrResponse
	}
	nodes := 0
	ids := map[string]bool{}
	var walk func(*etree.Element, int) bool
	walk = func(el *etree.Element, depth int) bool {
		nodes++
		if depth > 32 || nodes > 8192 {
			return false
		}
		for _, a := range el.Attr {
			if a.Key == "ID" || a.Key == "Id" || a.Key == "id" {
				if a.Value == "" || ids[a.Value] {
					return false
				}
				ids[a.Value] = true
			}
		}
		for _, c := range el.ChildElements() {
			if !walk(c, depth+1) {
				return false
			}
		}
		return true
	}
	if !walk(d.Root(), 0) {
		return nil, ErrResponse
	}
	return d.Root(), nil
}
func ParseMetadata(raw string, loopback bool) (*saml.EntityDescriptor, error) {
	root, e := safeXML([]byte(raw), 262144)
	if e != nil || root.Tag != "EntityDescriptor" || root.NamespaceURI() != metadataNS {
		return nil, ErrConfig
	}
	var m saml.EntityDescriptor
	if xml.Unmarshal([]byte(raw), &m) != nil || m.EntityID == "" || len(m.EntityID) > 1024 || len(m.IDPSSODescriptors) != 1 || (!m.ValidUntil.IsZero() && !time.Now().Before(m.ValidUntil)) {
		return nil, ErrConfig
	}
	d := m.IDPSSODescriptors[0]
	if d.ProtocolSupportEnumeration != protocolNS {
		return nil, ErrConfig
	}
	redirects := 0
	for _, s := range d.SingleSignOnServices {
		if s.Binding == saml.HTTPRedirectBinding {
			redirects++
			if !Endpoint(s.Location, loopback) {
				return nil, ErrConfig
			}
		}
	}
	if redirects != 1 {
		return nil, ErrConfig
	}
	certs := 0
	for _, k := range d.KeyDescriptors {
		if k.Use != "" && k.Use != "signing" {
			continue
		}
		for _, x := range k.KeyInfo.X509Data.X509Certificates {
			der, e := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(x.Data), ""))
			if e != nil {
				return nil, ErrConfig
			}
			cert, e := x509.ParseCertificate(der)
			if e != nil || !time.Now().Before(cert.NotAfter) || time.Now().Before(cert.NotBefore) {
				return nil, ErrConfig
			}
			key, ok := cert.PublicKey.(*rsa.PublicKey)
			if !ok || key.N.BitLen() < 2048 {
				return nil, ErrConfig
			}
			certs++
		}
	}
	if certs == 0 || certs > 8 {
		return nil, ErrConfig
	}
	return &m, nil
}
func New(c Config, key IdentityKey) (*Client, error) {
	if !Endpoint(c.EntityID, c.AllowLoopbackHTTP) || !Endpoint(c.ACSURL, c.AllowLoopbackHTTP) {
		return nil, ErrConfig
	}
	acs, _ := url.Parse(c.ACSURL)
	if acs.Path != ACSPath {
		return nil, ErrConfig
	}
	m, e := ParseMetadata(c.MetadataXML, c.AllowLoopbackHTTP)
	if e != nil {
		return nil, e
	}
	kb, _ := pem.Decode(key.PrivateKey)
	cb, _ := pem.Decode(key.Certificate)
	if kb == nil || cb == nil {
		return nil, ErrConfig
	}
	k, e := x509.ParsePKCS1PrivateKey(kb.Bytes)
	if e != nil || k.N.BitLen() < 2048 {
		return nil, ErrConfig
	}
	cert, e := x509.ParseCertificate(cb.Bytes)
	if e != nil || !time.Now().Before(cert.NotAfter) || time.Now().Before(cert.NotBefore) {
		return nil, ErrConfig
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.Cmp(k.N) != 0 || pub.E != k.E {
		return nil, ErrConfig
	}
	meta := *acs
	meta.Path = MetadataPath
	force := true
	sp := &saml.ServiceProvider{EntityID: c.EntityID, Key: k, Certificate: cert, MetadataURL: meta, AcsURL: *acs, IDPMetadata: m, AuthnNameIDFormat: saml.NameIDFormat(Persistent), ForceAuthn: &force, SignatureMethod: dsig.RSASHA256SignatureMethod}
	sp.ValidateAudienceRestriction = func(a *saml.Assertion) error {
		if a.Conditions == nil || len(a.Conditions.AudienceRestrictions) == 0 {
			return ErrResponse
		}
		for _, r := range a.Conditions.AudienceRestrictions {
			if r.Audience.Value != c.EntityID {
				return ErrResponse
			}
		}
		return nil
	}
	fp := sha256.Sum256(cert.Raw)
	roots := []*x509.Certificate{}
	for _, kd := range m.IDPSSODescriptors[0].KeyDescriptors {
		if kd.Use != "" && kd.Use != "signing" {
			continue
		}
		for _, x := range kd.KeyInfo.X509Data.X509Certificates {
			der, _ := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(x.Data), ""))
			crt, _ := x509.ParseCertificate(der)
			roots = append(roots, crt)
		}
	}
	return &Client{sp: sp, metadata: m, fingerprint: hex.EncodeToString(fp[:]), roots: roots}, nil
}
func (c *Client) Valid() bool {
	now := time.Now()
	if !now.Before(c.sp.Certificate.NotAfter) || (!c.metadata.ValidUntil.IsZero() && !now.Before(c.metadata.ValidUntil)) {
		return false
	}
	for _, cert := range c.roots {
		if now.Before(cert.NotAfter) && !now.Before(cert.NotBefore) {
			return true
		}
	}
	return false
}
func (c *Client) Issuer() string      { return c.metadata.EntityID }
func (c *Client) Fingerprint() string { return c.fingerprint }
func (c *Client) Metadata() ([]byte, error) {
	m := c.sp.Metadata()
	for i := range m.SPSSODescriptors {
		d := &m.SPSSODescriptors[i]
		d.SingleLogoutServices = nil
		keys := []saml.KeyDescriptor{}
		for _, k := range d.KeyDescriptors {
			if k.Use == "signing" {
				keys = append(keys, k)
			}
		}
		d.KeyDescriptors = keys
	}
	return xml.Marshal(m)
}
func (c *Client) Begin(state string) (requestID, location string, err error) {
	r, e := c.sp.MakeAuthenticationRequest(c.sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if e != nil {
		return "", "", e
	}
	u, e := r.Redirect(state, c.sp)
	if e != nil {
		return "", "", e
	}
	return r.ID, u.String(), nil
}

// Validate accepts one signed plaintext assertion. Rejecting extra assertions,
// unsupported conditions and weak algorithms keeps the accepted profile explicit.
func (c *Client) Validate(encoded, requestID string) (Identity, error) {
	if !c.Valid() || len(encoded) > 1400000 || requestID == "" {
		return Identity{}, ErrResponse
	}
	raw, e := base64.StdEncoding.DecodeString(encoded)
	if e != nil {
		return Identity{}, ErrResponse
	}
	root, e := safeXML(raw, 1048576)
	if e != nil || root.Tag != "Response" || root.NamespaceURI() != protocolNS {
		return Identity{}, ErrResponse
	}
	assertions := 0
	signatures := 0
	var assertion *etree.Element
	for _, el := range root.ChildElements() {
		if el.Tag == "Assertion" && el.NamespaceURI() == assertionNS {
			assertions++
			assertion = el
		}
		if el.Tag == "EncryptedAssertion" {
			return Identity{}, ErrResponse
		}
	}
	if assertions != 1 {
		return Identity{}, ErrResponse
	}
	for _, el := range assertion.ChildElements() {
		if el.Tag == "Signature" && el.NamespaceURI() == dsigNS {
			signatures++
		}
		if el.Tag == "Conditions" {
			for _, condition := range el.ChildElements() {
				if condition.NamespaceURI() != assertionNS || (condition.Tag != "AudienceRestriction" && condition.Tag != "OneTimeUse") {
					return Identity{}, ErrResponse
				}
			}
		}
	}
	if signatures != 1 {
		return Identity{}, ErrResponse
	}
	var algorithms func(*etree.Element) bool
	algorithms = func(el *etree.Element) bool {
		if el.NamespaceURI() == dsigNS {
			a := el.SelectAttrValue("Algorithm", "")
			switch el.Tag {
			case "SignatureMethod":
				if a != dsig.RSASHA256SignatureMethod && a != dsig.RSASHA384SignatureMethod && a != dsig.RSASHA512SignatureMethod {
					return false
				}
			case "DigestMethod":
				if a != "http://www.w3.org/2001/04/xmlenc#sha256" && a != "http://www.w3.org/2001/04/xmldsig-more#sha384" && a != "http://www.w3.org/2001/04/xmlenc#sha512" {
					return false
				}
			}
		}
		for _, ch := range el.ChildElements() {
			if !algorithms(ch) {
				return false
			}
		}
		return true
	}
	if !algorithms(root) {
		return Identity{}, ErrResponse
	}
	// Verify the assertion even when the enclosing Response is also signed.
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: c.roots})
	if _, e := vc.Validate(assertion); e != nil {
		return Identity{}, ErrResponse
	}
	if !singleChildren(root, map[string]int{"Issuer": 1, "Status": 1, "Assertion": 1, "Signature": -1}) || !singleChildren(assertion, map[string]int{"Issuer": 1, "Subject": 1, "Conditions": 1, "AuthnStatement": 1, "Signature": 1, "AttributeStatement": -1}) {
		return Identity{}, ErrResponse
	}
	for _, el := range assertion.ChildElements() {
		switch el.Tag {
		case "Subject":
			if !singleChildren(el, map[string]int{"NameID": 1, "SubjectConfirmation": 1}) {
				return Identity{}, ErrResponse
			}
			for _, sc := range el.ChildElements() {
				if sc.Tag == "SubjectConfirmation" && !singleChildren(sc, map[string]int{"SubjectConfirmationData": 1}) {
					return Identity{}, ErrResponse
				}
			}
		case "Conditions":
			for _, r := range el.ChildElements() {
				if r.Tag == "AudienceRestriction" && !singleChildren(r, map[string]int{"Audience": 1}) {
					return Identity{}, ErrResponse
				}
			}
		}
	}
	var response saml.Response
	if xml.Unmarshal(raw, &response) != nil || response.IssueInstant.After(time.Now().Add(time.Minute)) {
		return Identity{}, ErrResponse
	}
	a, e := c.sp.ParseXMLResponse(raw, []string{requestID}, c.sp.AcsURL)
	if e != nil {
		return Identity{}, ErrResponse
	}
	now := time.Now()
	skew := time.Minute
	if root.SelectAttrValue("Destination", "") != c.sp.AcsURL.String() || root.SelectAttrValue("Version", "") != "2.0" || a.Version != "2.0" || a.ID == "" || a.Subject == nil || a.Subject.NameID == nil || a.Conditions == nil || len(a.Subject.SubjectConfirmations) != 1 || len(a.AuthnStatements) != 1 || a.IssueInstant.After(now.Add(skew)) {
		return Identity{}, ErrResponse
	}
	n := a.Subject.NameID
	if n.Format != Persistent || n.Value == "" || strings.TrimSpace(n.Value) != n.Value || len(n.Value) > 1024 || (n.NameQualifier != "" && n.NameQualifier != c.Issuer()) || (n.SPNameQualifier != "" && n.SPNameQualifier != c.sp.EntityID) || n.SPProvidedID != "" {
		return Identity{}, ErrResponse
	}
	sc := a.Subject.SubjectConfirmations[0]
	d := sc.SubjectConfirmationData
	if d == nil || !d.NotBefore.IsZero() || sc.Method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" || d.InResponseTo != requestID || d.Recipient != c.sp.AcsURL.String() || !now.Before(d.NotOnOrAfter.Add(skew)) || a.Conditions.NotBefore.After(now.Add(skew)) || !now.Before(a.Conditions.NotOnOrAfter.Add(skew)) || a.Conditions.NotOnOrAfter.Sub(a.Conditions.NotBefore) > 10*time.Minute {
		return Identity{}, ErrResponse
	}
	s := a.AuthnStatements[0]
	if s.AuthnInstant.Before(now.Add(-5*time.Minute)) || s.AuthnInstant.After(now.Add(skew)) || (s.SessionNotOnOrAfter != nil && !now.Before(*s.SessionNotOnOrAfter)) {
		return Identity{}, ErrResponse
	}
	return Identity{Subject: n.Value, AssertionID: a.ID, Expires: a.Conditions.NotOnOrAfter.Add(skew)}, nil
}

// Negative cardinality means an optional child. Unknown protocol elements are
// rejected instead of being silently discarded by encoding/xml.
func singleChildren(el *etree.Element, allowed map[string]int) bool {
	counts := map[string]int{}
	for _, c := range el.ChildElements() {
		if _, ok := allowed[c.Tag]; !ok {
			return false
		}
		ns := assertionNS
		if c.Tag == "Signature" {
			ns = dsigNS
		}
		if el.Tag == "Response" && (c.Tag == "Status") {
			ns = protocolNS
		}
		if c.NamespaceURI() != ns {
			return false
		}
		counts[c.Tag]++
	}
	for k, n := range allowed {
		if n >= 0 && counts[k] != n {
			return false
		}
		if n < 0 && counts[k] > 1 {
			return false
		}
	}
	return true
}
