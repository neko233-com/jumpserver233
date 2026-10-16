// Package passkeyclient owns WebAuthn parsing and cryptographic verification.
package passkeyclient

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/url"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var ErrConfig = errors.New("Passkey requires a configured HTTPS domain or localhost origin")
var ErrCredential = errors.New("Passkey verification rejected")

type Credential = webauthn.Credential
type Session = webauthn.SessionData
type Creation = protocol.CredentialCreation
type Assertion = protocol.CredentialAssertion
type User struct {
	ID, Name    string
	Credentials []Credential
}

func Handle(id string) []byte                    { h := sha256.Sum256([]byte("jms233/passkey/user/" + id)); return h[:] }
func (u User) WebAuthnID() []byte                { return Handle(u.ID) }
func (u User) WebAuthnName() string              { return u.Name }
func (u User) WebAuthnDisplayName() string       { return u.Name }
func (u User) WebAuthnCredentials() []Credential { return u.Credentials }

type Client struct {
	wa           *webauthn.WebAuthn
	Origin, RPID string
}

func New(origin string) (*Client, error) {
	u, e := url.Parse(origin)
	if e != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || net.ParseIP(u.Hostname()) != nil || (u.Scheme != "https" && !(u.Scheme == "http" && u.Hostname() == "localhost")) {
		return nil, ErrConfig
	}
	wa, e := webauthn.New(&webauthn.Config{RPID: u.Hostname(), RPDisplayName: "JumpServer233", RPOrigins: []string{origin}, AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired}, AttestationPreference: protocol.PreferNoAttestation})
	if e != nil {
		return nil, ErrConfig
	}
	return &Client{wa: wa, Origin: origin, RPID: u.Hostname()}, nil
}
func (c *Client) BeginRegistration(u User) (*Creation, *Session, error) {
	return c.wa.BeginRegistration(u, webauthn.WithExclusions(webauthn.Credentials(u.Credentials).CredentialDescriptors()), webauthn.WithExtensions(webauthn.WithExtensionCredProps()))
}
func (c *Client) VerifyRegistration(u User, s Session, raw []byte) (*Credential, error) {
	if len(raw) > 65536 {
		return nil, ErrCredential
	}
	p, e := protocol.ParseCredentialCreationResponseBytes(raw)
	if e != nil {
		return nil, ErrCredential
	}
	cred, e := c.wa.CreateCredential(u, s, p)
	if e != nil {
		return nil, fmt.Errorf("%w: %v", ErrCredential, e)
	}
	if !cred.Flags.UserVerified || (cred.Extensions.RK != nil && !*cred.Extensions.RK) {
		return nil, ErrCredential
	}
	return cred, nil
}
func (c *Client) BeginLogin() (*Assertion, *Session, error) {
	return c.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
}
func (c *Client) VerifyLogin(s Session, raw []byte, lookup func([]byte, []byte) (User, error)) (User, *Credential, error) {
	if len(raw) > 65536 {
		return User{}, nil, ErrCredential
	}
	p, e := protocol.ParseCredentialRequestResponseBytes(raw)
	if e != nil {
		return User{}, nil, ErrCredential
	}
	u, cred, e := c.wa.ValidatePasskeyLogin(func(id, handle []byte) (webauthn.User, error) { return lookup(id, handle) }, s, p)
	if e != nil || cred == nil || !cred.Flags.UserVerified {
		return User{}, nil, ErrCredential
	}
	user, ok := u.(User)
	if !ok {
		return User{}, nil, ErrCredential
	}
	return user, cred, nil
}
