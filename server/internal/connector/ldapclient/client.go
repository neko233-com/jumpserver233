// Package ldapclient is the directory protocol boundary. Passwords are used
// only for a TLS-protected bind and never returned with an identity.
package ldapclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	ldap "github.com/go-ldap/ldap/v3"
)

var ErrConfig = errors.New("invalid directory configuration")
var ErrUnavailable = errors.New("directory unavailable")
var ErrCredentials = errors.New("directory credentials rejected")

type Config struct {
	URL               string `json:"url"`
	BaseDN            string `json:"base_dn"`
	BindDN            string `json:"bind_dn"`
	Filter            string `json:"filter"`
	IdentityAttribute string `json:"identity_attribute"`
	CAPEM             string `json:"ca_pem"`
}
type Identity struct {
	Subject string `json:"subject"`
}
type Directory interface {
	Check(context.Context, Config, string) error
	Lookup(context.Context, Config, string, string) (Identity, error)
	Authenticate(context.Context, Config, string, string, string) (Identity, error)
}
type Client struct{}

var attributePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$`)

func Validate(c Config) error {
	u, e := url.Parse(c.URL)
	if e != nil || (u.Scheme != "ldaps" && u.Scheme != "ldap") || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || len(c.URL) > 2048 || len(c.BaseDN) > 2048 || len(c.BindDN) > 2048 || len(c.Filter) > 2048 || strings.Count(c.Filter, "{username}") != 1 || !attributePattern.MatchString(c.IdentityAttribute) {
		return ErrConfig
	}
	if _, e = ldap.ParseDN(c.BaseDN); e != nil || c.BaseDN == "" {
		return ErrConfig
	}
	if _, e = ldap.ParseDN(c.BindDN); e != nil || c.BindDN == "" {
		return ErrConfig
	}
	if _, e = ldap.CompileFilter(strings.Replace(c.Filter, "{username}", "validation", 1)); e != nil {
		return ErrConfig
	}
	if _, e = tlsConfig(c); e != nil {
		return ErrConfig
	}
	return nil
}
func tlsConfig(c Config) (*tls.Config, error) {
	u, e := url.Parse(c.URL)
	if e != nil {
		return nil, ErrConfig
	}
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	if len(c.CAPEM) > 262144 || (c.CAPEM != "" && !roots.AppendCertsFromPEM([]byte(c.CAPEM))) {
		return nil, ErrConfig
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname(), RootCAs: roots}, nil
}
func validUsername(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) < 0
}

// A connection has an absolute deadline, cancellation, and a read budget. No
// referrals or aliases are followed, and binds never use an empty password.
func connect(ctx context.Context, c Config, password string) (*ldap.Conn, func(), error) {
	return connectWithBudget(ctx, c, password, 10*time.Second, 1<<20)
}
func connectWithBudget(ctx context.Context, c Config, password string, duration time.Duration, budget int) (*ldap.Conn, func(), error) {
	if Validate(c) != nil || password == "" || len(password) > 4096 {
		return nil, nil, ErrConfig
	}
	u, _ := url.Parse(c.URL)
	port := u.Port()
	if port == "" {
		port = "389"
		if u.Scheme == "ldaps" {
			port = "636"
		}
	}
	deadline := time.Now().Add(duration)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn, e := (&net.Dialer{Deadline: deadline}).DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if e != nil {
		return nil, nil, ErrUnavailable
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	cleanupRaw := func() { stop(); _ = conn.Close() }
	tc, e := tlsConfig(c)
	if e != nil {
		cleanupRaw()
		return nil, nil, ErrConfig
	}
	var wire net.Conn = conn
	if u.Scheme == "ldaps" {
		t := tls.Client(conn, tc)
		if e = t.HandshakeContext(ctx); e != nil {
			cleanupRaw()
			return nil, nil, ErrUnavailable
		}
		wire = t
	}
	l := ldap.NewConn(&budgetConn{Conn: wire, remaining: budget}, u.Scheme == "ldaps")
	l.Start()
	l.SetTimeout(time.Until(deadline))
	cleanup := func() { stop(); _ = l.Close(); _ = conn.Close() }
	if u.Scheme == "ldap" {
		if e = l.StartTLS(tc); e != nil {
			cleanup()
			return nil, nil, ErrUnavailable
		}
	}
	if e = l.Bind(c.BindDN, password); e != nil {
		cleanup()
		return nil, nil, ErrUnavailable
	}
	return l, cleanup, nil
}

type budgetConn struct {
	net.Conn
	remaining int
}

func (c *budgetConn) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, ErrUnavailable
	}
	if len(p) > c.remaining {
		p = p[:c.remaining]
	}
	n, e := c.Conn.Read(p)
	c.remaining -= n
	return n, e
}
func (Client) Check(ctx context.Context, c Config, password string) error {
	_, close, e := connect(ctx, c, password)
	if e == nil {
		close()
	}
	return e
}
func lookup(l *ldap.Conn, c Config, username string) (Identity, string, error) {
	if !validUsername(username) {
		return Identity{}, "", ErrCredentials
	}
	filter := strings.Replace(c.Filter, "{username}", ldap.EscapeFilter(username), 1)
	result, e := l.Search(ldap.NewSearchRequest(c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 5, false, filter, []string{c.IdentityAttribute, "userAccountControl"}, nil))
	if e != nil {
		if ldap.IsErrorWithCode(e, ldap.LDAPResultSizeLimitExceeded) {
			return Identity{}, "", ErrCredentials
		}
		return Identity{}, "", ErrUnavailable
	}
	if len(result.Entries) != 1 || len(result.Referrals) > 0 {
		return Identity{}, "", ErrCredentials
	}
	entry := result.Entries[0]
	dn, e := ldap.ParseDN(entry.DN)
	base, _ := ldap.ParseDN(c.BaseDN)
	if e != nil || !(base.EqualFold(dn) || base.AncestorOfFold(dn)) {
		return Identity{}, "", ErrCredentials
	}
	raw := entry.GetRawAttributeValues(c.IdentityAttribute)
	if len(raw) != 1 || len(raw[0]) == 0 || len(raw[0]) > 256 {
		return Identity{}, "", ErrCredentials
	}
	if flags := entry.GetAttributeValue("userAccountControl"); flags != "" {
		n, e := strconv.ParseUint(flags, 10, 32)
		if e != nil || n&2 != 0 {
			return Identity{}, "", ErrCredentials
		}
	}
	return Identity{Subject: base64.RawURLEncoding.EncodeToString(raw[0])}, entry.DN, nil
}
func (Client) Lookup(ctx context.Context, c Config, password, username string) (Identity, error) {
	l, close, e := connect(ctx, c, password)
	if e != nil {
		return Identity{}, e
	}
	defer close()
	id, _, e := lookup(l, c, username)
	return id, e
}
func (Client) Authenticate(ctx context.Context, c Config, bindPassword, username, password string) (Identity, error) {
	if !validUsername(username) || password == "" || len(password) > 4096 {
		return Identity{}, ErrCredentials
	}
	l, close, e := connect(ctx, c, bindPassword)
	if e != nil {
		return Identity{}, e
	}
	defer close()
	id, dn, e := lookup(l, c, username)
	if e != nil {
		return Identity{}, e
	}
	if e = l.Bind(dn, password); e != nil {
		return Identity{}, ErrCredentials
	}
	return id, nil
}
