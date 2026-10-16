package ldapclient

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/testsupport/ldapserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fixtureConfig(s *ldapserver.Server) Config {
	return Config{URL: s.URL, BaseDN: ldapserver.BaseDN, BindDN: ldapserver.BindDN, Filter: "(uid={username})", IdentityAttribute: "entryUUID", CAPEM: s.CAPEM}
}
func TestVerifiedLDAPSAndStartTLSAuthentication(t *testing.T) {
	for _, start := range []bool{false, true} {
		t.Run(map[bool]string{false: "LDAPS", true: "StartTLS"}[start], func(t *testing.T) {
			s, e := ldapserver.Start(ldapserver.Options{StartTLS: start})
			require.NoError(t, e)
			defer s.Close()
			c := fixtureConfig(s)
			require.NoError(t, (Client{}).Check(context.Background(), c, ldapserver.BindPassword))
			id, e := (Client{}).Authenticate(context.Background(), c, ldapserver.BindPassword, ldapserver.Username, ldapserver.Password)
			require.NoError(t, e)
			assert.Equal(t, base64.RawURLEncoding.EncodeToString([]byte("synthetic-stable-directory-id")), id.Subject)
			c.IdentityAttribute = "objectGUID"
			c.Filter = "(sAMAccountName={username})"
			id, e = (Client{}).Authenticate(context.Background(), c, ldapserver.BindPassword, ldapserver.Username, ldapserver.Password)
			require.NoError(t, e)
			assert.Equal(t, base64.RawURLEncoding.EncodeToString([]byte("\x01\x02synthetic-binary-guid")), id.Subject)
		})
	}
}
func TestDirectoryRejectsUntrustedTLSAndBadIdentities(t *testing.T) {
	cases := []struct {
		name     string
		o        ldapserver.Options
		mutate   func(*Config)
		password string
	}{
		{name: "untrusted CA", mutate: func(c *Config) { c.CAPEM = "" }, password: ldapserver.Password},
		{name: "hostname mismatch", o: ldapserver.Options{BadHostname: true}, password: ldapserver.Password},
		{name: "StartTLS refused", o: ldapserver.Options{StartTLS: true, RejectStartTLS: true}, password: ldapserver.Password},
		{name: "duplicates", o: ldapserver.Options{Duplicate: true}, password: ldapserver.Password}, {name: "missing identity", o: ldapserver.Options{MissingIdentity: true}, password: ldapserver.Password},
		{name: "outside base", o: ldapserver.Options{OutsideBase: true}, password: ldapserver.Password}, {name: "AD disabled", o: ldapserver.Options{Disabled: true}, password: ldapserver.Password}, {name: "referrals", o: ldapserver.Options{Referral: true}, password: ldapserver.Password},
		{name: "empty password", password: ""}, {name: "wrong password", password: "invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, e := ldapserver.Start(tc.o)
			require.NoError(t, e)
			defer s.Close()
			c := fixtureConfig(s)
			if tc.mutate != nil {
				tc.mutate(&c)
			}
			_, e = (Client{}).Authenticate(context.Background(), c, ldapserver.BindPassword, ldapserver.Username, tc.password)
			require.Error(t, e)
			assert.NotContains(t, e.Error(), ldapserver.BindPassword)
			assert.NotContains(t, e.Error(), ldapserver.Password)
			if tc.password == "" {
				assert.Zero(t, s.Binds.Load())
			}
		})
	}
}
func TestLDAPFilterInjectionIsEscapedAndCancelledOperationsStop(t *testing.T) {
	name := "user*)(uid=*)"
	s, e := ldapserver.Start(ldapserver.Options{SearchName: name})
	require.NoError(t, e)
	defer s.Close()
	c := fixtureConfig(s)
	_, e = (Client{}).Authenticate(context.Background(), c, ldapserver.BindPassword, name, ldapserver.Password)
	require.NoError(t, e)
	_, e = (Client{}).Authenticate(context.Background(), c, ldapserver.BindPassword, "*)(uid=*)", ldapserver.Password)
	assert.ErrorIs(t, e, ErrCredentials)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, e = (Client{}).Authenticate(ctx, c, ldapserver.BindPassword, name, ldapserver.Password)
	assert.Error(t, e)
	assert.Less(t, time.Since(start), time.Second)
}
func TestInvalidDirectoryConfiguration(t *testing.T) {
	c := Config{URL: "ldaps://directory.example.invalid", BaseDN: ldapserver.BaseDN, BindDN: ldapserver.BindDN, Filter: "(uid={username})", IdentityAttribute: "entryUUID"}
	require.NoError(t, Validate(c))
	for _, raw := range []string{"http://host", "ldap://user:password@host", "ldaps://host/path", "ldapi:///socket", "ldaps://host?query"} {
		n := c
		n.URL = raw
		assert.Error(t, Validate(n), raw)
	}
	for _, f := range []string{"(uid=*)", "(uid={username}", "(|(uid={username})(cn={username}))"} {
		n := c
		n.Filter = f
		assert.Error(t, Validate(n))
	}
	n := c
	n.CAPEM = "invalid"
	assert.Error(t, Validate(n))
	n = c
	n.IdentityAttribute = "uid)(cn"
	assert.Error(t, Validate(n))
	_, e := (Client{}).Authenticate(context.Background(), c, "", ldapserver.Username, ldapserver.Password)
	assert.Error(t, e)
	assert.False(t, validUsername(strings.Repeat("a", 257)))
}

func TestCancelInFlightDirectoryBindClosesConnection(t *testing.T) {
	s, e := ldapserver.Start(ldapserver.Options{StallBinds: true})
	require.NoError(t, e)
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- (Client{}).Check(ctx, fixtureConfig(s), ldapserver.BindPassword) }()
	require.Eventually(t, func() bool { return s.Binds.Load() > 0 }, time.Second, 5*time.Millisecond)
	cancel()
	select {
	case e := <-done:
		require.Error(t, e)
	case <-time.After(time.Second):
		t.Fatal("cancelled bind did not release the connection")
	}
}
