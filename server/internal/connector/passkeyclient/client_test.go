package passkeyclient_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/connector/passkeyclient"
	"github.com/neko233-com/jumpserver233/server/testsupport/passkeyauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasskeyRegistrationAndSignedDiscoverableAssertion(t *testing.T) {
	cl, e := passkeyclient.New("https://console.example.invalid")
	require.NoError(t, e)
	a, e := passkeyauth.New(cl.Origin, cl.RPID)
	require.NoError(t, e)
	user := passkeyclient.User{ID: "synthetic-user-123", Name: "qa.operator"}
	op, session, e := cl.BeginRegistration(user)
	require.NoError(t, e)
	raw, _ := json.Marshal(op)
	assert.Contains(t, string(raw), `"userVerification":"required"`)
	assert.Contains(t, string(raw), `"residentKey":"required"`)
	reg, e := a.Registration(op, passkeyauth.Overrides{})
	require.NoError(t, e)
	cred, e := cl.VerifyRegistration(user, *session, reg)
	require.NoError(t, e)
	assert.Equal(t, a.ID, cred.ID)
	assert.True(t, cred.Flags.UserVerified)
	user.Credentials = []passkeyclient.Credential{*cred}
	lookup := func(id, h []byte) (passkeyclient.User, error) {
		if !bytes.Equal(id, a.ID) || !bytes.Equal(h, user.WebAuthnID()) {
			return passkeyclient.User{}, passkeyclient.ErrCredential
		}
		return user, nil
	}
	for name, o := range map[string]passkeyauth.Overrides{"valid": {}, "wrong origin": {Origin: "https://attacker.invalid"}, "wrong port": {Origin: "https://console.example.invalid:444"}, "wrong scheme": {Origin: "http://console.example.invalid"}, "wrong rp": {RPID: "attacker.invalid"}, "wrong challenge": {Challenge: "YW5vdGhlci1yYW5kb20tY2hhbGxlbmdlLWJ5dGVzLTIzMw"}, "no UV": {NoUV: true}, "no UP": {NoUP: true}, "cross origin": {CrossOrigin: true}, "wrong type": {Type: "webauthn.create"}, "wrong handle": {Handle: []byte("foreign")}, "invalid signature": {CorruptSignature: true}} {
		t.Run(name, func(t *testing.T) {
			op, s, e := cl.BeginLogin()
			require.NoError(t, e)
			body, e := a.Assertion(op, o)
			require.NoError(t, e)
			u, c, e := cl.VerifyLogin(*s, body, lookup)
			if name == "valid" {
				require.NoError(t, e)
				assert.Equal(t, user.ID, u.ID)
				assert.NotNil(t, c)
			} else {
				assert.ErrorIs(t, e, passkeyclient.ErrCredential)
			}
		})
	}
	for name, o := range map[string]passkeyauth.Overrides{"no UV": {NoUV: true}, "no UP": {NoUP: true}, "wrong origin": {Origin: "https://other.invalid"}, "wrong RP": {RPID: "other.invalid"}, "wrong type": {Type: "webauthn.get"}, "cross origin": {CrossOrigin: true}} {
		t.Run("registration/"+name, func(t *testing.T) {
			u := passkeyclient.User{ID: "other-user", Name: "other"}
			op, s, e := cl.BeginRegistration(u)
			require.NoError(t, e)
			b, e := a.Registration(op, o)
			require.NoError(t, e)
			_, e = cl.VerifyRegistration(u, *s, b)
			assert.ErrorIs(t, e, passkeyclient.ErrCredential)
		})
	}
	for _, origin := range []string{"", "http://public.example.invalid", "http://127.0.0.1:5177", "https://127.0.0.1", "https://console.example.invalid/path", "https://user:password@console.example.invalid", "https://console.example.invalid?x=1"} {
		_, e := passkeyclient.New(origin)
		assert.Error(t, e, origin)
	}
	_, e = passkeyclient.New("http://localhost:5178")
	assert.NoError(t, e)
}
