package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func proofService(t *testing.T) (*Service, User) {
	t.Helper()
	s, e := OpenServiceWithVaultKey(filepath.Join(t.TempDir(), "users.json"), []byte(strings.Repeat("p", 32)))
	require.NoError(t, e)
	u, e := s.Bootstrap("proof.admin", "synthetic-proof-password")
	require.NoError(t, e)
	return s, u
}
func quarantineTest(t *testing.T, s *Service) (LoginSession, QuarantinedLogin) {
	t.Helper()
	login, e := s.Authenticate("proof.admin", "synthetic-proof-password")
	require.NoError(t, e)
	proof, e := s.QuarantineLogin(login.AccessToken)
	require.NoError(t, e)
	return login, proof
}
func TestLoginProofQuarantineResumeAndDigestRevocation(t *testing.T) {
	s, u := proofService(t)
	now := time.Now().UTC().Truncate(time.Second)
	s.now = func() time.Time { return now }
	login, proof := quarantineTest(t, s)
	_, ok := s.ValidateToken(login.AccessToken)
	assert.False(t, ok)
	assert.Equal(t, "local", proof.AuthSource)
	assert.Equal(t, now.Add(5*time.Minute), proof.ExpiresAt)
	require.NoError(t, s.ValidateLoginProof(proof.Proof, u.ID))
	assert.ErrorIs(t, s.ValidateLoginProof(proof.Proof, "other"), ErrInvalidLoginProof)
	_, ok = s.ValidateToken(proof.Proof)
	assert.False(t, ok)
	raw, e := base64.RawURLEncoding.DecodeString(proof.Proof)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), u.ID)
	assert.NotContains(t, string(raw), login.AccessToken)
	now = now.Add(time.Minute)
	resumed, e := s.ResumeLoginProof(proof.Proof)
	require.NoError(t, e)
	assert.NotEqual(t, login.AccessToken, resumed.AccessToken)
	assert.Equal(t, login.ExpiresAt, resumed.ExpiresAt)
	hash := sha256.Sum256([]byte(resumed.AccessToken))
	assert.Equal(t, now.Add(-time.Minute), s.sessions[hash].authenticatedAt)
	_, ok = s.ValidateToken(resumed.AccessToken)
	require.True(t, ok)
	require.NoError(t, s.RevokeReviewedSession(hash[:]))
	_, ok = s.ValidateToken(resumed.AccessToken)
	assert.False(t, ok)
	assert.ErrorIs(t, s.RevokeReviewedSession([]byte("bad")), ErrInvalidLoginProof)
}
func TestLoginProofTamperExpiryAndCredentialChanges(t *testing.T) {
	cases := map[string]func(*Service){
		"password": func(s *Service) {
			r := s.users["proof.admin"]
			r.PasswordHash = append([]byte(nil), r.PasswordHash...)
			r.PasswordHash[0] ^= 1
			s.users["proof.admin"] = r
		},
		"role":         func(s *Service) { r := s.users["proof.admin"]; r.Role = RoleOperator; s.users["proof.admin"] = r },
		"mfa":          func(s *Service) { r := s.users["proof.admin"]; r.MFAEnabled = true; s.users["proof.admin"] = r },
		"removed":      func(s *Service) { delete(s.users, "proof.admin") },
		"required mfa": func(s *Service) { s.mfaPolicy = MFAEnforcementAll },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s, u := proofService(t)
			_, p := quarantineTest(t, s)
			change(s)
			assert.ErrorIs(t, s.ValidateLoginProof(p.Proof, u.ID), ErrInvalidLoginProof)
			_, e := s.ResumeLoginProof(p.Proof)
			assert.ErrorIs(t, e, ErrInvalidLoginProof)
		})
	}
	s, u := proofService(t)
	_, p := quarantineTest(t, s)
	raw, e := base64.RawURLEncoding.DecodeString(p.Proof)
	require.NoError(t, e)
	raw[len(raw)-1] ^= 1
	assert.ErrorIs(t, s.ValidateLoginProof(base64.RawURLEncoding.EncodeToString(raw), u.ID), ErrInvalidLoginProof)
	assert.ErrorIs(t, s.ValidateLoginProof(strings.Repeat("x", 8193), u.ID), ErrInvalidLoginProof)
	s.now = func() time.Time { return p.ExpiresAt }
	assert.ErrorIs(t, s.ValidateLoginProof(p.Proof, u.ID), ErrInvalidLoginProof)
}
func TestLoginProofRejectsChangedCredentialBeforeQuarantine(t *testing.T) {
	s, _ := proofService(t)
	login, e := s.Authenticate("proof.admin", "synthetic-proof-password")
	require.NoError(t, e)
	r := s.users["proof.admin"]
	r.Role = RoleOperator
	s.users["proof.admin"] = r
	_, e = s.QuarantineLogin(login.AccessToken)
	assert.ErrorIs(t, e, ErrInvalidLoginProof)
}
func TestLoginProofRejectsStaleSessionsAndUnavailableEncryption(t *testing.T) {
	s, _ := proofService(t)
	login, e := s.Authenticate("proof.admin", "synthetic-proof-password")
	require.NoError(t, e)
	now := s.now()
	s.now = func() time.Time { return now.Add(61 * time.Second) }
	_, e = s.QuarantineLogin(login.AccessToken)
	assert.ErrorIs(t, e, ErrInvalidLoginProof)
	s.now = func() time.Time { return now }
	s.aead = nil
	_, e = s.QuarantineLogin(login.AccessToken)
	assert.ErrorIs(t, e, ErrLoginProofUnavailable)
}
func TestLoginProofExternalAndPasskeyRevocation(t *testing.T) {
	for _, source := range []string{"oidc", "ldap", "cas", "saml"} {
		t.Run(source, func(t *testing.T) {
			s, _ := proofService(t)
			enabled := true
			s.SetExternalSourceAllowed(source, func(string) bool { return enabled })
			u, e := s.EnsureExternalUser(source, "https://synthetic.invalid", "subject", "proof."+source, true)
			require.NoError(t, e)
			login, challenge, e := s.AuthenticateExternalUser(u.ID, source, "")
			require.NoError(t, e)
			require.Nil(t, challenge)
			p, e := s.QuarantineLogin(login.AccessToken)
			require.NoError(t, e)
			assert.Equal(t, source, p.AuthSource)
			require.NoError(t, s.ValidateLoginProof(p.Proof, u.ID))
			enabled = false
			assert.ErrorIs(t, s.ValidateLoginProof(p.Proof, u.ID), ErrInvalidLoginProof)
		})
	}
	s, u := proofService(t)
	allowed := true
	s.SetPasskeyAllowed(func(user, id string) bool { return allowed && user == u.ID && id == "credential" })
	login, setup, e := s.AuthenticatePasskeyUser(u.ID, "credential", "")
	require.NoError(t, e)
	require.Nil(t, setup)
	p, e := s.QuarantineLogin(login.AccessToken)
	require.NoError(t, e)
	assert.Equal(t, "passkey", p.AuthSource)
	allowed = false
	_, e = s.ResumeLoginProof(p.Proof)
	assert.ErrorIs(t, e, ErrInvalidLoginProof)
}
func TestLoginProofMFASetupAndReload(t *testing.T) {
	s, u := proofService(t)
	_, e := s.SetMFAEnforcement(MFAEnforcementAll)
	require.NoError(t, e)
	_, challenge, e := s.AuthenticateWithOTPOrMFASetup(u.Username, "synthetic-proof-password", "")
	require.NoError(t, e)
	require.NotNil(t, challenge)
	_, e = s.QuarantineLogin(challenge.Token)
	assert.ErrorIs(t, e, ErrInvalidLoginProof)
	code := testTOTPCode(t, challenge.Enrollment.Secret, uint64(s.now().Unix()/int64(totpPeriod/time.Second)))
	login, e := s.ConfirmMFASetupChallenge(challenge.Token, code)
	require.NoError(t, e)
	p, e := s.QuarantineLogin(login.AccessToken)
	require.NoError(t, e)
	reloaded, e := OpenServiceWithVaultKey(s.path, []byte(strings.Repeat("p", 32)))
	require.NoError(t, e)
	require.NoError(t, reloaded.ValidateLoginProof(p.Proof, u.ID))
	_, e = reloaded.ResumeLoginProof(p.Proof)
	require.NoError(t, e)
	wrong, e := OpenServiceWithVaultKey(s.path, []byte(strings.Repeat("w", 32)))
	if e == nil {
		assert.ErrorIs(t, wrong.ValidateLoginProof(p.Proof, u.ID), ErrInvalidLoginProof)
	}
	data, e := os.ReadFile(s.path)
	require.NoError(t, e)
	assert.NotContains(t, string(data), p.Proof)
	assert.NotContains(t, string(data), login.AccessToken)
}
