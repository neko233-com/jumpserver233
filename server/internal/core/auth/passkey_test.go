package auth

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasskeyPrimaryEnforcesMFAAndTaggedSetup(t *testing.T) {
	s := externalService(t)
	user := s.ListUsers()[0]
	s.SetPasskeyAllowed(func(id, key string) bool { return id == user.ID && key == "1.synthetic" })
	_, _, err := s.AuthenticatePasskeyUser(user.ID, "foreign", "")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
	_, err = s.SetMFAEnforcement(MFAEnforcementAll)
	require.NoError(t, err)
	now := time.Unix(1700000010, 0)
	s.now = func() time.Time { return now }
	login, setup, err := s.AuthenticatePasskeyUser(user.ID, "1.synthetic", "")
	require.NoError(t, err)
	assert.Empty(t, login.AccessToken)
	require.NotNil(t, setup)
	code := testTOTPCode(t, setup.Enrollment.Secret, uint64(now.Unix()/30))
	_, err = s.ConfirmMFASetupChallenge(setup.Token, code)
	assert.ErrorIs(t, err, ErrMFASetupChallenge)
	_, err = s.ConfirmMFASetupChallenge(setup.Token, code, user.ID)
	assert.ErrorIs(t, err, ErrMFASetupChallenge)
	_, err = s.ConfirmPasskeyMFASetupChallenge(setup.Token, code, user.ID, "foreign")
	assert.ErrorIs(t, err, ErrMFASetupChallenge)
	login, err = s.ConfirmPasskeyMFASetupChallenge(setup.Token, code, user.ID, "1.synthetic")
	require.NoError(t, err)
	assert.True(t, login.User.MFAEnabled)
	_, ok := s.ValidateToken(login.AccessToken)
	assert.True(t, ok)
	_, _, err = s.AuthenticatePasskeyUser(user.ID, "1.synthetic", "")
	assert.ErrorIs(t, err, ErrOTPRequired)
	now = now.Add(30 * time.Second)
	code = testTOTPCode(t, setup.Enrollment.Secret, uint64(now.Unix()/30))
	assert.ErrorIs(t, s.VerifyPasskeyManagement(user.ID, "", code, login.AccessToken), ErrInvalidCredentials)
	require.NoError(t, s.VerifyPasskeyManagement(user.ID, "synthetic-local-admin-password", code, login.AccessToken))
	assert.Error(t, s.VerifyPasskeyManagement(user.ID, "", code, login.AccessToken))
	now = now.Add(6 * time.Minute)
	code = testTOTPCode(t, setup.Enrollment.Secret, uint64(now.Unix()/30))
	assert.Error(t, s.VerifyPasskeyManagement(user.ID, "", code, login.AccessToken))
}
func TestPasskeyExternalSourcesRemainControlledAndRequireSSOForManagement(t *testing.T) {
	for _, source := range []string{"oidc", "ldap", "cas", "saml"} {
		t.Run(source, func(t *testing.T) {
			s := externalService(t)
			issuer := "https://idp.example.invalid"
			enabled := true
			s.SetExternalSourceAllowed(source, func(value string) bool { return enabled && value == issuer })
			u, e := s.EnsureExternalUser(source, issuer, "subject", "", true)
			require.NoError(t, e)
			s.SetPasskeyAllowed(func(id, key string) bool { return id == u.ID && key == "1.synthetic" })
			passkey, _, e := s.AuthenticatePasskeyUser(u.ID, "1.synthetic", "")
			require.NoError(t, e)
			assert.Equal(t, source, passkey.User.Source)
			assert.Equal(t, RoleOperator, passkey.User.Role)
			assert.ErrorIs(t, s.VerifyPasskeyManagement(u.ID, "", "", passkey.AccessToken), ErrExternalReauthRequired)
			assert.ErrorIs(t, s.verifyMFACredential(s.users[u.Username], "", []string{passkey.AccessToken}), ErrExternalReauthRequired)
			sso, _, e := s.AuthenticateExternalUser(u.ID, source, "")
			require.NoError(t, e)
			assert.NoError(t, s.VerifyPasskeyManagement(u.ID, "", "", sso.AccessToken))
			enabled = false
			_, _, e = s.AuthenticatePasskeyUser(u.ID, "1.synthetic", "")
			assert.ErrorIs(t, e, ErrInvalidCredentials)
			_, ok := s.ValidateToken(passkey.AccessToken)
			assert.False(t, ok)
		})
	}
}
func TestPasskeyLongLivedTokensAndPasswordSessionsCannotReplaceProof(t *testing.T) {
	s := externalService(t)
	u := s.ListUsers()[0]
	token, e := s.CreatePermanentToken(u.ID)
	require.NoError(t, e)
	assert.Error(t, s.VerifyPasskeyManagement(u.ID, "", "", token.Token))
	assert.Error(t, s.VerifyPasskeyManagement(u.ID, "wrong-password", "", token.Token))
	_, e = s.SetMFAEnforcement(MFAEnforcementAll)
	require.NoError(t, e)
	assert.False(t, s.PasskeyManagementReady(u.ID))
}
func TestPasskeySharedSessionKeepsCredentialBinding(t *testing.T) {
	url := os.Getenv("JMS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for shared Passkey sessions")
	}
	docs, e := storage.OpenPostgres(context.Background(), url, "passkey-auth-"+time.Now().Format("150405.000000000"))
	require.NoError(t, e)
	defer docs.Close()
	defer docs.Delete("users")
	defer docs.Delete("auth-sessions")
	root := t.TempDir()
	s, e := OpenServiceWithDocumentsAndVaultKey(filepath.Join(root, "users.json"), docs, make([]byte, 32))
	require.NoError(t, e)
	u, e := s.Bootstrap("qa.user", "synthetic-primary-password-233")
	require.NoError(t, e)
	s.SetPasskeyAllowed(func(id, key string) bool { return id == u.ID && key == "1.synthetic" })
	login, _, e := s.AuthenticatePasskeyUser(u.ID, "1.synthetic", "")
	require.NoError(t, e)
	next, e := OpenServiceWithDocumentsAndVaultKey(filepath.Join(t.TempDir(), "users.json"), docs, make([]byte, 32))
	require.NoError(t, e)
	next.SetPasskeyAllowed(func(id, key string) bool { return id == u.ID && key == "1.synthetic" })
	_, ok := next.ValidateToken(login.AccessToken)
	assert.True(t, ok)
	next.SetPasskeyAllowed(func(string, string) bool { return false })
	_, ok = next.ValidateToken(login.AccessToken)
	assert.False(t, ok)
}
