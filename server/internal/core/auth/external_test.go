package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func externalService(t *testing.T) *Service {
	t.Helper()
	s, err := OpenServiceWithVaultKey(filepath.Join(t.TempDir(), "users.json"), make([]byte, 32))
	require.NoError(t, err)
	_, err = s.Bootstrap("admin.user", "synthetic-local-admin-password")
	require.NoError(t, err)
	s.SetExternalIssuerAllowed(func(issuer string) bool { return issuer == "https://issuer.example.invalid" })
	return s
}

func TestExternalLoginFailsWithoutProviderInitializer(t *testing.T) {
	s := externalService(t)
	user, err := s.EnsureOIDCUser("https://issuer.example.invalid", "subject", "", true)
	require.NoError(t, err)
	s.SetExternalIssuerAllowed(nil)
	_, _, err = s.AuthenticateOIDCUser(user.ID, "")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestExternalSourcesNeverCrossAuthenticateOrRevokeEachOther(t *testing.T) {
	for _, source := range []string{"ldap", "cas", "saml"} {
		t.Run(source, func(t *testing.T) {
			s := externalService(t)
			s.SetExternalSourceAllowed(source, func(issuer string) bool { return issuer == "https://issuer.example.invalid" })
			oidc, err := s.EnsureOIDCUser("https://issuer.example.invalid", "same-subject", "", true)
			require.NoError(t, err)
			directory, err := s.EnsureExternalUser(source, "https://issuer.example.invalid", "same-subject", "", true)
			require.NoError(t, err)
			assert.NotEqual(t, oidc.ID, directory.ID)
			_, _, err = s.AuthenticateOIDCUser(directory.ID, "")
			assert.ErrorIs(t, err, ErrInvalidCredentials)
			old, _, err := s.AuthenticateOIDCUser(oidc.ID, "")
			require.NoError(t, err)
			login, _, err := s.AuthenticateExternalUser(directory.ID, source, "")
			require.NoError(t, err)
			token, err := s.CreatePermanentToken(directory.ID)
			require.NoError(t, err)
			key, err := s.CreateAccessKey(directory.ID)
			require.NoError(t, err)
			mac := hmac.New(sha256.New, []byte(key.Secret))
			mac.Write([]byte("request"))
			signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
			s.SetExternalSourceAllowed(source, nil)
			_, ok := s.ValidateToken(login.AccessToken)
			assert.False(t, ok)
			_, ok = s.ValidatePermanentToken(token.Token)
			assert.False(t, ok)
			_, ok = s.VerifyAccessKeySignature(key.ID, "request", signature)
			assert.False(t, ok)
			_, ok = s.ValidateToken(old.AccessToken)
			assert.True(t, ok)
			_, err = s.Authenticate(directory.Username, "synthetic-password")
			assert.ErrorIs(t, err, ErrInvalidCredentials)

		})
	}
}

func TestExternalIdentityDoesNotLinkLocalNamesOrAcceptPasswords(t *testing.T) {
	s := externalService(t)
	_, err := s.EnsureOIDCUser("https://issuer.example.invalid", "subject", "", false)
	assert.ErrorIs(t, err, ErrUserNotFound)
	_, err = s.EnsureOIDCUser("https://issuer.example.invalid", "subject", "admin.user", true)
	assert.ErrorIs(t, err, ErrUserExists)
	user, err := s.EnsureOIDCUser("https://issuer.example.invalid", "subject", "sso.operator", true)
	require.NoError(t, err)
	assert.Equal(t, RoleOperator, user.Role)
	assert.Equal(t, "oidc", user.Source)
	again, err := s.EnsureOIDCUser("https://issuer.example.invalid", "subject", "different.alias", true)
	require.NoError(t, err)
	assert.Equal(t, user.ID, again.ID)
	other, err := s.EnsureOIDCUser("https://another.example.invalid", "subject", "", true)
	require.NoError(t, err)
	assert.NotEqual(t, user.ID, other.ID)
	_, err = s.Authenticate("sso.operator", "synthetic-local-admin-password")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.ErrorIs(t, s.ChangePassword(user.ID, "", "anything", "synthetic-new-password"), ErrExternalIdentity)
	restored, err := OpenServiceWithVaultKey(s.path, make([]byte, 32))
	require.NoError(t, err)
	same, err := restored.EnsureOIDCUser("https://issuer.example.invalid", "subject", "", false)
	require.NoError(t, err)
	assert.Equal(t, user.ID, same.ID)
}
func TestExternalLoginEnforcesMFAAndRecentSSOProofForRecovery(t *testing.T) {
	for _, source := range []string{"oidc", "ldap", "cas", "saml"} {
		t.Run(source, func(t *testing.T) {
			s := externalService(t)
			s.SetExternalSourceAllowed(source, func(issuer string) bool { return issuer == "https://issuer.example.invalid" })
			now := time.Unix(1_700_000_010, 0)
			s.now = func() time.Time { return now }
			user, err := s.EnsureExternalUser(source, "https://issuer.example.invalid", "subject", "", true)
			require.NoError(t, err)
			_, err = s.SetMFAEnforcement(MFAEnforcementAll)
			require.NoError(t, err)
			login, setup, err := s.AuthenticateExternalUser(user.ID, source, "")
			require.NoError(t, err)
			assert.Empty(t, login.AccessToken)
			require.NotNil(t, setup)
			_, ok := s.ValidateToken(setup.Token)
			assert.False(t, ok)
			code := testTOTPCode(t, setup.Enrollment.Secret, uint64(now.Unix()/30))
			_, err = s.ConfirmMFASetupChallenge(setup.Token, code)
			assert.ErrorIs(t, err, ErrMFASetupChallenge)
			login, err = s.ConfirmMFASetupChallenge(setup.Token, code, user.ID)
			require.NoError(t, err)
			assert.True(t, login.User.MFAEnabled)
			_, _, err = s.AuthenticateExternalUser(user.ID, source, "")
			assert.ErrorIs(t, err, ErrOTPRequired)
			now = now.Add(30 * time.Second)
			code = testTOTPCode(t, setup.Enrollment.Secret, uint64(now.Unix()/30))
			_, err = s.RegenerateMFARecoveryCodes(user.ID, "", code)
			assert.ErrorIs(t, err, ErrExternalReauthRequired)
			recovery, err := s.RegenerateMFARecoveryCodes(user.ID, "", code, login.AccessToken)
			require.NoError(t, err)
			require.Len(t, recovery.Codes, 10)
			recovered, _, err := s.AuthenticateExternalUser(user.ID, source, recovery.Codes[0])
			require.NoError(t, err)
			assert.NotEmpty(t, recovered.AccessToken)
			_, _, err = s.AuthenticateExternalUser(user.ID, source, recovery.Codes[0])
			require.Error(t, err)
			now = now.Add(6 * time.Minute)
			code = testTOTPCode(t, setup.Enrollment.Secret, uint64(now.Unix()/30))
			_, err = s.RegenerateMFARecoveryCodes(user.ID, "", code, login.AccessToken)
			assert.ErrorIs(t, err, ErrExternalReauthRequired)

		})
	}
}

func TestDisabledIssuerBlocksSessionPermanentTokenAndAccessKey(t *testing.T) {
	s := externalService(t)
	issuer := "https://issuer.example.invalid"
	user, err := s.EnsureOIDCUser(issuer, "subject", "", true)
	require.NoError(t, err)
	var enabled atomic.Bool
	enabled.Store(true)
	s.SetExternalIssuerAllowed(func(value string) bool { return enabled.Load() && value == issuer })
	session, _, err := s.AuthenticateOIDCUser(user.ID, "")
	require.NoError(t, err)
	_, ok := s.ValidateToken(session.AccessToken)
	assert.True(t, ok)
	token, err := s.CreatePermanentToken(user.ID)
	require.NoError(t, err)
	_, ok = s.ValidatePermanentToken(token.Token)
	assert.True(t, ok)
	key, err := s.CreateAccessKey(user.ID)
	require.NoError(t, err)
	mac := hmac.New(sha256.New, []byte(key.Secret))
	mac.Write([]byte("signed-request"))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	_, ok = s.VerifyAccessKeySignature(key.ID, "signed-request", signature)
	assert.True(t, ok)
	enabled.Store(false)
	_, ok = s.ValidateToken(session.AccessToken)
	assert.False(t, ok)
	_, ok = s.ValidatePermanentToken(token.Token)
	assert.False(t, ok)
	_, ok = s.VerifyAccessKeySignature(key.ID, "signed-request", signature)
	assert.False(t, ok)
	_, _, err = s.AuthenticateOIDCUser(user.ID, "")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestExternalIdentityAndRecentSessionProofReloadFromPostgres(t *testing.T) {
	url := os.Getenv("JMS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for external-session PostgreSQL integration")
	}
	docs, err := storage.OpenPostgres(context.Background(), url, "external-auth-"+time.Now().Format("150405.000000000"))
	require.NoError(t, err)
	defer docs.Close()
	defer docs.Delete("users")
	defer docs.Delete("auth-sessions")
	path := filepath.Join(t.TempDir(), "users.json")
	s, err := OpenServiceWithDocumentsAndVaultKey(path, docs, make([]byte, 32))
	require.NoError(t, err)
	_, err = s.Bootstrap("admin.user", "synthetic-local-admin-password")
	require.NoError(t, err)
	s.SetExternalIssuerAllowed(func(issuer string) bool { return issuer == "https://issuer.example.invalid" })
	user, err := s.EnsureOIDCUser("https://issuer.example.invalid", "subject", "", true)
	require.NoError(t, err)
	login, _, err := s.AuthenticateOIDCUser(user.ID, "")
	require.NoError(t, err)
	next, err := OpenServiceWithDocumentsAndVaultKey(path, docs, make([]byte, 32))
	require.NoError(t, err)
	next.SetExternalIssuerAllowed(func(issuer string) bool { return issuer == "https://issuer.example.invalid" })
	current, ok := next.ValidateToken(login.AccessToken)
	require.True(t, ok)
	assert.Equal(t, "oidc", current.Source)
	next.mu.RLock()
	_, record, ok := next.storedUserByIDLocked(user.ID)
	next.mu.RUnlock()
	require.True(t, ok)
	require.NoError(t, next.verifyMFACredential(record, "", []string{login.AccessToken}))
}

func TestDirectoryIdentityAndRecentSessionReloadFromPostgres(t *testing.T) {
	for _, source := range []string{"ldap", "cas", "saml"} {
		t.Run(source, func(t *testing.T) {
			databaseURL := os.Getenv("JMS_TEST_DATABASE_URL")
			if databaseURL == "" {
				t.Skip("set JMS_TEST_DATABASE_URL for LDAP identity integration")
			}
			docs, err := storage.OpenPostgres(context.Background(), databaseURL, source+"-auth-"+time.Now().Format("150405.000000000"))
			require.NoError(t, err)
			defer docs.Close()
			defer docs.Delete("users")
			defer docs.Delete("auth-sessions")
			path := filepath.Join(t.TempDir(), "users.json")
			key := make([]byte, 32)
			s, err := OpenServiceWithDocumentsAndVaultKey(path, docs, key)
			require.NoError(t, err)
			_, err = s.Bootstrap("admin.user", "synthetic-local-admin-password")
			require.NoError(t, err)
			check := func(issuer string) bool { return issuer == source+":test-directory" }
			s.SetExternalSourceAllowed(source, check)
			user, err := s.EnsureExternalUser(source, source+":test-directory", "stable-id", "", true)
			require.NoError(t, err)
			session, _, err := s.AuthenticateExternalUser(user.ID, source, "")
			require.NoError(t, err)
			next, err := OpenServiceWithDocumentsAndVaultKey(path, docs, key)
			require.NoError(t, err)
			next.SetExternalSourceAllowed(source, check)
			current, ok := next.ValidateToken(session.AccessToken)
			require.True(t, ok)
			assert.Equal(t, source, current.Source)
			next.mu.RLock()
			_, record, ok := next.storedUserByIDLocked(user.ID)
			next.mu.RUnlock()
			require.True(t, ok)
			require.NoError(t, next.verifyMFACredential(record, "", []string{session.AccessToken}))

		})
	}
}
