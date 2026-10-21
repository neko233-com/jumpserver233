package auth

import (
	"context"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func passwordActorFor(t *testing.T, s *Service, id string) UserActor {
	t.Helper()
	u, e := s.ManagedUser(id)
	require.NoError(t, e)
	return UserActor{ID: u.ID, Name: u.Username, AuthGeneration: u.AuthGeneration, ManageAdministrators: true, ManageCredentials: true}
}
func TestPasswordSecurityDuplicateRequestsDoNotRepeatSideEffects(t *testing.T) {
	s, a, u, _ := lifecycleEnv(t)
	actor := passwordActorFor(t, s, a.ID)
	login, e := s.Authenticate(a.Username, "synthetic-lifecycle-admin-233")
	require.NoError(t, e)
	original := s.PasswordPolicy()
	unchanged, e := s.SavePasswordPolicy(original, actor)
	require.NoError(t, e)
	assert.Equal(t, original, unchanged)
	_, ok := s.ValidateToken(login.AccessToken)
	assert.True(t, ok)
	_, n, e := s.PasswordPolicyAudit(0, 25)
	require.NoError(t, e)
	assert.Zero(t, n)
	changed := original
	changed.MinLength = 16
	_, e = s.SavePasswordPolicy(changed, actor)
	require.NoError(t, e)
	actor = passwordActorFor(t, s, a.ID)
	before, e := s.ManagedUser(u.ID)
	require.NoError(t, e)
	_, e = s.SavePasswordPolicy(changed, actor)
	assert.ErrorIs(t, e, ErrUserRevision)
	after, e := s.ManagedUser(u.ID)
	require.NoError(t, e)
	assert.Equal(t, before, after)
	_, n, e = s.PasswordPolicyAudit(0, 25)
	require.NoError(t, e)
	assert.Equal(t, 1, n)
	reset, e := s.ResetCredentials(u.ID, before.Revision, "password_reset", "synthetic-idempotency-password-233", true, actor)
	require.NoError(t, e)
	_, e = s.ResetCredentials(u.ID, before.Revision, "password_reset", "synthetic-idempotency-password-233", true, actor)
	assert.ErrorIs(t, e, ErrUserRevision)
	after, e = s.ManagedUser(u.ID)
	require.NoError(t, e)
	assert.Equal(t, reset, after)
	assert.Len(t, s.userEvents, 1)
}
func savePasswordPolicyFor(t *testing.T, s *Service, a User, change func(*PasswordPolicy)) PasswordPolicy {
	t.Helper()
	p := s.PasswordPolicy()
	change(&p)
	out, e := s.SavePasswordPolicy(p, passwordActorFor(t, s, a.ID))
	require.NoError(t, e)
	return out
}
func TestPasswordRulesClassesUTF8AndRoleSpecificLength(t *testing.T) {
	p := defaultPasswordPolicy()
	p.AdminMinLength = 20
	p.RequireUpper = true
	p.RequireLower = true
	p.RequireDigit = true
	p.RequireSpecial = true
	for _, v := range []string{"short", "abcdefghijklmnop", "ABCDEFGHIJKLMNOP", "Abcdefghijklmnop", "Abcdefghi1234567", "Abc1!\x00abcdefghijkl", string([]byte{255}) + "Abcdefgh123!"} {
		assert.Error(t, p.check(v, RoleOperator), v)
	}
	assert.NoError(t, p.check("Abcd-12345678", RoleOperator))
	assert.Error(t, p.check("Abcd-12345678", RoleAdmin))
	assert.NoError(t, p.check("Abcd-12345678901234567890", RoleAdmin))
	assert.NoError(t, p.check("中文汉字密码Abc1!", RoleOperator))
	assert.Error(t, p.check(strings.Repeat("A", 257), RoleAdmin))
}
func TestPasswordPolicyRevokesAllLocalCredentialsAndPreservesExternalIdentity(t *testing.T) {
	s, a, u, _ := lifecycleEnv(t)
	login, e := s.Authenticate(u.Username, "synthetic-lifecycle-user-233")
	require.NoError(t, e)
	permanent, e := s.CreatePermanentToken(u.ID)
	require.NoError(t, e)
	_, e = s.CreateAccessKey(u.ID)
	require.NoError(t, e)
	s.SetExternalSourceAllowed("oidc", func(string) bool { return true })
	external, e := s.EnsureOIDCUser("https://provider.invalid", "subject", "", true)
	require.NoError(t, e)
	externalLogin, _, e := s.AuthenticateExternalUser(external.ID, "oidc", "")
	require.NoError(t, e)
	p := savePasswordPolicyFor(t, s, a, func(p *PasswordPolicy) { p.MinLength = 16; p.HistoryCount = 3 })
	assert.Equal(t, 2, p.Revision)
	_, ok := s.ValidateToken(login.AccessToken)
	assert.False(t, ok)
	_, ok = s.ValidatePermanentToken(permanent.Token)
	assert.False(t, ok)
	keys, e := s.ListAccessKeys(u.ID)
	require.NoError(t, e)
	assert.Empty(t, keys)
	_, ok = s.ValidateToken(externalLogin.AccessToken)
	assert.True(t, ok)
	_, e = s.CreateUser("too.short", "long-password", RoleOperator)
	assert.ErrorIs(t, e, ErrPasswordPolicy)
	_, e = s.CreateUser("valid.user", "long-enough-password-233", RoleOperator)
	require.NoError(t, e)
	events, n, e := s.PasswordPolicyAudit(0, 25)
	require.NoError(t, e)
	assert.Equal(t, 1, n)
	assert.Equal(t, 2, events[0].Affected)
	old := p
	old.Revision = 1
	_, e = s.SavePasswordPolicy(old, passwordActorFor(t, s, a.ID))
	assert.ErrorIs(t, e, ErrUserRevision)
	reloaded, e := OpenServiceWithVaultKey(s.path, make([]byte, 32))
	require.NoError(t, e)
	assert.Equal(t, p, reloaded.PasswordPolicy())
	_, n, e = reloaded.PasswordPolicyAudit(0, 25)
	require.NoError(t, e)
	assert.Equal(t, 1, n)
}
func TestPasswordHistoryAndPersonalSessionContract(t *testing.T) {
	s, a, u, _ := lifecycleEnv(t)
	savePasswordPolicyFor(t, s, a, func(p *PasswordPolicy) { p.HistoryCount = 2 })
	old := "synthetic-lifecycle-user-233"
	first := "synthetic-new-password-first-233"
	second := "synthetic-new-password-second-233"
	login, e := s.Authenticate(u.Username, old)
	require.NoError(t, e)
	other, e := s.Authenticate(u.Username, old)
	require.NoError(t, e)
	api, e := s.CreatePermanentToken(u.ID)
	require.NoError(t, e)
	require.NoError(t, s.ChangePassword(u.ID, login.AccessToken, old, first))
	_, ok := s.ValidateToken(login.AccessToken)
	assert.True(t, ok)
	_, ok = s.ValidateToken(other.AccessToken)
	assert.False(t, ok)
	_, ok = s.ValidatePermanentToken(api.Token)
	assert.True(t, ok)
	assert.ErrorIs(t, s.ChangePassword(u.ID, login.AccessToken, first, old), ErrPasswordHistory)
	require.NoError(t, s.ChangePassword(u.ID, login.AccessToken, first, second))
	assert.ErrorIs(t, s.ChangePassword(u.ID, login.AccessToken, second, first), ErrPasswordHistory)
	raw, e := os.ReadFile(s.path)
	require.NoError(t, e)
	for _, secret := range []string{old, first, second, api.Token, login.AccessToken} {
		assert.NotContains(t, string(raw), secret)
	}
	reload, e := OpenServiceWithVaultKey(s.path, make([]byte, 32))
	require.NoError(t, e)
	assert.ErrorIs(t, reload.ChangePassword(u.ID, "", second, first), ErrPasswordHistory)
	wrong := make([]byte, 32)
	wrong[0] = 1
	_, e = OpenServiceWithVaultKey(s.path, wrong)
	assert.ErrorIs(t, e, ErrUserStoreCorrupt)
}
func TestPasswordLegacyHistoryChecksSaltedHashBeforeMigration(t *testing.T) {
	s, a, u, _ := lifecycleEnv(t)
	r := s.users[u.Username]
	r.PasswordFingerprint = nil
	s.users[u.Username] = r
	savePasswordPolicyFor(t, s, a, func(p *PasswordPolicy) { p.HistoryCount = 2 })
	old := "synthetic-lifecycle-user-233"
	require.NoError(t, s.ChangePassword(u.ID, "", old, "synthetic-fresh-password-233"))
	assert.ErrorIs(t, s.ChangePassword(u.ID, "", "synthetic-fresh-password-233", old), ErrPasswordHistory)
	history := s.users[u.Username].PasswordHistory
	require.Len(t, history, 1)
	assert.Len(t, history[0].Salt, 16)
	assert.Empty(t, history[0].Fingerprint)
}
func TestPasswordExpiryRestrictedProofBoundToSourceAndReplay(t *testing.T) {
	s, a, u, _ := lifecycleEnv(t)
	savePasswordPolicyFor(t, s, a, func(p *PasswordPolicy) { p.MaxAgeDays = 1; p.HistoryCount = 3 })
	now := u.CreatedAt.Add(24 * time.Hour)
	s.now = func() time.Time { return now }
	require.True(t, s.PasswordChangeRequired(u.ID))
	_, ok := s.ActiveUserByID(u.ID)
	assert.False(t, ok)
	login, e := s.Authenticate(u.Username, "synthetic-lifecycle-user-233")
	require.NoError(t, e)
	pending, e := s.BeginPasswordChange(login.AccessToken, "192.0.2.1")
	require.NoError(t, e)
	_, ok = s.ValidateToken(login.AccessToken)
	assert.False(t, ok)
	assert.ErrorIs(t, s.CompletePasswordChange(pending.Token, "192.0.2.2", "synthetic-new-password-233"), ErrPasswordChallenge)
	assert.ErrorIs(t, s.CompletePasswordChange(pending.Token, "192.0.2.1", "short"), ErrInvalidPassword)
	require.NoError(t, s.CompletePasswordChange(pending.Token, "192.0.2.1", "synthetic-new-password-233"))
	assert.False(t, s.PasswordChangeRequired(u.ID))
	assert.ErrorIs(t, s.CompletePasswordChange(pending.Token, "192.0.2.1", "synthetic-other-password-233"), ErrPasswordChallenge)
	assert.Equal(t, now, s.users[u.Username].PasswordChangedAt)
	fresh, e := s.Authenticate(u.Username, "synthetic-new-password-233")
	require.NoError(t, e)
	_, ok = s.ValidateToken(fresh.AccessToken)
	assert.True(t, ok)
	_, e = s.Authenticate(u.Username, "synthetic-lifecycle-user-233")
	assert.ErrorIs(t, e, ErrInvalidCredentials)
}
func TestPasswordRecoveryPermissionsRevisionAndDisabledState(t *testing.T) {
	s, a, u, _ := lifecycleEnv(t)
	actor := passwordActorFor(t, s, a.ID)
	denied := actor
	denied.ManageCredentials = false
	_, e := s.ResetCredentials(u.ID, 1, "password_reset", "synthetic-reset-password-233", true, denied)
	assert.ErrorIs(t, e, ErrCredentialPermission)
	_, e = s.ResetCredentials(a.ID, 1, "mfa_reset", "", false, actor)
	assert.ErrorIs(t, e, ErrUserSelf)
	_, e = s.ResetCredentials(u.ID, 99, "password_reset", "synthetic-reset-password-233", true, actor)
	assert.ErrorIs(t, e, ErrUserRevision)
	disabled := false
	row := lifecycleChange(t, s, u, actor, "update", UserUpdate{IsActive: &disabled})
	row, e = s.ResetCredentials(u.ID, row.Revision, "password_reset", "synthetic-reset-password-233", true, actor)
	require.NoError(t, e)
	assert.Equal(t, "disabled", row.State)
	assert.True(t, row.PasswordChangeRequired)
	disabled = true
	lifecycleChange(t, s, u, actor, "update", UserUpdate{IsActive: &disabled})
	login, e := s.Authenticate(u.Username, "synthetic-reset-password-233")
	require.NoError(t, e)
	pending, e := s.BeginPasswordChange(login.AccessToken, "127.0.0.1")
	require.NoError(t, e)
	require.NoError(t, s.CancelPasswordChange(pending.Token, "127.0.0.1"))
	_, e = s.PasswordChangePending(pending.Token, "127.0.0.1")
	assert.ErrorIs(t, e, ErrPasswordChallenge)
	assert.True(t, s.PasswordChangeRequired(u.ID))
	s.SetExternalSourceAllowed("ldap", func(string) bool { return true })
	external, e := s.EnsureExternalUser("ldap", "https://directory.invalid", "subject", "", true)
	require.NoError(t, e)
	_, e = s.ResetCredentials(external.ID, 1, "password_reset", "synthetic-reset-password-233", true, actor)
	assert.ErrorIs(t, e, ErrExternalIdentity)
}
func TestPasswordMFARecoveryRevokesCodesAndEnforcesNewEnrollment(t *testing.T) {
	s, a, u, _ := lifecycleEnv(t)
	enroll, e := s.StartMFAEnrollment(u.ID)
	require.NoError(t, e)
	now := s.now()
	code := testTOTPCode(t, enroll.Secret, uint64(now.Unix()/30))
	_, e = s.ConfirmMFAEnrollment(u.ID, code)
	require.NoError(t, e)
	row, e := s.ManagedUser(u.ID)
	require.NoError(t, e)
	_, e = s.ResetCredentials(u.ID, row.Revision, "mfa_reset", "", false, passwordActorFor(t, s, a.ID))
	require.NoError(t, e)
	r := s.users[u.Username]
	assert.False(t, r.MFAEnabled)
	assert.Empty(t, r.MFASecretCiphertext)
	assert.Empty(t, r.MFARecoveryCodeHashes)
	assert.Empty(t, r.MFASetupChallengeHash)
	_, e = s.SetMFAEnforcement(MFAEnforcementAll)
	require.NoError(t, e)
	_, setup, e := s.AuthenticateWithOTPOrMFASetup(u.Username, "synthetic-lifecycle-user-233", "")
	require.NoError(t, e)
	require.NotNil(t, setup)
	assert.NotEqual(t, enroll.Secret, setup.Enrollment.Secret)
}
func TestPasswordPolicyPersistenceFailureRollsBackAllUserEpochs(t *testing.T) {
	s, a, u, _ := lifecycleEnv(t)
	original := s.path
	s.path = t.TempDir()
	p := s.PasswordPolicy()
	p.HistoryCount = 2
	_, e := s.SavePasswordPolicy(p, passwordActorFor(t, s, a.ID))
	require.Error(t, e)
	assert.Equal(t, 1, s.PasswordPolicy().Revision)
	assert.Zero(t, s.users[u.Username].AuthGeneration)
	_, n, e := s.PasswordPolicyAudit(0, 25)
	require.NoError(t, e)
	assert.Zero(t, n)
	_, e = s.ResetCredentials(u.ID, 1, "password_reset", "synthetic-recovery-password-233", true, passwordActorFor(t, s, a.ID))
	require.Error(t, e)
	assert.Zero(t, s.users[u.Username].AuthGeneration)
	s.path = original
	_, e = s.Authenticate(u.Username, "synthetic-lifecycle-user-233")
	require.NoError(t, e)
}
func TestPasswordChallengeInvalidatedByPolicyLifecycleAndTimeout(t *testing.T) {
	for _, kind := range []string{"policy", "revoke", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			s, a, u, _ := lifecycleEnv(t)
			_, e := s.ResetCredentials(u.ID, 1, "password_reset", "synthetic-recovery-password-233", true, passwordActorFor(t, s, a.ID))
			require.NoError(t, e)
			login, e := s.Authenticate(u.Username, "synthetic-recovery-password-233")
			require.NoError(t, e)
			pending, e := s.BeginPasswordChange(login.AccessToken, "127.0.0.1")
			require.NoError(t, e)
			switch kind {
			case "policy":
				savePasswordPolicyFor(t, s, a, func(p *PasswordPolicy) { p.MinLength = 16 })
			case "revoke":
				lifecycleChange(t, s, u, passwordActorFor(t, s, a.ID), "revoke", UserUpdate{})
			case "timeout":
				s.now = func() time.Time { return pending.ExpiresAt }
			}
			_, e = s.PasswordChangePending(pending.Token, "127.0.0.1")
			assert.ErrorIs(t, e, ErrPasswordChallenge)
		})
	}
}
func TestPasswordSharedChallengeAndSecurityEpochSurviveFailover(t *testing.T) {
	url := os.Getenv("JMS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("PostgreSQL integration fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	docs, e := storage.OpenPostgres(ctx, url, "password-security-"+time.Now().Format("150405.000000000"))
	require.NoError(t, e)
	t.Cleanup(func() { _ = docs.Delete("users"); _ = docs.Delete("auth-sessions"); _ = docs.Close() })
	path := filepath.Join(t.TempDir(), "users.json")
	s, e := OpenServiceWithDocumentsAndVaultKey(path, docs, make([]byte, 32))
	require.NoError(t, e)
	a, e := s.Bootstrap("admin", "synthetic-security-admin-233")
	require.NoError(t, e)
	u, e := s.CreateUser("operator", "synthetic-original-password-233", RoleOperator)
	require.NoError(t, e)
	login, e := s.Authenticate(u.Username, "synthetic-original-password-233")
	require.NoError(t, e)
	stale, e := docs.Load("auth-sessions")
	require.NoError(t, e)
	_, e = s.ResetCredentials(u.ID, 1, "password_reset", "synthetic-recovery-password-233", true, passwordActorFor(t, s, a.ID))
	require.NoError(t, e)
	login, e = s.Authenticate(u.Username, "synthetic-recovery-password-233")
	require.NoError(t, e)
	pending, e := s.BeginPasswordChange(login.AccessToken, "192.0.2.1")
	require.NoError(t, e)
	leader, e := OpenServiceWithDocumentsAndVaultKey(path, docs, make([]byte, 32))
	require.NoError(t, e)
	_, e = leader.PasswordChangePending(pending.Token, "192.0.2.1")
	require.NoError(t, e)
	require.NoError(t, leader.CompletePasswordChange(pending.Token, "192.0.2.1", "synthetic-finished-password-233"))
	require.NoError(t, docs.Save("auth-sessions", stale))
	leader, e = OpenServiceWithDocumentsAndVaultKey(path, docs, make([]byte, 32))
	require.NoError(t, e)
	assert.Empty(t, leader.sessions)
	_, e = leader.PasswordChangePending(pending.Token, "192.0.2.1")
	assert.ErrorIs(t, e, ErrPasswordChallenge)
	raw, e := docs.Load("users")
	require.NoError(t, e)
	var envelope map[string]any
	require.NoError(t, json.Unmarshal(raw, &envelope))
	assert.Equal(t, float64(4), envelope["version"])
}
