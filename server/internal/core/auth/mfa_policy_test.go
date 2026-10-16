package auth

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDelegatedSystemRolesParticipateInAdminMFA(t *testing.T) {
	service, err := OpenServiceWithVaultKey(filepath.Join(t.TempDir(), "users.json"), make([]byte, 32))
	require.NoError(t, err)
	_, err = service.Bootstrap("admin.user", "synthetic-admin-password")
	require.NoError(t, err)
	operator, err := service.CreateUser("operator.user", "synthetic-operator-password", RoleOperator)
	require.NoError(t, err)
	service.SetPrivilegedCheck(func(id string) bool { return id == operator.ID })
	_, err = service.SetMFAEnforcement(MFAEnforcementAdmins)
	require.NoError(t, err)
	login, challenge, err := service.AuthenticateWithOTPOrMFASetup("operator.user", "synthetic-operator-password", "")
	require.NoError(t, err)
	require.NotNil(t, challenge)
	assert.Empty(t, login.AccessToken)
	now := service.now()
	code := testTOTPCode(t, challenge.Enrollment.Secret, uint64(now.Unix()/int64(totpPeriod/time.Second)))
	_, err = service.ConfirmMFASetupChallenge(challenge.Token, code)
	require.NoError(t, err)
	_, err = service.DisableMFA(operator.ID, "synthetic-operator-password", code)
	assert.ErrorIs(t, err, ErrMFARequiredByPolicy)
}

func TestGlobalMFAEnforcementSetupChallengeAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	key := []byte(strings.Repeat("p", 32))
	service, err := OpenServiceWithVaultKey(path, key)
	if err != nil {
		t.Fatal(err)
	}
	const adminPassword = "an-initial-admin-password-123"
	const operatorPassword = "an-initial-operator-password-123"
	admin, err := service.Bootstrap("admin.user", adminPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateUser("operator.user", operatorPassword, RoleOperator); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_010, 0).UTC()
	service.now = func() time.Time { return now }
	if _, err := service.SetMFAEnforcement(MFAEnforcementAdmins); err != nil {
		t.Fatal(err)
	}

	if _, err := service.AuthenticateWithOTP("admin.user", adminPassword, ""); !errors.Is(err, ErrMFASetupRequired) {
		t.Fatalf("legacy login method error = %v, want ErrMFASetupRequired", err)
	}
	adminSession, challenge, err := service.AuthenticateWithOTPOrMFASetup("admin.user", adminPassword, "")
	if err != nil || challenge == nil || adminSession.AccessToken != "" {
		t.Fatalf("unenrolled admin sign-in = %+v, %+v, %v; want setup-only challenge", adminSession, challenge, err)
	}
	if _, ok := service.ValidateToken(challenge.Token); ok {
		t.Fatal("setup challenge was accepted as a bearer session")
	}
	if _, err := service.ConfirmMFASetupChallenge("invalid-token", "000000"); !errors.Is(err, ErrMFASetupChallenge) {
		t.Fatalf("invalid setup challenge = %v, want ErrMFASetupChallenge", err)
	}
	if _, err := service.ConfirmMFASetupChallenge(challenge.Token, "bad-code"); !errors.Is(err, ErrInvalidOTP) {
		t.Fatalf("invalid setup code = %v, want ErrInvalidOTP", err)
	}
	step := uint64(now.Unix() / int64(totpPeriod/time.Second))
	code := testTOTPCode(t, challenge.Enrollment.Secret, step)
	login, err := service.ConfirmMFASetupChallenge(challenge.Token, code)
	if err != nil || login.AccessToken == "" || !login.User.MFAEnabled {
		t.Fatalf("confirm setup challenge = %+v, %v", login, err)
	}
	if user, ok := service.ValidateToken(login.AccessToken); !ok || user.ID != admin.ID || !user.MFAEnabled {
		t.Fatalf("setup-issued session = %+v, %v", user, ok)
	}
	if _, err := service.ConfirmMFASetupChallenge(challenge.Token, code); !errors.Is(err, ErrMFASetupChallenge) {
		t.Fatalf("replayed setup challenge = %v, want ErrMFASetupChallenge", err)
	}
	if _, err := service.DisableMFA(admin.ID, adminPassword, "000000"); !errors.Is(err, ErrMFARequiredByPolicy) {
		t.Fatalf("disable MFA under policy = %v, want ErrMFARequiredByPolicy", err)
	}
	if session, setup, err := service.AuthenticateWithOTPOrMFASetup("operator.user", operatorPassword, ""); err != nil || setup != nil || session.AccessToken == "" {
		t.Fatalf("operator sign-in with admins-only policy = %+v, %+v, %v", session, setup, err)
	}

	if _, err := service.SetMFAEnforcement(MFAEnforcementAll); err != nil {
		t.Fatal(err)
	}
	if _, setup, err := service.AuthenticateWithOTPOrMFASetup("operator.user", operatorPassword, ""); err != nil || setup == nil {
		t.Fatalf("operator sign-in after all-users policy = challenge %+v, %v", setup, err)
	}
	reloaded, err := OpenServiceWithVaultKey(path, key)
	if err != nil {
		t.Fatalf("reload user and policy stores: %v", err)
	}
	if got := reloaded.MFAEnforcementSettings().Mode; got != MFAEnforcementAll {
		t.Fatalf("reloaded MFA policy = %q, want %q", got, MFAEnforcementAll)
	}
}

func TestGlobalMFAEnforcementRequiresVaultKeyAndSetupChallengeExpires(t *testing.T) {
	withoutKey, err := OpenService(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withoutKey.Bootstrap("admin.user", "an-initial-admin-password-123"); err != nil {
		t.Fatal(err)
	}
	if _, err := withoutKey.SetMFAEnforcement(MFAEnforcementAdmins); !errors.Is(err, ErrMFAKeyUnavailable) {
		t.Fatalf("enable policy without Vault key = %v, want ErrMFAKeyUnavailable", err)
	}

	path := filepath.Join(t.TempDir(), "users.json")
	service, err := OpenServiceWithVaultKey(path, []byte(strings.Repeat("e", 32)))
	if err != nil {
		t.Fatal(err)
	}
	const password = "an-initial-admin-password-123"
	if _, err := service.Bootstrap("admin.user", password); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_010, 0).UTC()
	service.now = func() time.Time { return now }
	if _, err := service.SetMFAEnforcement(MFAEnforcementAdmins); err != nil {
		t.Fatal(err)
	}
	_, challenge, err := service.AuthenticateWithOTPOrMFASetup("admin.user", password, "")
	if err != nil || challenge == nil {
		t.Fatalf("create MFA challenge = %+v, %v", challenge, err)
	}
	now = now.Add(totpEnrollmentTTL)
	if _, err := service.ConfirmMFASetupChallenge(challenge.Token, testTOTPCode(t, challenge.Enrollment.Secret, uint64(now.Unix()/30))); !errors.Is(err, ErrMFAEnrollmentExpired) {
		t.Fatalf("confirm expired setup challenge = %v, want ErrMFAEnrollmentExpired", err)
	}
	_, renewed, err := service.AuthenticateWithOTPOrMFASetup("admin.user", password, "")
	if err != nil || renewed == nil || renewed.Token == challenge.Token {
		t.Fatalf("renew expired MFA challenge = %+v, %v", renewed, err)
	}
}
