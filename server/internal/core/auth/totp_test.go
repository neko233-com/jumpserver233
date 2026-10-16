package auth

import (
	"encoding/base32"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTOTPMatchesRFC6238SHA1Vector(t *testing.T) {
	key := []byte("12345678901234567890")
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)
	code := totpAtStep(key, 1)
	if code != "287082" {
		t.Fatalf("TOTP at RFC test time = %q, want 287082", code)
	}
	step, ok := matchTOTP([]byte(secret), code, time.Unix(59, 0))
	if !ok || step != 1 {
		t.Fatalf("matchTOTP() = (%d, %v), want (1, true)", step, ok)
	}
	if _, ok := matchTOTP([]byte(secret), "28708x", time.Unix(59, 0)); ok {
		t.Fatal("TOTP accepted a non-numeric code")
	}
	if _, ok := matchTOTP([]byte(secret), code, time.Unix(120, 0)); ok {
		t.Fatal("TOTP accepted a code outside its time window")
	}
}

func TestMFAEnrollmentEncryptedLoginReplayProtectionAndDisable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	key := []byte(strings.Repeat("k", 32))
	service, err := OpenServiceWithVaultKey(path, key)
	if err != nil {
		t.Fatal(err)
	}
	const password = "an-initial-admin-password-123"
	admin, err := service.Bootstrap("admin.user", password)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_010, 0).UTC()
	service.now = func() time.Time { return now }

	enrollment, err := service.StartMFAEnrollment(admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := service.StartMFAEnrollment(admin.ID)
	if err != nil || resumed.Secret != enrollment.Secret || !resumed.ExpiresAt.Equal(enrollment.ExpiresAt) {
		t.Fatalf("resumed enrollment = %+v, %v; want the same pending secret", resumed, err)
	}
	if !strings.Contains(enrollment.ProvisioningURI, "otpauth://totp/") || !strings.Contains(enrollment.ProvisioningURI, "secret="+enrollment.Secret) {
		t.Fatalf("invalid provisioning URI %q", enrollment.ProvisioningURI)
	}
	if _, err := service.ConfirmMFAEnrollment(admin.ID, "bad-code"); !errors.Is(err, ErrInvalidOTP) {
		t.Fatalf("invalid enrollment confirmation = %v, want ErrInvalidOTP", err)
	}

	step := now.Unix() / int64(totpPeriod/time.Second)
	code := testTOTPCode(t, enrollment.Secret, uint64(step))
	enabled, err := service.ConfirmMFAEnrollment(admin.ID, code)
	if err != nil || !enabled.MFAEnabled {
		t.Fatalf("confirm enrollment = %+v, %v", enabled, err)
	}
	if _, err := service.ConfirmMFAEnrollment(admin.ID, code); !errors.Is(err, ErrMFAAlreadyEnabled) {
		t.Fatalf("second confirmation = %v, want ErrMFAAlreadyEnabled", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), enrollment.Secret) {
		t.Fatal("user store contains the plaintext TOTP secret")
	}
	if _, err := OpenServiceWithVaultKey(path, []byte(strings.Repeat("x", 32))); !errors.Is(err, ErrUserStoreCorrupt) {
		t.Fatalf("reload with wrong vault key = %v, want ErrUserStoreCorrupt", err)
	}

	reloaded, err := OpenServiceWithVaultKey(path, key)
	if err != nil {
		t.Fatalf("reload MFA user store: %v", err)
	}
	reloaded.now = func() time.Time { return now }
	if _, err := reloaded.AuthenticateWithOTP("admin.user", password, ""); !errors.Is(err, ErrOTPRequired) {
		t.Fatalf("login without OTP = %v, want ErrOTPRequired", err)
	}
	if _, err := reloaded.AuthenticateWithOTP("admin.user", password, "not-code"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("login with wrong OTP = %v, want ErrInvalidCredentials", err)
	}
	if _, err := reloaded.AuthenticateWithOTP("admin.user", password, code); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("replayed enrollment OTP = %v, want ErrInvalidCredentials", err)
	}

	now = now.Add(totpPeriod)
	reloaded.now = func() time.Time { return now }
	nextCode := testTOTPCode(t, enrollment.Secret, uint64(now.Unix()/int64(totpPeriod/time.Second)))
	login, err := reloaded.AuthenticateWithOTP("admin.user", password, nextCode)
	if err != nil || login.AccessToken == "" || !login.User.MFAEnabled {
		t.Fatalf("login with fresh OTP = %+v, %v", login, err)
	}
	if user, ok := reloaded.ValidateToken(login.AccessToken); !ok || !user.MFAEnabled {
		t.Fatalf("validated login user = %+v, %v; want current MFA status", user, ok)
	}

	if _, err := reloaded.DisableMFA(admin.ID, "wrong-password", nextCode); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("disable with wrong password = %v, want ErrInvalidCredentials", err)
	}
	now = now.Add(totpPeriod)
	reloaded.now = func() time.Time { return now }
	disableCode := testTOTPCode(t, enrollment.Secret, uint64(now.Unix()/int64(totpPeriod/time.Second)))
	disabled, err := reloaded.DisableMFA(admin.ID, password, disableCode)
	if err != nil || disabled.MFAEnabled {
		t.Fatalf("disable MFA = %+v, %v", disabled, err)
	}
	if _, err := reloaded.Authenticate("admin.user", password); err != nil {
		t.Fatalf("password-only login after MFA disable = %v", err)
	}
}

func TestMFAEnrollmentRequiresVaultKeyAndExpires(t *testing.T) {
	withoutKey, err := OpenService(filepath.Join(t.TempDir(), "plain-users.json"))
	if err != nil {
		t.Fatal(err)
	}
	admin, err := withoutKey.Bootstrap("admin.user", "an-initial-admin-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withoutKey.StartMFAEnrollment(admin.ID); !errors.Is(err, ErrMFAKeyUnavailable) {
		t.Fatalf("enroll without vault key = %v, want ErrMFAKeyUnavailable", err)
	}

	key := []byte(strings.Repeat("v", 32))
	service, err := OpenServiceWithVaultKey(filepath.Join(t.TempDir(), "users.json"), key)
	if err != nil {
		t.Fatal(err)
	}
	admin, err = service.Bootstrap("admin.user", "an-initial-admin-password-123")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_010, 0).UTC()
	service.now = func() time.Time { return now }
	if _, err := service.StartMFAEnrollment(admin.ID); err != nil {
		t.Fatal(err)
	}
	now = now.Add(totpEnrollmentTTL)
	if _, err := service.ConfirmMFAEnrollment(admin.ID, "000000"); !errors.Is(err, ErrMFAEnrollmentExpired) {
		t.Fatalf("confirm expired enrollment = %v, want ErrMFAEnrollmentExpired", err)
	}
}

func TestMFARecoveryCodesPersistAndAreSingleUse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	key := []byte(strings.Repeat("r", 32))
	service, err := OpenServiceWithVaultKey(path, key)
	if err != nil {
		t.Fatal(err)
	}
	const password = "an-initial-admin-password-123"
	admin, err := service.Bootstrap("admin.user", password)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_010, 0).UTC()
	service.now = func() time.Time { return now }
	enrollment, err := service.StartMFAEnrollment(admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	firstStep := uint64(now.Unix() / int64(totpPeriod/time.Second))
	if _, err := service.ConfirmMFAEnrollment(admin.ID, testTOTPCode(t, enrollment.Secret, firstStep)); err != nil {
		t.Fatal(err)
	}

	now = now.Add(totpPeriod)
	secondStep := uint64(now.Unix() / int64(totpPeriod/time.Second))
	generated, err := service.RegenerateMFARecoveryCodes(admin.ID, password, testTOTPCode(t, enrollment.Secret, secondStep))
	if err != nil {
		t.Fatalf("generate recovery codes: %v", err)
	}
	if len(generated.Codes) != mfaRecoveryCodeCount || generated.GeneratedAt.IsZero() {
		t.Fatalf("recovery-code response has %d codes and timestamp %v", len(generated.Codes), generated.GeneratedAt)
	}
	for _, code := range generated.Codes {
		if len(code) != 30 || strings.Count(code, "-") != 4 {
			t.Fatalf("recovery code has unexpected format")
		}
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range generated.Codes {
		if strings.Contains(string(contents), code) || strings.Contains(string(contents), strings.ReplaceAll(code, "-", "")) {
			t.Fatal("user store contains plaintext MFA recovery code")
		}
	}

	reloaded, err := OpenServiceWithVaultKey(path, key)
	if err != nil {
		t.Fatalf("reload recovery-code store: %v", err)
	}
	reloaded.now = func() time.Time { return now }
	login, err := reloaded.AuthenticateWithOTP(admin.Username, password, generated.Codes[0])
	if err != nil || login.AccessToken == "" {
		t.Fatalf("login with recovery code failed: %v", err)
	}
	if _, err := reloaded.AuthenticateWithOTP(admin.Username, password, generated.Codes[0]); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("reuse of recovery code = %v, want ErrInvalidCredentials", err)
	}

	rotated, err := reloaded.RegenerateMFARecoveryCodes(admin.ID, password, generated.Codes[1])
	if err != nil || len(rotated.Codes) != mfaRecoveryCodeCount {
		t.Fatalf("regenerate with unused recovery code: %v", err)
	}
	if _, err := reloaded.AuthenticateWithOTP(admin.Username, password, generated.Codes[2]); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("old code remained valid after regeneration: %v", err)
	}
	if _, err := reloaded.AuthenticateWithOTP(admin.Username, password, rotated.Codes[0]); err != nil {
		t.Fatalf("new recovery code did not work: %v", err)
	}

	now = now.Add(totpPeriod)
	reloaded.now = func() time.Time { return now }
	thirdStep := uint64(now.Unix() / int64(totpPeriod/time.Second))
	if _, err := reloaded.DisableMFA(admin.ID, password, testTOTPCode(t, enrollment.Secret, thirdStep)); err != nil {
		t.Fatalf("disable MFA: %v", err)
	}
	reloaded.mu.RLock()
	_, record, ok := reloaded.storedUserByIDLocked(admin.ID)
	reloaded.mu.RUnlock()
	if !ok || len(record.MFARecoveryCodeHashes) != 0 {
		t.Fatalf("recovery codes remain after MFA disable: %+v", record.MFARecoveryCodeHashes)
	}
}

func testTOTPCode(t *testing.T, secret string, step uint64) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return totpAtStep(key, step)
}
