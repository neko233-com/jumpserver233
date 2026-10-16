package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAccessKeySecretIsEncryptedAndSurvivesReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	key := []byte(strings.Repeat("v", 32))
	service, err := OpenServiceWithVaultKey(path, key)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := service.Bootstrap("admin.user", "an-initial-admin-password-123")
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := service.CreateAccessKey(admin.ID)
	if err != nil {
		t.Fatalf("create AccessKey: %v", err)
	}
	if !validAccessKeyID(credentials.ID) || credentials.Secret == "" {
		t.Fatalf("created credentials = %+v", credentials)
	}

	stringToSign := "(request-target): get /api/v1/users/me?include=profile\naccept: application/json\ndate: Thu, 15 Oct 2026 06:00:00 GMT"
	signature := signAccessKeyTestSignature(credentials.Secret, stringToSign)
	if user, ok := service.VerifyAccessKeySignature(credentials.ID, stringToSign, signature); !ok || user.ID != admin.ID {
		t.Fatalf("verify generated signature = (%+v, %v), want admin", user, ok)
	}
	if _, ok := service.VerifyAccessKeySignature(credentials.ID, stringToSign+" ", signature); ok {
		t.Fatal("signature verified against a different request")
	}

	listed, err := service.ListAccessKeys(admin.ID)
	if err != nil || len(listed) != 1 || listed[0].ID != credentials.ID {
		t.Fatalf("listed AccessKeys = %+v, %v", listed, err)
	}
	metadata, err := json.Marshal(listed)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(metadata), credentials.Secret) {
		t.Fatal("AccessKey metadata exposed its secret")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), credentials.Secret) {
		t.Fatal("user store contains an AccessKey secret in plaintext")
	}

	reloaded, err := OpenServiceWithVaultKey(path, key)
	if err != nil {
		t.Fatalf("reload AccessKey store: %v", err)
	}
	if user, ok := reloaded.VerifyAccessKeySignature(credentials.ID, stringToSign, signature); !ok || user.ID != admin.ID {
		t.Fatalf("verify signature after reload = (%+v, %v), want admin", user, ok)
	}
	if err := reloaded.DeleteAccessKey(admin.ID, credentials.ID); err != nil {
		t.Fatalf("delete AccessKey: %v", err)
	}
	if _, ok := reloaded.VerifyAccessKeySignature(credentials.ID, stringToSign, signature); ok {
		t.Fatal("revoked AccessKey still verifies")
	}
	if err := reloaded.DeleteAccessKey(admin.ID, credentials.ID); !errors.Is(err, ErrAccessKeyNotFound) {
		t.Fatalf("delete missing AccessKey error = %v, want ErrAccessKeyNotFound", err)
	}
}

func TestAccessKeyRequiresVaultKeyAndEnforcesPerUserLimit(t *testing.T) {
	service, err := OpenService(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	admin, err := service.Bootstrap("admin.user", "an-initial-admin-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateAccessKey(admin.ID); !errors.Is(err, ErrAccessKeyUnavailable) {
		t.Fatalf("create without vault key error = %v, want ErrAccessKeyUnavailable", err)
	}

	withVault, err := OpenServiceWithVaultKey(filepath.Join(t.TempDir(), "users.json"), []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	admin, err = withVault.Bootstrap("admin.user", "an-initial-admin-password-123")
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < maxAccessKeys; index++ {
		if _, err := withVault.CreateAccessKey(admin.ID); err != nil {
			t.Fatalf("create key %d: %v", index+1, err)
		}
	}
	if _, err := withVault.CreateAccessKey(admin.ID); !errors.Is(err, ErrAccessKeyLimit) {
		t.Fatalf("eleventh AccessKey error = %v, want ErrAccessKeyLimit", err)
	}
}

func signAccessKeyTestSignature(secret, stringToSign string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
