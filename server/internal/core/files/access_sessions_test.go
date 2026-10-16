package files

import (
	"testing"
	"time"
)

func TestAccessSessionIsBoundToOperatorAssetAndAccount(t *testing.T) {
	store := NewAccessSessionStore()
	token, _, err := store.Issue("user-1", "asset-1", "deploy")
	if err != nil {
		t.Fatal(err)
	}
	if !store.Authorize(token, "user-1", "asset-1", "deploy") {
		t.Fatal("issued SFTP session was rejected")
	}
	for _, mismatch := range []struct{ user, asset, account string }{
		{"user-2", "asset-1", "deploy"},
		{"user-1", "asset-2", "deploy"},
		{"user-1", "asset-1", "root"},
	} {
		if store.Authorize(token, mismatch.user, mismatch.asset, mismatch.account) {
			t.Fatalf("session authorized mismatched tuple %#v", mismatch)
		}
	}
	if store.Authorize("not-a-token", "user-1", "asset-1", "deploy") {
		t.Fatal("malformed token was authorized")
	}
}

func TestAccessSessionExpiresAndCanOnlyBeRevokedByOwner(t *testing.T) {
	store := NewAccessSessionStore()
	now := time.Now().UTC()
	store.now = func() time.Time { return now }
	token, expiry, err := store.Issue("user-1", "asset-1", "deploy")
	if err != nil {
		t.Fatal(err)
	}
	if !expiry.Equal(now.Add(SFTPAccessSessionLifetime)) {
		t.Fatalf("expiry = %s, want %s", expiry, now.Add(SFTPAccessSessionLifetime))
	}
	if store.Revoke(token, "user-2", "asset-1", "deploy") {
		t.Fatal("different user revoked the session")
	}
	if !store.Authorize(token, "user-1", "asset-1", "deploy") {
		t.Fatal("session became invalid before expiry")
	}
	if store.Revoke(token, "user-1", "asset-2", "deploy") {
		t.Fatal("session was revoked for the wrong asset")
	}
	if !store.Revoke(token, "user-1", "asset-1", "deploy") || store.Authorize(token, "user-1", "asset-1", "deploy") {
		t.Fatal("owner could not revoke the session")
	}

	second, _, err := store.Issue("user-1", "asset-1", "deploy")
	if err != nil {
		t.Fatal(err)
	}
	now = expiry
	if store.Authorize(second, "user-1", "asset-1", "deploy") {
		t.Fatal("expired session was authorized")
	}
}
