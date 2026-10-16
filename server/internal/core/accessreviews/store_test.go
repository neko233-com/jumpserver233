package accessreviews

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRequestApprovalPermitIsBoundToUserAssetAndAccount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access-reviews.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Request("user-1", "alice", "asset-1", "prod-1", "ops")
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := store.Request("user-1", "alice", "asset-1", "prod-1", "ops")
	if err != nil || duplicate.ID != first.ID {
		t.Fatalf("duplicate request = %#v, %v; want original %q", duplicate, err, first.ID)
	}
	if err := store.Resolve(first.ID, "admin", true); err != nil {
		t.Fatal(err)
	}
	if allowed, err := store.ConsumeApproved("user-2", "asset-1", "ops"); err != nil || allowed {
		t.Fatalf("other user consumed permit = %t, %v", allowed, err)
	}
	if allowed, err := store.ConsumeApproved("user-1", "asset-2", "ops"); err != nil || allowed {
		t.Fatalf("other asset consumed permit = %t, %v", allowed, err)
	}
	if allowed, err := store.ConsumeApproved("user-1", "asset-1", "root"); err != nil || allowed {
		t.Fatalf("other account consumed permit = %t, %v", allowed, err)
	}
	if allowed, err := store.ConsumeApproved("user-1", "asset-1", "ops"); err != nil || !allowed {
		t.Fatalf("approved user could not consume permit = %t, %v", allowed, err)
	}
	if allowed, err := store.ConsumeApproved("user-1", "asset-1", "ops"); err != nil || allowed {
		t.Fatalf("permit was reusable = %t, %v", allowed, err)
	}
	if got, err := store.Get(first.ID); err != nil || got.State != StateConsumed || got.ReviewedBy != "admin" {
		t.Fatalf("consumed review = %#v, %v", got, err)
	}
	data, err := json.Marshal(first)
	if err != nil || len(data) == 0 {
		t.Fatalf("marshal safe review record: %s, %v", data, err)
	}
	if got := string(data); containsAny(got, "permit_expires_at", "ticket", "credential", "password") {
		t.Fatalf("public review response exposes private fields: %s", got)
	}
}

func TestApprovalPermitsAreSeparatedByAccessAction(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "access-reviews.json"))
	if err != nil {
		t.Fatal(err)
	}
	sshReview, err := store.Request("user-1", "alice", "asset-1", "prod-1", "ops")
	if err != nil {
		t.Fatal(err)
	}
	sftpReview, err := store.RequestAction("user-1", "alice", "asset-1", "prod-1", "ops", ActionSFTP)
	if err != nil {
		t.Fatal(err)
	}
	if sshReview.ID == sftpReview.ID || sshReview.Action != ActionSSH || sftpReview.Action != ActionSFTP {
		t.Fatalf("access-method reviews were not distinct: SSH=%#v SFTP=%#v", sshReview, sftpReview)
	}
	if err := store.Resolve(sshReview.ID, "admin", true); err != nil {
		t.Fatal(err)
	}
	if allowed, err := store.ConsumeApprovedAction("user-1", "asset-1", "ops", ActionSFTP); err != nil || allowed {
		t.Fatalf("SSH approval authorized SFTP = %t, %v", allowed, err)
	}
	if allowed, err := store.ConsumeApprovedAction("user-1", "asset-1", "ops", ActionSSH); err != nil || !allowed {
		t.Fatalf("SSH approval could not authorize SSH = %t, %v", allowed, err)
	}
	if _, err := store.RequestAction("user-1", "alice", "asset-1", "prod-1", "ops", "unknown"); err == nil {
		t.Fatal("unsupported access action was accepted")
	}
}

func TestLegacyReviewWithoutActionLoadsAsSSH(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access-reviews.json")
	now := time.Now().UTC()
	legacy := []record{{Review: Review{
		ID: "legacy-review", UserID: "user-1", Operator: "alice", AssetID: "asset-1",
		AssetName: "prod-1", Account: "ops", State: StatePending,
		RequestedAt: now, ExpiresAt: now.Add(time.Minute),
	}}}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Get("legacy-review")
	if err != nil || got.Action != ActionSSH {
		t.Fatalf("legacy review = %#v, %v; want action %q", got, err, ActionSSH)
	}
}

func TestDeniedAndExpiredReviewsCannotBeResolvedTwice(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "access-reviews.json"))
	if err != nil {
		t.Fatal(err)
	}
	denied, err := store.Request("user-1", "alice", "asset-1", "prod-1", "ops")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Resolve(denied.ID, "admin", false); err != nil {
		t.Fatal(err)
	}
	if err := store.Resolve(denied.ID, "admin", true); err != ErrNotPending {
		t.Fatalf("resolve denied request again = %v, want ErrNotPending", err)
	}

	expired, err := store.Request("user-2", "bob", "asset-2", "prod-2", "ops")
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	item := store.records[expired.ID]
	old := time.Now().UTC().Add(-time.Minute)
	item.ExpiresAt = old
	store.records[expired.ID] = item
	if err := store.persistLocked(store.records); err != nil {
		t.Fatal(err)
	}
	store.mu.Unlock()
	if _, err := store.ListPending(); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(expired.ID)
	if err != nil || got.State != StateExpired {
		t.Fatalf("expired review = %#v, %v", got, err)
	}
	if err := store.Resolve(expired.ID, "admin", true); err != ErrNotPending {
		t.Fatalf("resolve expired request = %v, want ErrNotPending", err)
	}
}

func TestReviewStorePersistsRequestAndDecision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access-reviews.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Request("user-1", "alice", "asset-1", "prod-1", "ops")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Resolve(created.ID, "admin", true); err != nil {
		t.Fatal(err)
	}
	reloaded, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reloaded.Get(created.ID)
	if err != nil || got.State != StateApproved || got.ReviewedBy != "admin" {
		t.Fatalf("persisted review = %#v, %v", got, err)
	}
	if allowed, err := reloaded.ConsumeApproved("user-1", "asset-1", "ops"); err != nil || !allowed {
		t.Fatalf("persisted permit consumed = %t, %v", allowed, err)
	}
}

func containsAny(value string, fragments ...string) bool {
	for _, fragment := range fragments {
		if len(fragment) > 0 && contains(value, fragment) {
			return true
		}
	}
	return false
}

func contains(value, fragment string) bool {
	for i := 0; i+len(fragment) <= len(value); i++ {
		if value[i:i+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
