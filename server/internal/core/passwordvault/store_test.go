package passwordvault

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEncryptedOwnerScopedSingleUseGrant(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	key := bytes.Repeat([]byte{1}, 32)
	s, err := Open(path, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	item, err := s.Put("alice", Item{Kind: "game", Title: "Game", Username: "alice"}, "synthetic-password")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.List("bob")) != 0 {
		t.Fatal("cross-owner listing")
	}
	if _, _, err = s.Grant("bob", item.ID, "0123456789abcdef0123456789abcdef", time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-owner grant: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("synthetic-password")) || bytes.Contains(data, []byte("alice")) {
		t.Fatal("plaintext in encrypted store")
	}
	view, _ := json.Marshal(item)
	if bytes.Contains(view, []byte("synthetic-password")) {
		t.Fatal("password in item metadata")
	}
	gid, token, err := s.Grant("alice", item.ID, "0123456789abcdef0123456789abcdef", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	retryID, retryToken, err := s.Grant("alice", item.ID, "0123456789abcdef0123456789abcdef", time.Minute)
	if err != nil || retryID != gid || retryToken != token {
		t.Fatalf("grant retry: %v", err)
	}
	data, err = os.ReadFile(path)
	if err != nil || bytes.Contains(data, []byte(token)) {
		t.Fatal("grant token was not encrypted at rest")
	}
	s, err = Open(path, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Consume("alice", gid, token); !errors.Is(err, ErrDenied) {
		t.Fatalf("restart revived grant: %v", err)
	}
	if _, _, err = s.Grant("alice", item.ID, "0123456789abcdef0123456789abcdef", time.Minute); !errors.Is(err, ErrDenied) {
		t.Fatalf("restart replay: %v", err)
	}
	gid, token, err = s.Grant("alice", item.ID, "1123456789abcdef0123456789abcdef", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, secret, e := s.Consume("alice", gid, token)
			if e == nil && secret == "synthetic-password" {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful consumes: %d", successes.Load())
	}
	if _, _, err = s.Consume("alice", gid, token); !errors.Is(err, ErrDenied) {
		t.Fatalf("replay: %v", err)
	}
	if _, _, err = s.Grant("alice", item.ID, "1123456789abcdef0123456789abcdef", time.Minute); !errors.Is(err, ErrDenied) {
		t.Fatalf("grant replay: %v", err)
	}
	if _, err = Open(path, bytes.Repeat([]byte{2}, 32), nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong key: %v", err)
	}
}

func TestGrantRevocationAndRevision(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "vault.json"), bytes.Repeat([]byte{3}, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	item, err := s.Put("alice", Item{Kind: "website", Title: "Site"}, "one")
	if err != nil {
		t.Fatal(err)
	}
	id, token, err := s.Grant("alice", item.ID, "0123456789abcdef0123456789abcdef", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Put("alice", item, "two"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Put("alice", item, "stale"); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update: %v", err)
	}
	if _, _, err = s.Consume("alice", id, token); !errors.Is(err, ErrDenied) {
		t.Fatalf("old revision: %v", err)
	}
	id, token, err = s.Grant("alice", item.ID, "1123456789abcdef0123456789abcdef", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Revoke("alice", id); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Consume("alice", id, token); !errors.Is(err, ErrDenied) {
		t.Fatalf("revoked: %v", err)
	}
	if _, _, err = s.Grant("alice", item.ID, "1123456789abcdef0123456789abcdef", time.Minute); !errors.Is(err, ErrDenied) {
		t.Fatalf("revoked grant replay: %v", err)
	}
}

func TestCreateRetrySurvivesRestartAndRejectsDifferentPayload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	key := bytes.Repeat([]byte{4}, 32)
	s, err := Open(path, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	item := Item{Kind: "website", Title: "Site", Username: "person"}
	request := "0123456789abcdef0123456789abcdef"
	first, err := s.Create("alice", request, item, "synthetic-secret")
	if err != nil {
		t.Fatal(err)
	}
	s, err = Open(path, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := s.Create("alice", request, item, "synthetic-secret")
	if err != nil || retry.ID != first.ID || len(s.List("alice")) != 1 {
		t.Fatalf("retry: %v", err)
	}
	if _, err = s.Create("alice", request, item, "different"); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting retry: %v", err)
	}
}

func TestConsumeNeverDisclosesBeforeAuditIsSaved(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "vault.json")
	s, err := Open(path, bytes.Repeat([]byte{5}, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	item, err := s.Put("alice", Item{Kind: "game", Title: "Game"}, "synthetic-secret")
	if err != nil {
		t.Fatal(err)
	}
	id, token, err := s.Grant("alice", item.ID, "0123456789abcdef0123456789abcdef", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	block := filepath.Join(root, "not-a-directory")
	if err = os.WriteFile(block, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	s.path = filepath.Join(block, "vault.json")
	_, secret, err := s.Consume("alice", id, token)
	if err == nil || secret != "" {
		t.Fatal("secret disclosed when audit persistence failed")
	}
	s.path = path
	_, secret, err = s.Consume("alice", id, token)
	if err != nil || secret != "synthetic-secret" {
		t.Fatalf("retry after failed persistence: %v", err)
	}
}

func TestOrganizationSharedEntriesAndAgentAuthorization(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "vault.json"), bytes.Repeat([]byte{9}, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	item, err := s.Create("alice", "0123456789abcdef0123456789abcdef", Item{Kind: "website", Title: "Team login", Shared: true}, "synthetic-shared-secret")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.List("bob"); len(got) != 1 || got[0].ID != item.ID {
		t.Fatal("team member cannot list shared item")
	}
	_, secret, err := s.Reveal("bob", item.ID)
	if err != nil || secret != "synthetic-shared-secret" {
		t.Fatalf("team reveal: %v", err)
	}
	id, token, err := s.Grant("bob", item.ID, "1123456789abcdef0123456789abcdef", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Consume("alice", id, token); !errors.Is(err, ErrDenied) {
		t.Fatalf("grant issued to another identity: %v", err)
	}
	if _, secret, err = s.Consume("bob", id, token); err != nil || secret != "synthetic-shared-secret" {
		t.Fatalf("team agent: %v", err)
	}
	item, err = s.Put("bob", item, "synthetic-updated-secret")
	if err != nil {
		t.Fatalf("team update: %v", err)
	}
	item.Shared = false
	if _, err = s.Put("bob", item, "different"); !errors.Is(err, ErrDenied) {
		t.Fatalf("non-owner changed sharing: %v", err)
	}
	item, err = s.Put("alice", item, "private-secret")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.List("bob")) != 0 {
		t.Fatal("revoked sharing still visible")
	}
	if _, _, err = s.Reveal("bob", item.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked sharing reveal: %v", err)
	}
}
