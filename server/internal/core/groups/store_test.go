package groups

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func TestStorePersistsMembershipAndResolvesGroupIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user-groups.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	team, err := store.Create("Platform", "Production access")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(" platform ", "duplicate case-insensitive name"); !errors.Is(err, ErrGroupExists) {
		t.Fatalf("duplicate group error = %v, want ErrGroupExists", err)
	}
	if _, err := store.AddMember(team.ID, "user-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMember(team.ID, "user-a"); err != nil {
		t.Fatal(err)
	}
	if got := store.GroupIDsForUser("user-a"); !reflect.DeepEqual(got, []string{team.ID}) {
		t.Fatalf("group IDs = %v, want %v", got, []string{team.ID})
	}
	if _, err := store.RemoveMember(team.ID, "user-a"); err != nil {
		t.Fatal(err)
	}
	reloaded, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reloaded.Get(team.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.UserIDs, []string{"user-b"}) {
		t.Fatalf("reloaded members = %v, want [user-b]", got.UserIDs)
	}
}

func TestStoreRejectsInvalidGroupsAndMakesMembershipIdempotent(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "user-groups.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(" ", ""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("empty name error = %v, want ErrInvalidInput", err)
	}
	team, err := store.Create("Platform", "")
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.AddMember(team.ID, "user-a")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.AddMember(team.ID, "user-a")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.UserIDs, second.UserIDs) || len(second.UserIDs) != 1 {
		t.Fatalf("idempotent membership = %v then %v", first.UserIDs, second.UserIDs)
	}
	if _, err := store.AddMember("missing", "user-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing group error = %v, want ErrNotFound", err)
	}
}
