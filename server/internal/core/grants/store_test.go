package grants

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

func TestGrantPersistenceActionsAndTimeWindow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)
	grant, err := store.Create(Input{
		UserID: "user-operator", AssetID: "asset-01", Account: "deploy",
		Actions: []string{"connect", "connect"}, StartsAt: &start, EndsAt: &end,
	}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := grant.Actions, []string{"connect", "view"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("grant actions = %v, want %v", got, want)
	}
	before := start.Add(-time.Nanosecond)
	inside := start.Add(time.Hour)
	if store.Allows("user-operator", "asset-01", "deploy", "connect", before) {
		t.Fatal("grant was active before its start time")
	}
	if !store.Allows("user-operator", "asset-01", "deploy", "connect", inside) || !store.Allows("user-operator", "asset-01", "deploy", "view", inside) {
		t.Fatal("active connect grant did not allow connect and view")
	}
	if store.Allows("user-operator", "asset-01", "root", "connect", inside) {
		t.Fatal("grant matched a different SSH account")
	}
	if store.Allows("another-user", "asset-01", "deploy", "connect", inside) {
		t.Fatal("grant matched a different user")
	}
	if store.Allows("user-operator", "asset-01", "deploy", "connect", end) {
		t.Fatal("grant remained active at its exclusive end time")
	}

	reloaded, err := OpenStore(path)
	if err != nil {
		t.Fatalf("reload grant store: %v", err)
	}
	if got := reloaded.List(); len(got) != 1 || got[0].ID != grant.ID {
		t.Fatalf("reloaded grants = %#v", got)
	}
	if err := reloaded.Delete(grant.ID); err != nil {
		t.Fatalf("delete grant: %v", err)
	}
	if reloaded.Allows("user-operator", "asset-01", "deploy", "connect", inside) {
		t.Fatal("deleted grant remained active")
	}
	if err := reloaded.Delete(grant.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete error = %v, want ErrNotFound", err)
	}
}

func TestGrantRejectsUnsupportedActionsAndInvalidWindow(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "grants.json"))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	end := start
	for _, input := range []Input{
		{UserID: "user-one", AssetID: "asset-one", Account: "root"},
		{UserID: "user-one", AssetID: "asset-one", Account: "root", Actions: []string{"admin"}},
		{UserID: "user-one", AssetID: "asset-one", Account: "root", Actions: []string{"view"}, StartsAt: &start, EndsAt: &end},
		{AssetID: "asset-one", Account: "root", Actions: []string{"view"}},
		{UserID: "user-one", GroupID: "group-one", AssetID: "asset-one", Account: "root", Actions: []string{"view"}},
		{UserID: "user-one", AssetID: "asset-one", NodeID: "node-one", Account: "root", Actions: []string{"view"}},
		{UserID: "user-one", Account: "root", Actions: []string{"view"}},
	} {
		if _, err := store.Create(input, "admin"); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("Create(%+v) error = %v, want ErrInvalidInput", input, err)
		}
	}
}

func TestNodeGrantAppliesToAssetsInItsSubtree(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "grants.json"))
	if err != nil {
		t.Fatal(err)
	}
	grant, err := store.Create(Input{
		GroupID: "group-platform", NodeID: "node-root", Account: "deploy", Actions: []string{"connect", "sftp"},
	}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ancestors := []string{"node-root", "node-region", "node-hosts"}
	if got, want := store.ActionsForScopes("user-one", []string{"group-platform"}, "asset-one", ancestors, "deploy", now), []string{"connect", "sftp", "view"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("inherited node grant actions = %v, want %v", got, want)
	}
	if store.AllowsForScopes("user-one", []string{"group-platform"}, "asset-two", []string{"node-other"}, "deploy", "connect", now) {
		t.Fatal("node grant applied outside its subtree")
	}
	if store.AllowsForScopes("user-one", []string{"group-platform"}, "asset-one", ancestors, "root", "connect", now) {
		t.Fatal("node grant matched a different SSH account")
	}
	if !store.ReferencesNode("node-root") || store.ReferencesNode("node-region") {
		t.Fatal("node reference check returned an unexpected result")
	}
	if err := store.Delete(grant.ID); err != nil {
		t.Fatal(err)
	}
	if store.ReferencesNode("node-root") {
		t.Fatal("deleted node grant still blocks deleting its node")
	}
}

func TestGroupGrantAppliesToCurrentMembersOnly(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "grants.json"))
	if err != nil {
		t.Fatal(err)
	}
	grant, err := store.Create(Input{
		GroupID: "group-platform", AssetID: "asset-one", Account: "deploy", Actions: []string{"connect"},
	}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !store.AllowsFor("user-one", []string{"group-platform"}, "asset-one", "deploy", "connect", time.Now().UTC()) {
		t.Fatal("group member did not receive the group's connect grant")
	}
	if store.AllowsFor("user-one", nil, "asset-one", "deploy", "connect", time.Now().UTC()) {
		t.Fatal("user without group membership received the group's grant")
	}
	if !store.ReferencesGroup("group-platform") || store.ReferencesGroup("group-other") {
		t.Fatal("group reference check returned an unexpected result")
	}
	if got := store.ActionsFor("user-one", []string{"group-platform"}, "asset-one", "deploy", time.Now().UTC()); !reflect.DeepEqual(got, []string{"connect", "view"}) {
		t.Fatalf("group grant actions = %v, want [connect view]", got)
	}
	if err := store.Delete(grant.ID); err != nil {
		t.Fatal(err)
	}
	if store.ReferencesGroup("group-platform") {
		t.Fatal("deleted group grant still blocks deleting its group")
	}
}

func TestSharedGrantDocumentReloadsAuthorization(t *testing.T) {
	databaseURL := os.Getenv("JMS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set JMS_TEST_DATABASE_URL to run the PostgreSQL grant-store integration test")
	}
	namespace := fmt.Sprintf("grants-test-%d", time.Now().UTC().UnixNano())
	documents, err := storage.OpenPostgres(context.Background(), databaseURL, namespace)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = documents.Delete("grants")
		_ = documents.Close()
	})
	path := filepath.Join(t.TempDir(), "grants.json")
	firstNode, err := OpenStoreWithDocuments(path, documents)
	if err != nil {
		t.Fatal(err)
	}
	created, err := firstNode.Create(Input{
		UserID: "user-operator", AssetID: "asset-db", Account: "deploy", Actions: []string{"connect"},
	}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	secondNode, err := OpenStoreWithDocuments(path, documents)
	if err != nil {
		t.Fatalf("reload shared grant document: %v", err)
	}
	if !secondNode.Allows("user-operator", "asset-db", "deploy", "connect", time.Now().UTC()) {
		t.Fatalf("shared grant %s was not available on the second node", created.ID)
	}
}
