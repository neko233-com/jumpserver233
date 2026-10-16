package nodes

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func TestStorePersistsTreeAndReturnsAncestorPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asset-nodes.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	root, err := store.Create("Production", "")
	if err != nil {
		t.Fatal(err)
	}
	region, err := store.Create("Asia", root.ID)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := store.Create("Databases", region.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := store.AncestorIDs(leaf.ID), []string{root.ID, region.ID, leaf.ID}; !reflect.DeepEqual(got, want) {
		t.Fatalf("AncestorIDs() = %v, want %v", got, want)
	}
	reloaded, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := reloaded.AncestorIDs(leaf.ID), []string{root.ID, region.ID, leaf.ID}; !reflect.DeepEqual(got, want) {
		t.Fatalf("reloaded AncestorIDs() = %v, want %v", got, want)
	}
}

func TestStoreValidatesSiblingNamesParentsAndCycles(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "asset-nodes.json"))
	if err != nil {
		t.Fatal(err)
	}
	root, err := store.Create("Production", "")
	if err != nil {
		t.Fatal(err)
	}
	child, err := store.Create("Asia", root.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create("production", ""); !errors.Is(err, ErrNodeExists) {
		t.Fatalf("case-insensitive sibling duplicate error = %v", err)
	}
	if _, err := store.Create("Missing parent", "node-does-not-exist"); !errors.Is(err, ErrInvalidParent) {
		t.Fatalf("missing parent error = %v", err)
	}
	if _, err := store.Update(root.ID, root.Name, child.ID); !errors.Is(err, ErrInvalidParent) {
		t.Fatalf("cycle error = %v", err)
	}
	if err := store.Delete(root.ID); !errors.Is(err, ErrHasChildren) {
		t.Fatalf("delete parent error = %v", err)
	}
}

func TestStoreMoveUpdatesParentAndPreventsSiblingCollision(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "asset-nodes.json"))
	if err != nil {
		t.Fatal(err)
	}
	left, err := store.Create("Left", "")
	if err != nil {
		t.Fatal(err)
	}
	right, err := store.Create("Right", "")
	if err != nil {
		t.Fatal(err)
	}
	child, err := store.Create("Child", left.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create("Child", right.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(child.ID, "Child", right.ID); !errors.Is(err, ErrNodeExists) {
		t.Fatalf("move into duplicate sibling name error = %v", err)
	}
	moved, err := store.Update(child.ID, "Child", "")
	if err != nil {
		t.Fatal(err)
	}
	if moved.ParentID != "" {
		t.Fatalf("moved parent ID = %q, want root", moved.ParentID)
	}
}
