package storage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestDocumentsShareStateAndImportLegacyFiles(t *testing.T) {
	databaseURL := os.Getenv("JMS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set JMS_TEST_DATABASE_URL to run the PostgreSQL document-store integration test")
	}
	namespace := "storage-test-" + time.Now().UTC().Format("20060102150405.000000000")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	documents, err := OpenPostgres(ctx, databaseURL, namespace)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = documents.db.Exec(`DELETE FROM jms233_state_documents WHERE namespace = $1`, namespace)
		_ = documents.Close()
	})

	legacyPath := filepath.Join(t.TempDir(), "users.json")
	legacy := []byte(`[{"username":"admin"}]`)
	if err := os.WriteFile(legacyPath, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := documents.LoadOrImport("users", legacyPath)
	if err != nil {
		t.Fatalf("LoadOrImport() error = %v", err)
	}
	if !equalJSON(loaded, legacy) {
		t.Fatalf("imported document = %s, want %s", loaded, legacy)
	}

	updated := []byte(`[{"username":"operator"}]`)
	if err := documents.Save("users", updated); err != nil {
		t.Fatal(err)
	}
	secondNode, err := OpenPostgres(ctx, databaseURL, namespace)
	if err != nil {
		t.Fatal(err)
	}
	defer secondNode.Close()
	loaded, err = secondNode.Load("users")
	if err != nil {
		t.Fatalf("second node Load() error = %v", err)
	}
	if !equalJSON(loaded, updated) {
		t.Fatalf("second node document = %s, want %s", loaded, updated)
	}
	if _, err := secondNode.Load("missing"); !errors.Is(err, ErrDocumentNotFound) {
		t.Fatalf("missing document error = %v, want ErrDocumentNotFound", err)
	}
}

func equalJSON(left, right []byte) bool {
	var leftValue, rightValue any
	if json.Unmarshal(left, &leftValue) != nil || json.Unmarshal(right, &rightValue) != nil {
		return false
	}
	return reflect.DeepEqual(leftValue, rightValue)
}
