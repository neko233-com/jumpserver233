package assets

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	xssh "golang.org/x/crypto/ssh"
)

func TestStoreEncryptsCredentialsAndReloadsAssets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assets.json")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	asset := Asset{ID: "asset-one", Name: "db-01", Host: "192.0.2.12", Username: "ops", Port: 22}
	if _, err := store.Create(asset, "secret-password"); err != nil {
		t.Fatal(err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), "secret-password") {
		t.Fatal("asset store contains a plaintext password")
	}
	if _, err := store.Password(asset.ID); err != nil {
		t.Fatalf("decrypt stored credential: %v", err)
	}

	reloaded, err := OpenStore(path, key)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	if got := reloaded.List(); len(got) != 1 || got[0].Name != asset.Name {
		t.Fatalf("reloaded assets = %+v", got)
	}
	wrongKey := make([]byte, 32)
	if _, err := rand.Read(wrongKey); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(path, wrongKey); err == nil {
		t.Fatal("OpenStore() accepted a different vault key")
	}

	encodedKey := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	createdKey, err := LoadOrCreateVaultKey(t.TempDir(), encodedKey)
	if err != nil || len(createdKey) != 32 {
		t.Fatalf("LoadOrCreateVaultKey() = %d bytes, %v", len(createdKey), err)
	}
}

func TestSharedAssetDocumentReloadsEncryptedCredential(t *testing.T) {
	databaseURL := os.Getenv("JMS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set JMS_TEST_DATABASE_URL to run the PostgreSQL asset-store integration test")
	}
	namespace := fmt.Sprintf("assets-test-%d", time.Now().UTC().UnixNano())
	documents, err := storage.OpenPostgres(context.Background(), databaseURL, namespace)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = documents.Delete("assets")
		_ = documents.Close()
	})
	key := []byte("0123456789abcdef0123456789abcdef")
	path := filepath.Join(t.TempDir(), "assets.json")
	firstNode, err := OpenStoreWithDocuments(path, key, documents)
	if err != nil {
		t.Fatal(err)
	}
	asset := Asset{ID: "asset-db", Name: "db-host", Host: "db.internal", Username: "ops", Port: 22}
	const password = "database-stored-secret"
	if _, err := firstNode.Create(asset, password); err != nil {
		t.Fatal(err)
	}
	stored, err := documents.Load("assets")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), password) {
		t.Fatal("shared asset document contains a plaintext credential")
	}
	secondNode, err := OpenStoreWithDocuments(path, key, documents)
	if err != nil {
		t.Fatalf("reload shared asset document: %v", err)
	}
	if got, err := secondNode.Password(asset.ID); err != nil || got != password {
		t.Fatalf("shared credential = %q, %v; want decrypted credential", got, err)
	}
}

func TestServiceKeepsSecretsOutOfInventoryAndCalculatesRates(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(filepath.Join(t.TempDir(), "assets.json"), key)
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := xssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := xssh.FingerprintSHA256(signer.PublicKey())
	call := 0
	probe := func(_ context.Context, target sshclient.Target, credentials sshclient.Credentials, _ time.Duration) (sshclient.Metrics, error) {
		if target.Host != "example.internal" || credentials.Password != "vault-only" {
			t.Fatalf("probe received unexpected input: target=%+v password=%q", target, credentials.Password)
		}
		call++
		return sshclient.Metrics{
			CPUCores:             4,
			CPUPercent:           20,
			MemoryTotalBytes:     1024,
			MemoryUsedBytes:      512,
			MemoryPercent:        50,
			NetworkReceivedBytes: int64(call * 100),
			NetworkSentBytes:     int64(call * 200),
			DiskTotalBytes:       2048,
			DiskUsedBytes:        1024,
			DiskPercent:          50,
		}, nil
	}
	service := NewService(store, probe)
	requireReview := true
	asset, err := service.Create(Input{
		Name:                "app-01",
		Host:                "example.internal",
		Group:               "Production",
		Username:            "ops",
		HostKeyFingerprint:  fingerprint,
		Password:            "vault-only",
		LoginReviewRequired: &requireReview,
	})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := service.Update(asset.ID, Input{
		Name: "app-01", Host: "example.internal", Group: "Production", Username: "ops",
		HostKeyFingerprint: fingerprint, Port: 22,
	})
	if err != nil || !updated.LoginReviewRequired {
		t.Fatalf("update without login-review field = %#v, %v; existing policy must be preserved", updated, err)
	}
	disableReview := false
	updated, err = service.Update(asset.ID, Input{
		Name: "app-01", Host: "example.internal", Group: "Production", Username: "ops",
		HostKeyFingerprint: fingerprint, Port: 22, LoginReviewRequired: &disableReview,
	})
	if err != nil || updated.LoginReviewRequired {
		t.Fatalf("explicitly disable login review = %#v, %v", updated, err)
	}
	encoded, err := json.Marshal(service.List())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "vault-only") {
		t.Fatal("inventory response contains a stored password")
	}
	if _, err := service.Probe(context.Background(), asset.ID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	item, err := service.Probe(context.Background(), asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	if item.Monitor.State != "online" || item.Monitor.Metrics == nil {
		t.Fatalf("monitor state = %+v", item.Monitor)
	}
	if item.Monitor.NetworkReceivedBytesPerSecond <= 0 || item.Monitor.NetworkSentBytesPerSecond <= 0 {
		t.Fatalf("network rates were not calculated: %+v", item.Monitor)
	}
}

func TestNormalizeInputRequiresValidFingerprintAndHost(t *testing.T) {
	for _, input := range []Input{
		{Name: "a", Host: "bad host", Username: "u", HostKeyFingerprint: "SHA256:abc"},
		{Name: "a", Host: "host.example", Username: "u", HostKeyFingerprint: ""},
	} {
		if _, err := normalizeInput(input, ""); err == nil {
			t.Fatalf("normalizeInput() accepted invalid input %+v", input)
		}
	}
}
