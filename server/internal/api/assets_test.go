package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
)

func TestAssetAPIPersistsEncryptedCredentialsWithoutReturningThem(t *testing.T) {
	service := testAssetService(t)
	router := NewRouter("test", Dependencies{Assets: service})
	input := coreassets.Input{
		Name:               "ops-01",
		Host:               "192.0.2.42",
		Group:              "Production",
		Username:           "operator",
		HostKeyFingerprint: validTestFingerprint(),
		Password:           "super-secret-password",
		Port:               22,
	}
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/assets", strings.NewReader(string(body)))
	request.RemoteAddr = "127.0.0.1:43210"
	request.Header.Set("Origin", "http://127.0.0.1:5173")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), input.Password) {
		t.Fatal("asset create response exposed the password")
	}
	if !strings.Contains(response.Body.String(), `"host":"192.0.2.42"`) {
		t.Fatalf("asset response missing host: %s", response.Body.String())
	}

	listRequest := httptest.NewRequest(http.MethodGet, "/api/v1/assets", nil)
	listRequest.RemoteAddr = "127.0.0.1:43210"
	listRequest.Header.Set("Origin", "http://127.0.0.1:5173")
	listResponse := httptest.NewRecorder()
	router.ServeHTTP(listResponse, listRequest)
	if listResponse.Code != http.StatusOK || strings.Contains(listResponse.Body.String(), input.Password) {
		t.Fatalf("asset list response status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}
}

func TestAssetAPIRequiresConfiguredTokenAndRejectsUnknownOrigins(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	router := NewRouter("test", Dependencies{Assets: testAssetService(t), AdminToken: token})

	unauthenticated := httptest.NewRequest(http.MethodGet, "/api/v1/assets", nil)
	unauthenticated.RemoteAddr = "127.0.0.1:43210"
	unauthenticatedResponse := httptest.NewRecorder()
	router.ServeHTTP(unauthenticatedResponse, unauthenticated)
	if unauthenticatedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want %d", unauthenticatedResponse.Code, http.StatusUnauthorized)
	}

	badOrigin := httptest.NewRequest(http.MethodGet, "/api/v1/assets", nil)
	badOrigin.RemoteAddr = "127.0.0.1:43210"
	badOrigin.Header.Set("Authorization", "Bearer "+token)
	badOrigin.Header.Set("Origin", "https://attacker.example")
	badOriginResponse := httptest.NewRecorder()
	router.ServeHTTP(badOriginResponse, badOrigin)
	if badOriginResponse.Code != http.StatusForbidden {
		t.Fatalf("unknown-origin status = %d, want %d", badOriginResponse.Code, http.StatusForbidden)
	}
}

func TestAssetPasswordRotationIsAdminOnlyAndNeverReturnsSecret(t *testing.T) {
	identities, err := coreauth.OpenService(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.Bootstrap("admin.user", bootstrapPassword); err != nil {
		t.Fatal(err)
	}
	adminSession, err := identities.Authenticate("admin.user", bootstrapPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.CreateUser("operator.one", "an-operator-password-1234", coreauth.RoleOperator); err != nil {
		t.Fatal(err)
	}
	operatorSession, err := identities.Authenticate("operator.one", "an-operator-password-1234")
	if err != nil {
		t.Fatal(err)
	}

	store, err := coreassets.OpenStore(filepath.Join(t.TempDir(), "assets.json"), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	remotePassword := "initial-password"
	service := coreassets.NewServiceWithPasswordRotation(store, nil,
		func(_ context.Context, _ sshclient.Target, current sshclient.Credentials, next string, _ time.Duration) error {
			if current.Password != remotePassword {
				return errors.New("unexpected current credential")
			}
			remotePassword = next
			return nil
		},
		func(_ context.Context, _ sshclient.Target, credentials sshclient.Credentials, _ time.Duration) error {
			if credentials.Password != remotePassword {
				return errors.New("authentication failed")
			}
			return nil
		},
	)
	asset, err := service.Create(coreassets.Input{
		Name: "rotation-test", Host: "192.0.2.44", Username: "deploy", Password: remotePassword,
		Port: 22, HostKeyFingerprint: validTestFingerprint(),
	})
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter("test", Dependencies{Assets: service, Auth: identities})
	path := "/api/v1/assets/" + asset.ID + "/password-rotation"

	forbidden := doJSONRequest(t, router, http.MethodPost, path, "", operatorSession.AccessToken, "127.0.0.1:43210")
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("operator rotation = %d %s, want 403", forbidden.Code, forbidden.Body.String())
	}
	if remotePassword != "initial-password" {
		t.Fatal("operator request changed the remote password")
	}

	rotated := doJSONRequest(t, router, http.MethodPost, path, "", adminSession.AccessToken, "127.0.0.1:43210")
	if rotated.Code != http.StatusOK {
		t.Fatalf("administrator rotation = %d %s, want 200", rotated.Code, rotated.Body.String())
	}
	if strings.Contains(rotated.Body.String(), remotePassword) || !strings.Contains(rotated.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("rotation response exposed or cached credential state: headers=%v body=%s", rotated.Header(), rotated.Body.String())
	}
	storedPassword, err := store.Password(asset.ID)
	if err != nil || storedPassword != remotePassword || storedPassword == "initial-password" {
		t.Fatalf("stored password did not match verified remote credential: %v", err)
	}
}

func TestCredentialBackupAPIIsAdminOnlyMetadataOnlyAndRestoresVerifiedCredential(t *testing.T) {
	identities, err := coreauth.OpenService(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.Bootstrap("admin.user", bootstrapPassword); err != nil {
		t.Fatal(err)
	}
	adminSession, err := identities.Authenticate("admin.user", bootstrapPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.CreateUser("operator.one", "an-operator-password-1234", coreauth.RoleOperator); err != nil {
		t.Fatal(err)
	}
	operatorSession, err := identities.Authenticate("operator.one", "an-operator-password-1234")
	if err != nil {
		t.Fatal(err)
	}

	store, err := coreassets.OpenStore(filepath.Join(t.TempDir(), "assets.json"), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	remotePassword := "saved-credential"
	service := coreassets.NewServiceWithPasswordRotation(store, nil,
		func(_ context.Context, _ sshclient.Target, current sshclient.Credentials, next string, _ time.Duration) error {
			if current.Password != remotePassword {
				return errors.New("unexpected current credential")
			}
			remotePassword = next
			return nil
		},
		func(_ context.Context, _ sshclient.Target, credentials sshclient.Credentials, _ time.Duration) error {
			if credentials.Password != remotePassword {
				return errors.New("authentication failed")
			}
			return nil
		},
	)
	asset, err := service.Create(coreassets.Input{
		Name: "backup-test", Host: "192.0.2.46", Username: "deploy", Password: remotePassword,
		Port: 22, HostKeyFingerprint: validTestFingerprint(),
	})
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter("test", Dependencies{Assets: service, Auth: identities})
	basePath := "/api/v1/assets/" + asset.ID + "/credential-backups"

	operatorList := doJSONRequest(t, router, http.MethodGet, basePath, "", operatorSession.AccessToken, "127.0.0.1:43210")
	if operatorList.Code != http.StatusForbidden {
		t.Fatalf("operator backup list = %d, want 403", operatorList.Code)
	}
	operatorCreate := doJSONRequest(t, router, http.MethodPost, basePath, "", operatorSession.AccessToken, "127.0.0.1:43210")
	if operatorCreate.Code != http.StatusForbidden {
		t.Fatalf("operator backup create = %d, want 403", operatorCreate.Code)
	}

	created := doJSONRequest(t, router, http.MethodPost, basePath, "", adminSession.AccessToken, "127.0.0.1:43210")
	if created.Code != http.StatusCreated || !strings.Contains(created.Header().Get("Cache-Control"), "no-store") || strings.Contains(created.Body.String(), "saved-credential") {
		t.Fatalf("backup creation = %d headers=%v body=%s", created.Code, created.Header(), created.Body.String())
	}
	var backup coreassets.CredentialBackup
	if err := json.Unmarshal(created.Body.Bytes(), &backup); err != nil || backup.ID == "" {
		t.Fatalf("backup metadata = %+v, %v", backup, err)
	}
	listed := doJSONRequest(t, router, http.MethodGet, basePath, "", adminSession.AccessToken, "127.0.0.1:43210")
	if listed.Code != http.StatusOK || !strings.Contains(listed.Header().Get("Cache-Control"), "no-store") || !strings.Contains(listed.Body.String(), backup.ID) || strings.Contains(listed.Body.String(), "saved-credential") {
		t.Fatalf("backup list = %d headers=%v body=%s", listed.Code, listed.Header(), listed.Body.String())
	}

	if _, err := service.Update(asset.ID, coreassets.Input{
		Name: asset.Name, Host: asset.Host, Group: asset.Group, NodeID: asset.NodeID,
		Username: asset.Username, HostKeyFingerprint: asset.HostKeyFingerprint,
		Port: asset.Port, Remark: asset.Remark, Password: "current-credential",
	}); err != nil {
		t.Fatal(err)
	}
	remotePassword = "current-credential"
	restored := doJSONRequest(t, router, http.MethodPost, basePath+"/"+backup.ID+"/restore", "", adminSession.AccessToken, "127.0.0.1:43210")
	if restored.Code != http.StatusOK || !strings.Contains(restored.Header().Get("Cache-Control"), "no-store") || strings.Contains(restored.Body.String(), "saved-credential") || strings.Contains(restored.Body.String(), "current-credential") {
		t.Fatalf("backup restore = %d headers=%v body=%s", restored.Code, restored.Header(), restored.Body.String())
	}
	if active, err := store.Password(asset.ID); err != nil || active != "saved-credential" || remotePassword != active {
		t.Fatalf("restored credential active/remote = %q/%q, %v", active, remotePassword, err)
	}

	deleted := doJSONRequest(t, router, http.MethodDelete, basePath+"/"+backup.ID, "", adminSession.AccessToken, "127.0.0.1:43210")
	if deleted.Code != http.StatusNoContent || !strings.Contains(deleted.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("backup deletion = %d headers=%v body=%s", deleted.Code, deleted.Header(), deleted.Body.String())
	}
}

func testAssetService(t *testing.T) *coreassets.Service {
	t.Helper()
	key := []byte("0123456789abcdef0123456789abcdef")
	store, err := coreassets.OpenStore(t.TempDir()+"/assets.json", key)
	if err != nil {
		t.Fatal(err)
	}
	return coreassets.NewService(store, nil)
}

func validTestFingerprint() string {
	return "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}
