package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

func TestBootstrapLoginRevokeAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	service, err := OpenService(path)
	if err != nil {
		t.Fatal(err)
	}
	if !service.BootstrapRequired() {
		t.Fatal("new user store must require bootstrap")
	}
	admin, err := service.Bootstrap("Admin.User", "a-long-password-with-12+bytes")
	if err != nil {
		t.Fatal(err)
	}
	if admin.Role != RoleAdmin || admin.Username != "admin.user" || service.BootstrapRequired() {
		t.Fatalf("bootstrap user = %+v", admin)
	}
	if _, err := service.Bootstrap("second", "another-long-password-123"); !errors.Is(err, ErrBootstrapComplete) {
		t.Fatalf("second bootstrap error = %v, want ErrBootstrapComplete", err)
	}

	login, err := service.Authenticate("ADMIN.USER", "a-long-password-with-12+bytes")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if login.User.ID != admin.ID || login.User.Role != RoleAdmin || login.AccessToken == "" || login.ExpiresAt.IsZero() {
		t.Fatalf("login session = %+v", login)
	}
	if user, ok := service.ValidateToken(login.AccessToken); !ok || user.ID != admin.ID {
		t.Fatalf("ValidateToken() = %+v, %v", user, ok)
	}
	if _, err := service.Authenticate("admin.user", "incorrect-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("invalid credentials error = %v", err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"a-long-password-with-12+bytes", login.AccessToken} {
		if strings.Contains(string(contents), secret) {
			t.Fatalf("user store contains secret %q", secret)
		}
	}

	reloaded, err := OpenService(path)
	if err != nil {
		t.Fatalf("reload user store: %v", err)
	}
	if _, ok := reloaded.ValidateToken(login.AccessToken); ok {
		t.Fatal("login token survived restart")
	}
	if _, err := reloaded.Authenticate("admin.user", "a-long-password-with-12+bytes"); err != nil {
		t.Fatalf("reloaded password hash did not authenticate: %v", err)
	}
	service.RevokeToken(login.AccessToken)
	if _, ok := service.ValidateToken(login.AccessToken); ok {
		t.Fatal("revoked token remained valid")
	}
}

func TestCreateOperatorAndValidateInput(t *testing.T) {
	service, err := OpenService(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Bootstrap("admin.user", "an-initial-admin-password-123"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateUser("user.one", "a-long-password-with-12+bytes", RoleOperator); err != nil {
		t.Fatal(err)
	}
	operator, err := service.Authenticate("user.one", "a-long-password-with-12+bytes")
	if err != nil {
		t.Fatal(err)
	}
	if operator.User.Role != RoleOperator {
		t.Fatalf("role = %q, want %q", operator.User.Role, RoleOperator)
	}
	for _, test := range []struct {
		username string
		password string
		role     string
		wantErr  error
	}{
		{username: "x", password: "a-long-password-with-12+bytes", role: RoleOperator, wantErr: ErrInvalidUsername},
		{username: "user.two", password: "short", role: RoleOperator, wantErr: ErrInvalidPassword},
		{username: "user.two", password: "a-long-password-with-12+bytes", role: "root", wantErr: ErrInvalidRole},
	} {
		if _, err := service.CreateUser(test.username, test.password, test.role); !errors.Is(err, test.wantErr) {
			t.Errorf("CreateUser(%q) error = %v, want %v", test.username, err, test.wantErr)
		}
	}
}

func TestChangePasswordRevokesOtherSessionsAndPersistsNewHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	service, err := OpenService(path)
	if err != nil {
		t.Fatal(err)
	}
	const currentPassword = "an-initial-admin-password-123"
	const newPassword = "a-new-admin-password-with-24"
	admin, err := service.Bootstrap("admin.user", currentPassword)
	if err != nil {
		t.Fatal(err)
	}
	currentSession, err := service.Authenticate("admin.user", currentPassword)
	if err != nil {
		t.Fatal(err)
	}
	otherSession, err := service.Authenticate("admin.user", currentPassword)
	if err != nil {
		t.Fatal(err)
	}

	if err := service.ChangePassword(admin.ID, currentSession.AccessToken, "incorrect-current-password", newPassword); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong current password error = %v, want ErrInvalidCredentials", err)
	}
	if err := service.ChangePassword(admin.ID, currentSession.AccessToken, currentPassword, currentPassword); !errors.Is(err, ErrPasswordUnchanged) {
		t.Fatalf("unchanged password error = %v, want ErrPasswordUnchanged", err)
	}
	if err := service.ChangePassword(admin.ID, currentSession.AccessToken, currentPassword, "short"); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("short new password error = %v, want ErrInvalidPassword", err)
	}
	if err := service.ChangePassword(admin.ID, currentSession.AccessToken, currentPassword, newPassword); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if user, ok := service.ValidateToken(currentSession.AccessToken); !ok || user.ID != admin.ID {
		t.Fatalf("current session after password change = (%+v, %v), want retained session", user, ok)
	}
	if _, ok := service.ValidateToken(otherSession.AccessToken); ok {
		t.Fatal("password change did not revoke another active session")
	}
	if _, err := service.Authenticate("admin.user", currentPassword); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("old password login error = %v, want ErrInvalidCredentials", err)
	}
	if _, err := service.Authenticate("admin.user", newPassword); err != nil {
		t.Fatalf("new password login: %v", err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{currentPassword, newPassword, currentSession.AccessToken, otherSession.AccessToken} {
		if strings.Contains(string(contents), secret) {
			t.Fatalf("user store contains secret %q", secret)
		}
	}
	reloaded, err := OpenService(path)
	if err != nil {
		t.Fatalf("reload user store: %v", err)
	}
	if _, err := reloaded.Authenticate("admin.user", newPassword); err != nil {
		t.Fatalf("new password did not survive reload: %v", err)
	}
}

func TestOpenServiceRejectsCorruptStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	if err := os.WriteFile(path, []byte(`[{"id":"user-bad","username":"bad","role":"admin"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenService(path); !errors.Is(err, ErrUserStoreCorrupt) {
		t.Fatalf("OpenService() error = %v, want ErrUserStoreCorrupt", err)
	}
}

func TestSharedLoginSessionsSurviveNodeFailoverWithoutStoringTokens(t *testing.T) {
	databaseURL := os.Getenv("JMS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set JMS_TEST_DATABASE_URL to run the PostgreSQL auth-session integration test")
	}
	namespace := "auth-test-" + time.Now().UTC().Format("20060102150405.000000000")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	documents, err := storage.OpenPostgres(ctx, databaseURL, namespace)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = documents.Delete("auth-sessions")
		_ = documents.Delete("users")
		_ = documents.Close()
	})

	path := filepath.Join(t.TempDir(), "users.json")
	firstNode, err := OpenServiceWithDocuments(path, documents)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := firstNode.Bootstrap("admin.user", "a-long-password-with-12+bytes")
	if err != nil {
		t.Fatal(err)
	}
	login, err := firstNode.Authenticate("admin.user", "a-long-password-with-12+bytes")
	if err != nil {
		t.Fatal(err)
	}
	storedSessions, err := documents.Load("auth-sessions")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(storedSessions), login.AccessToken) {
		t.Fatal("shared auth state contains the bearer token instead of only its digest")
	}
	tokenHash := sha256.Sum256([]byte(login.AccessToken))
	if !strings.Contains(string(storedSessions), hex.EncodeToString(tokenHash[:])) {
		t.Fatal("shared auth state does not contain the bearer token digest")
	}

	secondNode, err := OpenServiceWithDocuments(path, documents)
	if err != nil {
		t.Fatalf("open standby auth service: %v", err)
	}
	if user, ok := secondNode.ValidateToken(login.AccessToken); !ok || user.ID != admin.ID {
		t.Fatalf("token after node failover = (%+v, %v), want the original admin", user, ok)
	}
	if err := secondNode.RevokeToken(login.AccessToken); err != nil {
		t.Fatalf("revoke shared token: %v", err)
	}
	newLeader, err := OpenServiceWithDocuments(path, documents)
	if err != nil {
		t.Fatalf("reload auth service after revocation: %v", err)
	}
	if _, ok := newLeader.ValidateToken(login.AccessToken); ok {
		t.Fatal("revoked token survived a subsequent node reload")
	}
}

func TestSharedPasswordChangeRevokesOtherSessionsAcrossFailover(t *testing.T) {
	databaseURL := os.Getenv("JMS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set JMS_TEST_DATABASE_URL to run the PostgreSQL password-change integration test")
	}
	namespace := "auth-password-test-" + time.Now().UTC().Format("20060102150405.000000000")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	documents, err := storage.OpenPostgres(ctx, databaseURL, namespace)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = documents.Delete("auth-sessions")
		_ = documents.Delete("users")
		_ = documents.Close()
	})

	const currentPassword = "an-initial-admin-password-123"
	const newPassword = "a-new-admin-password-with-24"
	path := filepath.Join(t.TempDir(), "users.json")
	firstNode, err := OpenServiceWithDocuments(path, documents)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := firstNode.Bootstrap("admin.user", currentPassword)
	if err != nil {
		t.Fatal(err)
	}
	currentSession, err := firstNode.Authenticate("admin.user", currentPassword)
	if err != nil {
		t.Fatal(err)
	}
	otherSession, err := firstNode.Authenticate("admin.user", currentPassword)
	if err != nil {
		t.Fatal(err)
	}

	standbyNode, err := OpenServiceWithDocuments(path, documents)
	if err != nil {
		t.Fatalf("open standby auth service: %v", err)
	}
	if err := standbyNode.ChangePassword(admin.ID, currentSession.AccessToken, currentPassword, newPassword); err != nil {
		t.Fatalf("change password on standby node: %v", err)
	}
	newLeader, err := OpenServiceWithDocuments(path, documents)
	if err != nil {
		t.Fatalf("reload auth service after password change: %v", err)
	}
	if user, ok := newLeader.ValidateToken(currentSession.AccessToken); !ok || user.ID != admin.ID {
		t.Fatalf("current token after failover = (%+v, %v), want retained admin session", user, ok)
	}
	if _, ok := newLeader.ValidateToken(otherSession.AccessToken); ok {
		t.Fatal("other token remained active after password change and failover")
	}
	if _, err := newLeader.Authenticate("admin.user", currentPassword); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("old password after failover = %v, want ErrInvalidCredentials", err)
	}
	if _, err := newLeader.Authenticate("admin.user", newPassword); err != nil {
		t.Fatalf("new password after failover: %v", err)
	}
}
