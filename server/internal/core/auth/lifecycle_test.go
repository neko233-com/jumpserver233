package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func lifecycleEnv(t *testing.T) (*Service, User, User, UserActor) {
	t.Helper()
	s, e := OpenServiceWithVaultKey(filepath.Join(t.TempDir(), "users.json"), make([]byte, 32))
	require.NoError(t, e)
	a, e := s.Bootstrap("admin", "synthetic-lifecycle-admin-233")
	require.NoError(t, e)
	u, e := s.CreateUser("operator", "synthetic-lifecycle-user-233", RoleOperator)
	require.NoError(t, e)
	return s, a, u, UserActor{ID: a.ID, Name: a.Username, ManageAdministrators: true}
}
func lifecycleChange(t *testing.T, s *Service, u User, a UserActor, action string, in UserUpdate) ManagedUser {
	t.Helper()
	row, e := s.ManagedUser(u.ID)
	require.NoError(t, e)
	in.Revision = row.Revision
	out, e := s.ChangeUsers([]UserChange{{ID: u.ID, Action: action, UserUpdate: in}}, a)
	require.NoError(t, e)
	require.Len(t, out, 1)
	return out[0]
}
func TestUserLifecycleRevokesCredentialsProofsAndSnapshots(t *testing.T) {
	s, _, u, a := lifecycleEnv(t)
	login, e := s.Authenticate(u.Username, "synthetic-lifecycle-user-233")
	require.NoError(t, e)
	proofLogin, e := s.Authenticate(u.Username, "synthetic-lifecycle-user-233")
	require.NoError(t, e)
	proof, e := s.QuarantineLogin(proofLogin.AccessToken)
	require.NoError(t, e)
	key, e := s.CreateAccessKey(u.ID)
	require.NoError(t, e)
	permanent, e := s.CreatePermanentToken(u.ID)
	require.NoError(t, e)
	enrollment, e := s.StartMFAEnrollment(u.ID)
	require.NoError(t, e)
	name := "new display name"
	row := lifecycleChange(t, s, u, a, "update", UserUpdate{Name: &name})
	assert.Equal(t, 0, row.AuthGeneration)
	_, ok := s.ValidateToken(login.AccessToken)
	assert.True(t, ok)
	assert.NoError(t, s.ValidateLoginProof(proof.Proof, u.ID))
	active := false
	row = lifecycleChange(t, s, u, a, "update", UserUpdate{IsActive: &active})
	assert.Equal(t, "disabled", row.State)
	assert.Equal(t, 1, row.AuthGeneration)
	_, ok = s.ValidateToken(login.AccessToken)
	assert.False(t, ok)
	_, e = s.Authenticate(u.Username, "synthetic-lifecycle-user-233")
	assert.ErrorIs(t, e, ErrInvalidCredentials)
	_, e = s.StartMFAEnrollment(u.ID)
	assert.Error(t, e)
	_, e = s.CreatePermanentToken(u.ID)
	assert.Error(t, e)
	_, e = s.CreateAccessKey(u.ID)
	assert.Error(t, e)
	active = true
	lifecycleChange(t, s, u, a, "update", UserUpdate{IsActive: &active})
	_, ok = s.ValidateToken(login.AccessToken)
	assert.False(t, ok)
	_, ok = s.ValidatePermanentToken(permanent.Token)
	assert.False(t, ok)
	mac := hmac.New(sha256.New, []byte(key.Secret))
	mac.Write([]byte("request"))
	_, ok = s.VerifyAccessKeySignature(key.ID, "request", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	assert.False(t, ok)
	assert.Error(t, s.ValidateLoginProof(proof.Proof, u.ID))
	_, e = s.ConfirmMFAEnrollment(u.ID, "000000")
	assert.Error(t, e)
	assert.NotEmpty(t, enrollment.Secret)
	_, ok = s.ActiveUserSnapshot(u)
	assert.False(t, ok)
	login, e = s.Authenticate(u.Username, "synthetic-lifecycle-user-233")
	require.NoError(t, e)
	_, ok = s.ActiveUserSnapshot(login.User)
	assert.True(t, ok)
	lifecycleChange(t, s, u, a, "revoke", UserUpdate{})
	_, ok = s.ValidateToken(login.AccessToken)
	assert.False(t, ok)
	events, n, e := s.UserAudit(u.ID, 0, 100)
	require.NoError(t, e)
	assert.Equal(t, 4, n)
	raw, e := json.Marshal(events)
	require.NoError(t, e)
	for _, secret := range []string{name, key.Secret, permanent.Token, login.AccessToken, enrollment.Secret, "synthetic-lifecycle-user-233"} {
		assert.NotContains(t, string(raw), secret)
	}
	reloaded, e := OpenServiceWithVaultKey(s.path, make([]byte, 32))
	require.NoError(t, e)
	events2, n2, e := reloaded.UserAudit(u.ID, 0, 100)
	require.NoError(t, e)
	assert.Equal(t, n, n2)
	assert.Equal(t, events, events2)
}
func TestUserLifecycleBatchGuardsArchiveRestoreAndExpiry(t *testing.T) {
	s, admin, u, a := lifecycleEnv(t)
	off := false
	on := true
	role := RoleAdmin
	name := "safe name"
	for _, change := range []UserChange{
		{ID: u.ID, Action: "update", UserUpdate: UserUpdate{Revision: 0, Name: &name}},
		{ID: u.ID, Action: "invalid", UserUpdate: UserUpdate{Revision: 1}},
		{ID: u.ID, Action: "update", UserUpdate: UserUpdate{Revision: 1, Name: ptrString(strings.Repeat("a", 129))}},
		{ID: u.ID, Action: "update", UserUpdate: UserUpdate{Revision: 1, Comment: ptrString("bad\x00")}},
	} {
		_, e := s.ChangeUsers([]UserChange{change}, a)
		assert.Error(t, e)
	}
	_, e := s.ChangeUsers([]UserChange{{ID: u.ID, Action: "update", UserUpdate: UserUpdate{Revision: 1, Name: &name}}, {ID: admin.ID, Action: "update", UserUpdate: UserUpdate{Revision: 99, IsActive: &off}}}, a)
	assert.ErrorIs(t, e, ErrUserRevision)
	row, e := s.ManagedUser(u.ID)
	require.NoError(t, e)
	assert.Empty(t, row.Name)
	assert.Equal(t, 1, row.Revision)
	_, e = s.ChangeUsers([]UserChange{{ID: u.ID, Action: "revoke", UserUpdate: UserUpdate{Revision: 1}}, {ID: u.ID, Action: "revoke", UserUpdate: UserUpdate{Revision: 1}}}, a)
	assert.Error(t, e)
	_, e = s.ChangeUsers([]UserChange{{ID: admin.ID, Action: "update", UserUpdate: UserUpdate{Revision: 1, IsActive: &off}}}, a)
	assert.ErrorIs(t, e, ErrUserSelf)
	delegated := a
	delegated.ManageAdministrators = false
	_, e = s.ChangeUsers([]UserChange{{ID: u.ID, Action: "update", UserUpdate: UserUpdate{Revision: 1, Role: &role}}}, delegated)
	assert.ErrorIs(t, e, ErrUserAdmin)
	system := UserActor{ID: "admin-token", Name: "system", ManageAdministrators: true}
	_, e = s.ChangeUsers([]UserChange{{ID: admin.ID, Action: "archive", UserUpdate: UserUpdate{Revision: 1}}}, system)
	assert.ErrorIs(t, e, ErrLastAdministrator)
	future := time.Now().Add(time.Hour)
	_, e = s.ChangeUsers([]UserChange{{ID: admin.ID, Action: "update", UserUpdate: UserUpdate{Revision: 1, DateExpired: &future}}}, system)
	assert.ErrorIs(t, e, ErrLastAdministrator)
	row = lifecycleChange(t, s, u, a, "archive", UserUpdate{})
	assert.Equal(t, "archived", row.State)
	assert.False(t, row.IsActive)
	_, ok := s.UserByID(u.ID)
	assert.False(t, ok)
	assert.Len(t, s.ListUsers(), 1)
	_, e = s.CreateUser(u.Username, "synthetic-new-password", RoleOperator)
	assert.ErrorIs(t, e, ErrUserExists)
	row = lifecycleChange(t, s, u, a, "restore", UserUpdate{})
	assert.Equal(t, "disabled", row.State)
	row = lifecycleChange(t, s, u, a, "update", UserUpdate{IsActive: &on, DateExpired: &future})
	assert.True(t, row.IsActive)
	s.now = func() time.Time { return future }
	_, e = s.Authenticate(u.Username, "synthetic-lifecycle-user-233")
	assert.ErrorIs(t, e, ErrInvalidCredentials)
	row, e = s.ManagedUser(u.ID)
	require.NoError(t, e)
	assert.Equal(t, "expired", row.State)
	row = lifecycleChange(t, s, u, a, "update", UserUpdate{ClearExpiry: true})
	assert.True(t, row.IsActive)
	assert.True(t, row.DateExpired.IsZero())
}
func ptrString(s string) *string { return &s }
func TestUserLifecycleExternalAndPasskeyExpectedGeneration(t *testing.T) {
	s, _, _, a := lifecycleEnv(t)
	s.SetPasskeyAllowed(func(string, string) bool { return true })
	for _, source := range []string{"oidc", "ldap", "saml", "cas", "radius"} {
		t.Run(source, func(t *testing.T) {
			s.SetExternalSourceAllowed(source, func(string) bool { return true })
			u, e := s.EnsureExternalUser(source, "https://identity.invalid", source, "", true)
			require.NoError(t, e)
			_, _, e = s.AuthenticateExternalUser(u.ID, source, "", 0)
			require.NoError(t, e)
			lifecycleChange(t, s, u, a, "revoke", UserUpdate{})
			_, _, e = s.AuthenticateExternalUser(u.ID, source, "", 0)
			assert.ErrorIs(t, e, ErrInvalidCredentials)
			_, _, e = s.AuthenticatePasskeyUser(u.ID, "synthetic-key", "", 0)
			assert.ErrorIs(t, e, ErrInvalidCredentials)
			_, _, e = s.AuthenticateExternalUser(u.ID, source, "", 1)
			require.NoError(t, e)
			admin := RoleAdmin
			row, e := s.ManagedUser(u.ID)
			require.NoError(t, e)
			_, e = s.ChangeUsers([]UserChange{{ID: u.ID, Action: "update", UserUpdate: UserUpdate{Revision: row.Revision, Role: &admin}}}, a)
			assert.ErrorIs(t, e, ErrExternalIdentity)
		})
	}
}
func TestUserLifecycleLegacyMigrationAndPersistenceRollback(t *testing.T) {
	s, _, u, a := lifecycleEnv(t)
	var records []storedUser
	for _, r := range s.users {
		r.Revision = 0
		records = append(records, r)
	}
	legacy, e := json.Marshal(records)
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(s.path, legacy, 0600))
	s, e = OpenServiceWithVaultKey(s.path, make([]byte, 32))
	require.NoError(t, e)
	row, e := s.ManagedUser(u.ID)
	require.NoError(t, e)
	assert.Equal(t, 1, row.Revision)
	name := "migrated"
	lifecycleChange(t, s, u, a, "update", UserUpdate{Name: &name})
	raw, e := os.ReadFile(s.path)
	require.NoError(t, e)
	assert.Contains(t, string(raw), `"version":4`)
	oldPath := s.path
	s.path = t.TempDir()
	_, e = s.ChangeUsers([]UserChange{{ID: u.ID, Action: "revoke", UserUpdate: UserUpdate{Revision: 2}}}, a)
	require.Error(t, e)
	row, e = s.ManagedUser(u.ID)
	require.NoError(t, e)
	assert.Equal(t, 2, row.Revision)
	assert.Zero(t, row.AuthGeneration)
	_, n, e := s.UserAudit("", 0, 100)
	require.NoError(t, e)
	assert.Equal(t, 1, n)
	s.path = oldPath
	var doc userEnvelope
	require.NoError(t, json.Unmarshal(raw, &doc))
	doc.Audit[0].Action = "forged"
	raw, e = json.Marshal(doc)
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(oldPath, raw, 0600))
	_, e = OpenServiceWithVaultKey(oldPath, make([]byte, 32))
	assert.ErrorIs(t, e, ErrUserStoreCorrupt)
}
func TestUserLifecycleSharedFailoverFencesStaleSessionDocument(t *testing.T) {
	url := os.Getenv("JMS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("PostgreSQL integration fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	docs, e := storage.OpenPostgres(ctx, url, "user-lifecycle-"+time.Now().Format("150405.000000000"))
	require.NoError(t, e)
	t.Cleanup(func() { _ = docs.Delete("users"); _ = docs.Delete("auth-sessions"); _ = docs.Close() })
	path := filepath.Join(t.TempDir(), "users.json")
	s, e := OpenServiceWithDocuments(path, docs)
	require.NoError(t, e)
	admin, e := s.Bootstrap("admin", "synthetic-admin-password-233")
	require.NoError(t, e)
	u, e := s.CreateUser("operator", "synthetic-user-password-233", RoleOperator)
	require.NoError(t, e)
	login, e := s.Authenticate(u.Username, "synthetic-user-password-233")
	require.NoError(t, e)
	stale, e := docs.Load("auth-sessions")
	require.NoError(t, e)
	lifecycleChange(t, s, u, UserActor{ID: admin.ID, Name: admin.Username, ManageAdministrators: true}, "revoke", UserUpdate{})
	require.NoError(t, docs.Save("auth-sessions", stale))
	leader, e := OpenServiceWithDocuments(path, docs)
	require.NoError(t, e)
	_, ok := leader.ValidateToken(login.AccessToken)
	assert.False(t, ok)
	_, n, e := leader.UserAudit(u.ID, 0, 25)
	require.NoError(t, e)
	assert.Equal(t, 1, n)
}
