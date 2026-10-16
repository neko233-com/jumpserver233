package passkeys

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/neko233-com/jumpserver233/server/testsupport/passkeyauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var owner = auth.User{ID: "user-synthetic", Username: "synthetic.operator"}

func service(t *testing.T, docs *storage.Documents) *Service {
	t.Helper()
	s, e := Open(filepath.Join(t.TempDir(), "passkeys.json"), make([]byte, 32), docs, "https://console.example.invalid")
	require.NoError(t, e)
	c := s.Snapshot()
	assert.False(t, c.Enabled)
	c.Enabled = true
	_, e = s.Save(c, "admin", "admin")
	require.NoError(t, e)
	return s
}
func register(t *testing.T, s *Service) (Metadata, *passkeyauth.Authenticator) {
	t.Helper()
	a, e := passkeyauth.New(s.origin, s.client.RPID)
	require.NoError(t, e)
	start, e := s.BeginRegistration(owner, "QA device", "synthetic-owner-session", "v1")
	require.NoError(t, e)
	raw, e := a.Registration(start.Options, passkeyauth.Overrides{})
	require.NoError(t, e)
	m, e := s.FinishRegistration(start.Token, "synthetic-owner-session", owner, raw, "v1")
	require.NoError(t, e)
	return m, a
}
func login(t *testing.T, s *Service, a *passkeyauth.Authenticator) string {
	t.Helper()
	b, e := s.BeginLogin()
	require.NoError(t, e)
	raw, e := a.Assertion(b.Options, passkeyauth.Overrides{})
	require.NoError(t, e)
	ticket, e := s.FinishLogin(b.Token, raw)
	require.NoError(t, e)
	return ticket
}
func TestPasskeyOwnershipRevisionExpiryAndOneUse(t *testing.T) {
	s := service(t, nil)
	m, a := register(t, s)
	assert.True(t, s.Allowed(owner.ID, s.sessionID(m.ID)))
	assert.False(t, s.Allowed("another", s.sessionID(m.ID)))
	assert.Len(t, s.List(owner.ID), 1)
	assert.Empty(t, s.List("another"))
	assert.ErrorIs(t, s.Delete(auth.User{ID: "another"}, m.ID), ErrNotFound)
	_, e := s.Rename(auth.User{ID: "another"}, m.ID, "renamed")
	assert.ErrorIs(t, e, ErrNotFound)
	_, e = s.Rename(owner, m.ID, "Renamed device")
	require.NoError(t, e)
	assert.Equal(t, "Renamed device", s.List(owner.ID)[0].Name)
	b, e := s.BeginLogin()
	require.NoError(t, e)
	raw, e := a.Assertion(b.Options, passkeyauth.Overrides{})
	require.NoError(t, e)
	_, e = s.FinishLogin("foreign-cookie", raw)
	assert.ErrorIs(t, e, ErrFlow)
	ticket, e := s.FinishLogin(b.Token, raw)
	require.NoError(t, e)
	_, e = s.FinishLogin(b.Token, raw)
	assert.ErrorIs(t, e, ErrFlow)
	// Five failed-factor attempts are allowed; a valid fifth completion can consume.
	for range 5 {
		p, e := s.Pending(ticket, true)
		require.NoError(t, e)
		assert.Equal(t, s.sessionID(m.ID), p.CredentialID)
	}
	assert.True(t, s.Consume(ticket, s.Snapshot().Revision))
	assert.False(t, s.Consume(ticket, s.Snapshot().Revision))
	start, e := s.BeginRegistration(owner, "Other device", "session-A", "v1")
	require.NoError(t, e)
	body, e := a.Registration(start.Options, passkeyauth.Overrides{})
	require.NoError(t, e)
	_, e = s.FinishRegistration(start.Token, "session-B", owner, body, "v1")
	assert.ErrorIs(t, e, ErrFlow)
	_, e = s.FinishRegistration(start.Token, "session-A", owner, body, "v1")
	assert.ErrorIs(t, e, ErrFlow)
	b, e = s.BeginLogin()
	require.NoError(t, e)
	raw, e = a.Assertion(b.Options, passkeyauth.Overrides{})
	require.NoError(t, e)
	s.now = func() time.Time { return time.Now().Add(6 * time.Minute) }
	_, e = s.FinishLogin(b.Token, raw)
	assert.ErrorIs(t, e, ErrFlow)
	s.now = time.Now
	b, e = s.BeginLogin()
	require.NoError(t, e)
	raw, e = a.Assertion(b.Options, passkeyauth.Overrides{})
	require.NoError(t, e)
	cfg := s.Snapshot()
	_, e = s.Save(cfg, "admin", "admin")
	require.NoError(t, e)
	_, e = s.FinishLogin(b.Token, raw)
	assert.ErrorIs(t, e, ErrFlow)
	_, e = s.Save(cfg, "admin", "admin")
	assert.ErrorIs(t, e, ErrConflict)
	ticket = login(t, s, a)
	cfg = s.Snapshot()
	cfg.Enabled = false
	_, e = s.Save(cfg, "admin", "admin")
	require.NoError(t, e)
	assert.False(t, s.Allowed(owner.ID, s.sessionID(m.ID)))
	_, e = s.Pending(ticket, false)
	assert.Error(t, e)
	_, e = s.BeginLogin()
	assert.ErrorIs(t, e, ErrDisabled)
}
func TestPasskeyCounterWarningZeroCountersAndEncryptedReload(t *testing.T) {
	s := service(t, nil)
	m, a := register(t, s)
	ticket := login(t, s, a)
	assert.NotNil(t, s.List(owner.ID)[0].LastUsedAt)
	assert.NoError(t, s.SetSetup(ticket, "setup"))
	p, e := s.Pending(ticket, false)
	require.NoError(t, e)
	assert.Equal(t, "setup", p.SetupToken)
	b, e := s.BeginLogin()
	require.NoError(t, e)
	zero := uint32(0)
	raw, e := a.Assertion(b.Options, passkeyauth.Overrides{Counter: &zero})
	require.NoError(t, e)
	_, e = s.FinishLogin(b.Token, raw)
	assert.ErrorIs(t, e, ErrClone)
	assert.True(t, s.List(owner.ID)[0].Disabled)
	assert.False(t, s.Allowed(owner.ID, s.sessionID(m.ID)))
	_, e = s.Pending(ticket, false)
	assert.Error(t, e)
	rawFile, e := os.ReadFile(s.path)
	require.NoError(t, e)
	assert.NotContains(t, string(rawFile), owner.ID)
	assert.NotContains(t, string(rawFile), "publicKey")
	next, e := Open(s.path, make([]byte, 32), nil, s.origin)
	require.NoError(t, e)
	assert.Equal(t, s.List(owner.ID), next.List(owner.ID))
	assert.True(t, next.List(owner.ID)[0].Disabled)
	_, e = Open(s.path, []byte("different-synthetic-vault-key-123"), nil, s.origin)
	assert.Error(t, e)
	s = service(t, nil)
	_, a = register(t, s)
	for range 2 {
		b, e = s.BeginLogin()
		require.NoError(t, e)
		raw, e = a.Assertion(b.Options, passkeyauth.Overrides{Counter: &zero})
		require.NoError(t, e)
		_, e = s.FinishLogin(b.Token, raw)
		require.NoError(t, e)
	}
	ticket = login(t, s, a)
	require.NoError(t, s.Delete(owner, s.List(owner.ID)[0].ID))
	_, e = s.Pending(ticket, false)
	assert.Error(t, e)
	assert.Empty(t, s.List(owner.ID))
}
func TestPasskeyCapacityNamesCancelAndOriginMigration(t *testing.T) {
	s := service(t, nil)
	for _, name := range []string{"", "bad\nname", strings.Repeat("x", 121), string([]byte{0xff})} {
		_, e := s.BeginRegistration(owner, name, "session", "v1")
		assert.ErrorIs(t, e, ErrInvalid)
	}
	for range 10 {
		register(t, s)
	}
	_, e := s.BeginRegistration(owner, "Eleventh", "session", "v1")
	assert.ErrorIs(t, e, ErrCapacity)
	b, e := s.BeginLogin()
	require.NoError(t, e)
	s.Cancel(b.Token)
	_, e = s.FinishLogin(b.Token, json.RawMessage(`{}`))
	assert.ErrorIs(t, e, ErrFlow)
	next, e := Open(s.path, make([]byte, 32), nil, "https://another.example.invalid")
	require.NoError(t, e)
	for _, m := range next.List(owner.ID) {
		assert.False(t, next.Allowed(owner.ID, next.sessionID(m.ID)))
	}
	invalid, e := Open(filepath.Join(t.TempDir(), "passkeys.json"), make([]byte, 32), nil, "http://127.0.0.1:5177")
	require.NoError(t, e)
	_, e = invalid.Save(Config{Enabled: true}, "admin", "admin")
	assert.ErrorIs(t, e, ErrDisabled)
	d := persisted{}
	for range 1100 {
		event(&d, time.Now(), "user", "user", "verify", "id")
	}
	assert.Len(t, d.Audit, 1000)
}
func TestPasskeyPostgresReloadCredentialsAndCounters(t *testing.T) {
	url := os.Getenv("JMS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for Passkey PostgreSQL integration")
	}
	docs, e := storage.OpenPostgres(context.Background(), url, "passkeys-"+time.Now().Format("150405.000000000"))
	require.NoError(t, e)
	defer docs.Close()
	defer docs.Delete("passkeys")
	s := service(t, docs)
	m, a := register(t, s)
	login(t, s, a)
	next, e := Open(filepath.Join(t.TempDir(), "passkeys.json"), make([]byte, 32), docs, s.origin)
	require.NoError(t, e)
	assert.True(t, next.Allowed(owner.ID, next.sessionID(m.ID)))
	assert.Equal(t, s.List(owner.ID), next.List(owner.ID))
	assert.Equal(t, s.data.Records[m.ID].Credential.Authenticator.SignCount, next.data.Records[m.ID].Credential.Authenticator.SignCount)
	raw, e := docs.Load("passkeys")
	require.NoError(t, e)
	assert.NotContains(t, string(raw), owner.ID)
	assert.NotContains(t, string(raw), "publicKey")
	login(t, next, a)
}

func TestPasskeyRegistrationBindsManagementVersion(t *testing.T) {
	s := service(t, nil)
	a, e := passkeyauth.New(s.origin, s.client.RPID)
	require.NoError(t, e)
	b, e := s.BeginRegistration(owner, "Version-bound key", "session", "before-change")
	require.NoError(t, e)
	raw, e := a.Registration(b.Options, passkeyauth.Overrides{})
	require.NoError(t, e)
	_, e = s.FinishRegistration(b.Token, "session", owner, raw, "after-change")
	assert.ErrorIs(t, e, ErrFlow)
	assert.Empty(t, s.List(owner.ID))
}
