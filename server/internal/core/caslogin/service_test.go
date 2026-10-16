package caslogin

import (
	"context"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/casclient"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/neko233-com/jumpserver233/server/testsupport/casprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fixture(t *testing.T, docs *storage.Documents) (*Service, *casprovider.Provider) {
	t.Helper()
	p := casprovider.New("", casprovider.Options{})
	server := httptest.NewServer(p)
	t.Cleanup(server.Close)
	p.BaseURL = server.URL + "/cas"
	s, e := Open(filepath.Join(t.TempDir(), "cas.json"), make([]byte, 32), docs, "", nil)
	require.NoError(t, e)
	_, e = s.Save(Config{Config: casclient.Config{BaseURL: p.BaseURL, Protocol: "3", AllowLoopbackHTTP: true}, CallbackURL: "http://127.0.0.1:5177" + CallbackPath, Enabled: true}, "admin-id", "admin")
	require.NoError(t, e)
	return s, p
}
func begin(t *testing.T, s *Service, p *casprovider.Provider) (Start, string, string) {
	t.Helper()
	start, e := s.Begin()
	require.NoError(t, e)
	u, e := url.Parse(start.URL)
	require.NoError(t, e)
	assert.Equal(t, "true", u.Query().Get("renew"))
	service, e := url.Parse(u.Query().Get("service"))
	require.NoError(t, e)
	ticket, e := p.Issue(service.String())
	require.NoError(t, e)
	return start, service.Query().Get("state"), ticket
}
func TestCASBrowserBindingExpiryRevisionsAndReplay(t *testing.T) {
	s, p := fixture(t, nil)
	start, state, ticket := begin(t, s, p)
	id, e := s.Finish(t.Context(), state, start.Proof, ticket)
	require.NoError(t, e)
	assert.Equal(t, casprovider.Subject, id.Subject)
	assert.Equal(t, p.BaseURL, id.Issuer)
	assert.False(t, id.Provision)
	_, e = s.Finish(t.Context(), state, start.Proof, ticket)
	assert.ErrorIs(t, e, ErrFlow)
	start, state, ticket = begin(t, s, p)
	_, e = s.Finish(t.Context(), state, "different-browser", ticket)
	assert.ErrorIs(t, e, ErrFlow)
	_, e = s.Finish(t.Context(), state, start.Proof, ticket)
	assert.ErrorIs(t, e, ErrFlow)
	assert.Equal(t, int32(1), p.Validations.Load())
	start, state, ticket = begin(t, s, p)
	s.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	_, e = s.Finish(t.Context(), state, start.Proof, ticket)
	assert.ErrorIs(t, e, ErrFlow)
	s.now = time.Now
	start, state, ticket = begin(t, s, p)
	cfg := s.Snapshot()
	_, e = s.Save(cfg, "admin", "admin")
	require.NoError(t, e)
	_, e = s.Finish(t.Context(), state, start.Proof, ticket)
	assert.ErrorIs(t, e, ErrFlow)
}
func TestCASEncryptedConfigPendingAndDisabledIdentity(t *testing.T) {
	s, p := fixture(t, nil)
	require.NoError(t, s.Check(t.Context()))
	raw, e := os.ReadFile(s.path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), p.BaseURL)
	next, e := Open(s.path, make([]byte, 32), nil, "", nil)
	require.NoError(t, e)
	assert.Equal(t, s.Snapshot(), next.Snapshot())
	assert.Len(t, next.Audit(), 1)
	assert.Equal(t, "admin-id", next.Audit()[0].ActorID)
	ticket, e := s.NewPending("user", s.Snapshot().Revision)
	require.NoError(t, e)
	pnd, e := s.Pending(ticket, false)
	require.NoError(t, e)
	assert.Equal(t, "user", pnd.UserID)
	assert.True(t, s.Consume(ticket, pnd.Revision))
	assert.False(t, s.Consume(ticket, pnd.Revision))
	ticket, e = s.NewPending("user", s.Snapshot().Revision)
	require.NoError(t, e)
	cfg := s.Snapshot()
	cfg.Enabled = false
	_, e = s.Save(cfg, "admin", "admin")
	require.NoError(t, e)
	assert.False(t, s.IssuerAllowed(p.BaseURL))
	_, e = s.Pending(ticket, false)
	assert.Error(t, e)
	_, e = s.Begin()
	assert.ErrorIs(t, e, ErrDisabled)
	_, e = s.Save(cfg, "admin", "admin")
	assert.ErrorIs(t, e, ErrConflict)
}
func TestCASCallbackMustMatchExplicitPublicOrigin(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "cas.json"), make([]byte, 32), nil, "https://console.example.invalid", nil)
	require.NoError(t, e)
	cfg := Config{Config: casclient.Config{BaseURL: "https://cas.example.invalid/cas", Protocol: "3"}, CallbackURL: "https://console.example.invalid" + CallbackPath, Enabled: true}
	_, e = s.Save(cfg, "a", "a")
	require.NoError(t, e)
	assert.True(t, s.SecureCookies())
	assert.Equal(t, "https://console.example.invalid/login", s.ReturnURL("/login"))
	cfg = s.Snapshot()
	cfg.CallbackURL = "https://attacker.example.invalid" + CallbackPath
	_, e = s.Save(cfg, "a", "a")
	assert.ErrorIs(t, e, ErrInvalid)
	cfg = s.Snapshot()
	cfg.CallbackURL += "?injected=1"
	_, e = s.Save(cfg, "a", "a")
	assert.ErrorIs(t, e, ErrInvalid)
}
func TestCASPostgresReload(t *testing.T) {
	value := os.Getenv("JMS_TEST_DATABASE_URL")
	if value == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for CAS PostgreSQL integration")
	}
	docs, e := storage.OpenPostgres(context.Background(), value, "cas-"+time.Now().Format("150405.000000000"))
	require.NoError(t, e)
	defer docs.Close()
	defer docs.Delete("cas-config")
	s, _ := fixture(t, docs)
	next, e := Open(filepath.Join(t.TempDir(), "cas.json"), make([]byte, 32), docs, "", nil)
	require.NoError(t, e)
	assert.Equal(t, s.Snapshot(), next.Snapshot())
	raw, e := docs.Load("cas-config")
	require.NoError(t, e)
	assert.NotContains(t, string(raw), s.Snapshot().BaseURL)
	require.NoError(t, next.Check(t.Context()))
}
