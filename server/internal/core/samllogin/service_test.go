package samllogin

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"github.com/crewjam/saml"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/samlclient"
	"github.com/neko233-com/jumpserver233/server/testsupport/samlprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fixture(t *testing.T) (*Service, *samlprovider.Provider) { return fixtureDocs(t, nil) }
func fixtureDocs(t *testing.T, docs *storage.Documents) (*Service, *samlprovider.Provider) {
	t.Helper()
	p, e := samlprovider.New("https://idp.example.invalid")
	require.NoError(t, e)
	s, e := Open(filepath.Join(t.TempDir(), "saml.json"), make([]byte, 32), docs, "https://console.example.invalid")
	require.NoError(t, e)
	_, e = s.Save(Config{Config: samlclient.Config{EntityID: "https://console.example.invalid/sp", ACSURL: "https://console.example.invalid" + samlclient.ACSPath, MetadataXML: p.Metadata()}, Enabled: true}, "admin-id", "admin")
	require.NoError(t, e)
	return s, p
}
func begin(t *testing.T, s *Service, p *samlprovider.Provider) (Start, string, string) {
	t.Helper()
	start, e := s.Begin()
	require.NoError(t, e)
	req, state, e := samlprovider.Request(start.URL)
	require.NoError(t, e)
	raw, e := p.Response(req, nil)
	require.NoError(t, e)
	return start, state, raw
}
func TestSAMLBrowserProofHandoffReplayAndConfigurationRevision(t *testing.T) {
	s, p := fixture(t)
	start, state, raw := begin(t, s, p)
	code, e := s.Accept(state, raw)
	require.NoError(t, e)
	assert.NotContains(t, code, samlprovider.Subject)
	id, e := s.Finalize(code, start.Proof)
	require.NoError(t, e)
	assert.Equal(t, samlprovider.Subject, id.Subject)
	assert.Equal(t, s.Namespace(), id.Issuer)
	assert.False(t, id.Provision)
	_, e = s.Accept(state, raw)
	assert.ErrorIs(t, e, ErrFlow)
	_, e = s.Finalize(code, start.Proof)
	assert.ErrorIs(t, e, ErrFlow)
	start, state, raw = begin(t, s, p)
	code, e = s.Accept(state, raw)
	require.NoError(t, e)
	_, e = s.Finalize(code, "foreign-browser")
	assert.ErrorIs(t, e, ErrFlow)
	_, e = s.Finalize(code, start.Proof)
	assert.ErrorIs(t, e, ErrFlow)
	start, state, raw = begin(t, s, p)
	code, e = s.Accept(state, raw)
	require.NoError(t, e)
	s.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	_, e = s.Finalize(code, start.Proof)
	assert.ErrorIs(t, e, ErrFlow)
	s.now = time.Now
	start, state, raw = begin(t, s, p)
	cfg := s.Snapshot()
	_, e = s.Save(cfg, "admin", "admin")
	require.NoError(t, e)
	_, e = s.Accept(state, raw)
	assert.ErrorIs(t, e, ErrFlow)
	start, state, raw = begin(t, s, p)
	s.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	_, e = s.Accept(state, raw)
	assert.ErrorIs(t, e, ErrFlow)
	s.now = time.Now
	start, state, raw = begin(t, s, p)
	u, _ := url.Parse(start.URL)
	req, _, e := samlprovider.Request(u.String())
	require.NoError(t, e)
	old, e := p.Response(req, nil)
	require.NoError(t, e)
	_, e = s.Accept(state, old)
	require.NoError(t, e)
	// A reused assertion ID is rejected even when signed for a fresh request.
	var previous string
	for k := range s.replays {
		previous = k
		break
	}
	_, state, _ = begin(t, s, p)
	var requestID string
	for _, f := range s.flows {
		requestID = f.RequestID
	}
	req.ID = requestID
	duplicate, e := p.Response(req, func(a *saml.Assertion, r *saml.Response) { a.ID = previous })
	require.NoError(t, e)
	_, e = s.Accept(state, duplicate)
	assert.ErrorIs(t, e, ErrFlow)
}
func TestSAMLEncryptedIdentityAndPendingLifecycle(t *testing.T) {
	s, _ := fixture(t)
	raw, e := os.ReadFile(s.path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "PRIVATE KEY")
	assert.NotContains(t, string(raw), s.Snapshot().MetadataXML)
	next, e := Open(s.path, make([]byte, 32), nil, s.publicURL)
	require.NoError(t, e)
	assert.Equal(t, s.Snapshot(), next.Snapshot())
	metadata, e := next.Metadata()
	require.NoError(t, e)
	assert.NotContains(t, string(metadata), "PRIVATE KEY")
	assert.Equal(t, "admin-id", next.Audit()[0].ActorID)
	_, e = Open(s.path, []byte("different-synthetic-vault-key-1234"), nil, s.publicURL)
	assert.Error(t, e)
	pending, e := s.NewPending("user", s.Snapshot().Revision)
	require.NoError(t, e)
	ticket, e := s.Pending(pending, false)
	require.NoError(t, e)
	assert.Equal(t, "user", ticket.UserID)
	assert.NoError(t, s.SetSetup(pending, "setup"))
	assert.True(t, s.Consume(pending, ticket.Revision))
	assert.False(t, s.Consume(pending, ticket.Revision))
	pending, e = s.NewPending("user", s.Snapshot().Revision)
	require.NoError(t, e)
	cfg := s.Snapshot()
	ns := s.Namespace()
	cfg.Enabled = false
	_, e = s.Save(cfg, "admin", "admin")
	require.NoError(t, e)
	assert.False(t, s.IssuerAllowed(ns))
	_, e = s.Pending(pending, false)
	assert.Error(t, e)
	_, e = s.Begin()
	assert.ErrorIs(t, e, ErrDisabled)
	_, e = s.Save(cfg, "admin", "admin")
	assert.ErrorIs(t, e, ErrConflict)
	cfg = s.Snapshot()
	cfg.Enabled = true
	cfg.ACSURL = "https://different.invalid" + samlclient.ACSPath
	_, e = s.Save(cfg, "admin", "admin")
	assert.ErrorIs(t, e, ErrInvalid)
}

func TestSAMLPostgresReloadPreservesSPIdentity(t *testing.T) {
	value := os.Getenv("JMS_TEST_DATABASE_URL")
	if value == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for SAML PostgreSQL integration")
	}
	docs, e := storage.OpenPostgres(context.Background(), value, "saml-"+time.Now().Format("150405.000000000"))
	require.NoError(t, e)
	defer docs.Close()
	defer docs.Delete("saml-config")
	s, _ := fixtureDocs(t, docs)
	next, e := Open(filepath.Join(t.TempDir(), "saml.json"), make([]byte, 32), docs, s.publicURL)
	require.NoError(t, e)
	assert.Equal(t, s.Snapshot(), next.Snapshot())
	assert.Equal(t, s.data.Key, next.data.Key)
	raw, e := docs.Load("saml-config")
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "PRIVATE KEY")
	assert.NotContains(t, string(raw), s.Snapshot().MetadataXML)
}

func TestSAMLExplicitCertificateRotationAndBoundedAudit(t *testing.T) {
	s, _ := fixture(t)
	before := s.Snapshot()
	c := before
	c.RotateSP = true
	after, e := s.Save(c, "admin", "admin")
	require.NoError(t, e)
	assert.NotEqual(t, before.SPFingerprint, after.SPFingerprint)
	assert.False(t, after.RotateSP)
	assert.Equal(t, before.IDPEntityID, after.IDPEntityID)
	assert.Empty(t, s.Audit()[0].Config.MetadataXML)
	assert.NotEmpty(t, s.Audit()[0].Config.MetadataSHA256)
	reloaded, e := Open(s.path, make([]byte, 32), nil, s.publicURL)
	require.NoError(t, e)
	assert.Equal(t, after.SPFingerprint, reloaded.Snapshot().SPFingerprint)
}

func TestSAMLExpiredCertificateDoesNotPreventAdminRecovery(t *testing.T) {
	s, _ := fixture(t)
	assert.True(t, s.Available())
	kb, _ := pem.Decode(s.data.Key.PrivateKey)
	key, e := x509.ParsePKCS1PrivateKey(kb.Bytes)
	require.NoError(t, e)
	cb, _ := pem.Decode(s.data.Key.Certificate)
	cert, e := x509.ParseCertificate(cb.Bytes)
	require.NoError(t, e)
	cert.NotBefore = time.Now().Add(-2 * time.Hour)
	cert.NotAfter = time.Now().Add(-time.Hour)
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	require.NoError(t, e)
	s.data.Key.Certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	require.NoError(t, s.persist(s.data))
	next, e := Open(s.path, make([]byte, 32), nil, s.publicURL)
	require.NoError(t, e)
	assert.False(t, next.Available())
	assert.False(t, next.IssuerAllowed(next.Namespace()))
	_, e = next.Begin()
	assert.ErrorIs(t, e, ErrDisabled)
	c := next.Snapshot()
	c.RotateSP = true
	_, e = next.Save(c, "admin", "admin")
	require.NoError(t, e)
	assert.True(t, next.Available())
}
