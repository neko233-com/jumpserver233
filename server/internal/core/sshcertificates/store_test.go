package sshcertificates

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xssh "golang.org/x/crypto/ssh"
)

func certStore(t *testing.T) *Store {
	t.Helper()
	s, e := Open(filepath.Join(t.TempDir(), "ssh-certificates.json"), make([]byte, 32), nil)
	require.NoError(t, e)
	t.Cleanup(s.Close)
	return s
}
func certTarget() Target {
	return Target{AssetID: "asset-cert", Host: "127.0.0.1", Port: 22, Username: "ops", Fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
}
func builtin(t *testing.T, s *Store) Issuer {
	t.Helper()
	v, e := s.Save("", "admin", Input{Name: "Built-in", Provider: "builtin", Enabled: true, RequestID: "create-issuer-001"})
	require.NoError(t, e)
	return v
}
func parseCert(t *testing.T, c sshclient.Credentials) *xssh.Certificate {
	t.Helper()
	key, _, _, _, e := xssh.ParseAuthorizedKey(c.Certificate)
	require.NoError(t, e)
	cert, ok := key.(*xssh.Certificate)
	require.True(t, ok)
	return cert
}

func TestSSHCertificateBuiltinCacheTwoPhaseRotationRestartAndNoFallback(t *testing.T) {
	s := certStore(t)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	issuer := builtin(t, s)
	target := certTarget()
	in := BindingInput{IssuerID: issuer.ID, RequestID: "bind-issuer-001"}
	binding, e := s.Bind(target, "admin", in)
	require.NoError(t, e)
	before, e := s.ConnectionIdentity(target.AssetID)
	require.NoError(t, e)
	original := sshclient.Credentials{Password: "bootstrap-must-never-return"}
	c, e := s.Resolve(target, original)
	require.NoError(t, e)
	assert.Empty(t, c.Password)
	cert := parseCert(t, c)
	assert.Equal(t, []string{target.Username}, cert.ValidPrincipals)
	assert.Equal(t, uint32(xssh.UserCert), cert.CertType)
	assert.LessOrEqual(t, cert.ValidBefore, uint64(now.Add(300*time.Second).Unix()))
	require.Len(t, s.data.Audit, 3)
	c.Certificate[0] = '!'
	again, e := s.Resolve(target, original)
	require.NoError(t, e)
	assert.NotEqual(t, c.Certificate, again.Certificate)
	assert.Equal(t, cert.Serial, parseCert(t, again).Serial)
	assert.Len(t, s.data.Audit, 3)
	now = now.Add(286 * time.Second)
	expired, e := s.Resolve(target, original)
	require.NoError(t, e)
	assert.Greater(t, parseCert(t, expired).Serial, cert.Serial)
	changed := target
	changed.Username = "root"
	_, e = s.Resolve(changed, original)
	assert.ErrorIs(t, e, ErrConflict)
	prepared, e := s.Rotate(issuer.ID, "admin", issuer.Revision, "prepare-ca-001")
	require.NoError(t, e)
	assert.Equal(t, issuer.PublicKey, prepared.PublicKey)
	assert.NotEmpty(t, prepared.PendingPublicKey)
	assert.Contains(t, prepared.TrustBundle, prepared.PendingPublicKey)
	repeated, e := s.Rotate(issuer.ID, "admin", issuer.Revision, "prepare-ca-001")
	require.NoError(t, e)
	assert.Equal(t, prepared, repeated)
	stillOld, e := s.Resolve(target, original)
	require.NoError(t, e)
	assert.Equal(t, issuer.Fingerprint, xssh.FingerprintSHA256(parseCert(t, stillOld).SignatureKey))
	active, e := s.Activate(issuer.ID, "admin", prepared.Revision, "activate-ca-001")
	require.NoError(t, e)
	assert.Empty(t, active.PendingPublicKey)
	assert.NotEqual(t, issuer.Fingerprint, active.Fingerprint)
	assert.Contains(t, active.TrustBundle, issuer.PublicKey)
	after, e := s.ConnectionIdentity(target.AssetID)
	require.NoError(t, e)
	assert.NotEqual(t, before, after)
	newCredential, e := s.Resolve(target, original)
	require.NoError(t, e)
	assert.Equal(t, active.Fingerprint, xssh.FingerprintSHA256(parseCert(t, newCredential).SignatureKey))
	raw, e := os.ReadFile(s.path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "PRIVATE KEY")
	assert.NotContains(t, string(raw), issuer.PublicKey)
	s.Close()
	peer, e := Open(s.path, make([]byte, 32), nil)
	require.NoError(t, e)
	defer peer.Close()
	replay, e := peer.Bind(target, "admin", in)
	require.NoError(t, e)
	assert.Equal(t, binding, replay)
	renewed, e := peer.Resolve(target, original)
	require.NoError(t, e)
	assert.NotEqual(t, newCredential.PrivateKey, renewed.PrivateKey)
	assert.Greater(t, parseCert(t, renewed).Serial, parseCert(t, newCredential).Serial)
	disabled := active.Input
	disabled.Enabled = false
	disabled.RequestID = "disable-ca-001"
	_, e = peer.Save(active.ID, "admin", disabled)
	require.NoError(t, e)
	_, e = peer.Resolve(target, original)
	assert.ErrorIs(t, e, ErrUnavailable)
	_, e = peer.Bind(target, "admin", BindingInput{Revision: 1, RequestID: "clear-policy-001"})
	require.NoError(t, e)
	fallback, e := peer.Resolve(target, original)
	require.NoError(t, e)
	assert.Equal(t, original, fallback)
	_, e = peer.Bind(target, "admin", in)
	require.NoError(t, e)
	current, e := peer.Binding(target.AssetID)
	require.NoError(t, e)
	assert.Empty(t, current.IssuerID)
}

func TestSSHCertificateRemoteSignerPinsAuthorityPrincipalKeyTTLAndRedactsToken(t *testing.T) {
	s := certStore(t)
	ca := builtin(t, s)
	authority := s.data.Issuers[ca.ID]
	var bad atomic.Bool
	var requests atomic.Int32
	var blocked atomic.Bool
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if blocked.Load() {
			entered <- struct{}{}
			<-release
		}
		assert.Equal(t, "/v1/ssh/sign/ops", r.URL.Path)
		assert.Equal(t, "synthetic-openbao-token", r.Header.Get("X-Vault-Token"))
		var in struct {
			PublicKey  string `json:"public_key"`
			Principals string `json:"valid_principals"`
			KeyID      string `json:"key_id"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
		key, _, _, _, e := xssh.ParseAuthorizedKey([]byte(in.PublicKey))
		require.NoError(t, e)
		now := time.Now()
		cert := &xssh.Certificate{Key: key, Serial: 42, CertType: xssh.UserCert, KeyId: in.KeyID, ValidPrincipals: []string{in.Principals}, ValidAfter: uint64(now.Add(-time.Second).Unix()), ValidBefore: uint64(now.Add(120 * time.Second).Unix()), Permissions: xssh.Permissions{Extensions: map[string]string{"permit-pty": "", "permit-port-forwarding": ""}}}
		if bad.Load() {
			cert.ValidPrincipals = append(cert.ValidPrincipals, "root")
		}
		signer, e := xssh.ParsePrivateKey(authority.PrivateKey)
		require.NoError(t, e)
		require.NoError(t, cert.SignCert(rand.Reader, signer))
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"signed_key": string(xssh.MarshalAuthorizedKey(cert))}})
	}))
	defer remote.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	input := Input{Name: "Remote", Provider: "openbao", Enabled: true, TTLSeconds: 120, Endpoint: remote.URL, Mount: "ssh", Role: "ops", RootCAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: remote.Certificate().Raw})), PublicKey: ca.PublicKey, Token: "synthetic-openbao-token", RequestID: "remote-issuer-001"}
	issuer, e := s.Save("", "admin", input)
	require.NoError(t, e)
	encoded, e := json.Marshal(issuer)
	require.NoError(t, e)
	assert.NotContains(t, string(encoded), input.Token)
	assert.True(t, issuer.HasToken)
	_, e = s.Bind(certTarget(), "admin", BindingInput{IssuerID: issuer.ID, RequestID: "remote-bind-001"})
	require.NoError(t, e)
	c, e := s.Resolve(certTarget(), sshclient.Credentials{Password: "never-fallback"})
	require.NoError(t, e)
	assert.Empty(t, c.Password)
	assert.EqualValues(t, 42, parseCert(t, c).Serial)
	assert.EqualValues(t, 1, requests.Load())
	s.cache = map[string]cached{}
	bad.Store(true)
	_, e = s.Resolve(certTarget(), sshclient.Credentials{Password: "never-fallback"})
	assert.ErrorIs(t, e, ErrUnavailable)
	stored, e := os.ReadFile(s.path)
	require.NoError(t, e)
	assert.NotContains(t, string(stored), input.Token)
	bad.Store(false)
	blocked.Store(true)
	resolved := make(chan error, 1)
	go func() {
		_, e := s.Resolve(certTarget(), sshclient.Credentials{Password: "never-fallback"})
		resolved <- e
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("signer did not receive the pending request")
	}
	update := issuer.Input
	update.Enabled = false
	update.RequestID = "disable-during-sign-001"
	managed := make(chan error, 1)
	go func() { _, e := s.Save(issuer.ID, "admin", update); managed <- e }()
	select {
	case e := <-managed:
		require.NoError(t, e)
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("remote signing held the configuration lock")
	}
	close(release)
	assert.ErrorIs(t, <-resolved, ErrConflict)
}

func TestSSHCertificateValidationAtomicWriteAndUnknownFormat(t *testing.T) {
	s := certStore(t)
	for _, in := range []Input{{Name: "bad", Provider: "builtin", TTLSeconds: 601, RequestID: "invalid-ca-001"}, {Name: "bad", Provider: "builtin", Token: "unexpected", RequestID: "invalid-ca-001"}, {Name: "remote", Provider: "openbao", Endpoint: "http://192.0.2.1", RequestID: "invalid-ca-001"}} {
		_, e := s.Save("", "admin", in)
		assert.ErrorIs(t, e, ErrInvalid)
	}
	path := s.path
	s.path = filepath.Dir(path)
	_, e := s.Save("", "admin", Input{Name: "Atomic", Provider: "builtin", Enabled: true, RequestID: "atomic-ca-001"})
	require.Error(t, e)
	s.path = path
	rows, e := s.Issuers()
	require.NoError(t, e)
	assert.Empty(t, rows)
	issuer := builtin(t, s)
	_, e = s.Bind(certTarget(), "admin", BindingInput{IssuerID: issuer.ID, RequestID: "atomic-bind-001"})
	require.NoError(t, e)
	assert.ErrorIs(t, s.Delete(issuer.ID, "admin", issuer.Revision, "delete-ca-001"), ErrInUse)
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	_, e = Open(path, bytes.Repeat([]byte{1}, 32), nil)
	assert.ErrorIs(t, e, ErrInvalid)
	var box envelope
	require.NoError(t, json.Unmarshal(raw, &box))
	box.Version = 2
	raw, e = json.Marshal(box)
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(path, raw, 0600))
	_, e = Open(path, make([]byte, 32), nil)
	assert.ErrorIs(t, e, ErrInvalid)
}

func TestSSHCertificatePostgresTenantScopeAndCounterTakeover(t *testing.T) {
	database := os.Getenv("JMS_TEST_DATABASE_URL")
	if database == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for certificate PostgreSQL integration")
	}
	docs, e := storage.OpenPostgres(context.Background(), database, fmt.Sprintf("certificates-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	defer docs.Close()
	a, e := docs.Scoped("cert-org-a")
	require.NoError(t, e)
	b, e := docs.Scoped("cert-org-b")
	require.NoError(t, e)
	defer a.Delete("ssh-certificates")
	defer b.Delete("ssh-certificates")
	path := filepath.Join(t.TempDir(), "ssh-certificates.json")
	s, e := Open(path, make([]byte, 32), a)
	require.NoError(t, e)
	issuer := builtin(t, s)
	_, e = s.Bind(certTarget(), "admin", BindingInput{IssuerID: issuer.ID, RequestID: "pg-cert-bind-001"})
	require.NoError(t, e)
	first, e := s.Resolve(certTarget(), sshclient.Credentials{})
	require.NoError(t, e)
	s.Close()
	peer, e := Open(path, make([]byte, 32), a)
	require.NoError(t, e)
	defer peer.Close()
	next, e := peer.Resolve(certTarget(), sshclient.Credentials{})
	require.NoError(t, e)
	assert.Greater(t, parseCert(t, next).Serial, parseCert(t, first).Serial)
	other, e := Open(filepath.Join(t.TempDir(), "ssh-certificates.json"), make([]byte, 32), b)
	require.NoError(t, e)
	defer other.Close()
	rows, e := other.Issuers()
	require.NoError(t, e)
	assert.Empty(t, rows)
	_, e = docs.Load("ssh-certificates")
	assert.ErrorIs(t, e, storage.ErrDocumentNotFound)
	assert.NotContains(t, issuer.TrustBundle, "PRIVATE")
}
