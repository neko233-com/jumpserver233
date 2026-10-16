package assets

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshidentity"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xssh "golang.org/x/crypto/ssh"
)

func TestRealOpenSSHSharedKeyCohortCommitsBeforeRetirement(t *testing.T) {
	address := os.Getenv("JMS_TEST_KEY_HOST_ADDR")
	if address == "" {
		t.Skip("set JMS_TEST_KEY_HOST_ADDR for disposable shared SSH key integration")
	}
	require.True(t, strings.HasPrefix(os.Getenv("JMS_TEST_KEY_HOST_NAME"), "jms233-keyhost-"))
	host, portText, e := net.SplitHostPort(address)
	require.NoError(t, e)
	port, e := strconv.Atoi(portText)
	require.NoError(t, e)
	fingerprint := os.Getenv("JMS_TEST_KEY_HOST_FINGERPRINT")
	transport, e := xssh.Dial("tcp", address, &xssh.ClientConfig{User: "sharedkeyqa", Auth: []xssh.AuthMethod{xssh.Password("synthetic-keyhost-password-233")}, HostKeyCallback: func(_ string, _ net.Addr, k xssh.PublicKey) error {
		if xssh.FingerprintSHA256(k) != fingerprint {
			return errors.New("fixture fingerprint mismatch")
		}
		return nil
	}, Timeout: 5 * time.Second})
	require.NoError(t, e)
	defer transport.Close()
	remote, e := sftp.NewClient(transport)
	require.NoError(t, e)
	defer remote.Close()
	home, e := remote.RealPath(".")
	require.NoError(t, e)
	file := path.Join(home, ".ssh", "authorized_keys")
	f, e := remote.Open(file)
	require.NoError(t, e)
	original, e := io.ReadAll(f)
	require.NoError(t, e)
	require.NoError(t, f.Close())
	write := func(raw []byte) error {
		f, e := remote.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		if e != nil {
			return e
		}
		defer f.Close()
		if _, e = f.Write(raw); e != nil {
			return e
		}
		if e = f.Chmod(0600); e != nil {
			return e
		}
		return f.Sync()
	}
	defer func() { assert.NoError(t, write(original)) }()
	oldLine := strings.TrimSpace(string(xssh.MarshalAuthorizedKey(sshidentity.Signer().PublicKey())))
	require.NoError(t, write([]byte("# preserved shared key fixture\nno-agent-forwarding "+oldLine+" original-shared-key\n")))
	c, e := OpenPasswordCoordinator(filepath.Join(t.TempDir(), "shared-passwords.json"), make([]byte, 32), nil)
	require.NoError(t, e)
	services := []*Service{}
	assets := []Asset{}
	for i, scope := range []string{"default", "other"} {
		key := make([]byte, 32)
		key[0] = byte(i)
		st, e := OpenStore(filepath.Join(t.TempDir(), "assets.json"), key)
		require.NoError(t, e)
		s := NewService(st, nil)
		a, e := s.Create(Input{Name: "Real shared SSH key", Host: host, Port: port, Username: "sharedkeyqa", HostKeyFingerprint: fingerprint, CredentialType: CredentialSSHKey, PrivateKey: string(sshidentity.PEM(""))})
		require.NoError(t, e)
		require.NoError(t, s.CoordinatePasswords(c, scope))
		services = append(services, s)
		assets = append(assets, a)
	}
	services[0].keyUpdater = func(ctx context.Context, target sshclient.Target, key sshclient.Credentials, id string) (KeyUpdater, error) {
		u, e := sshclient.OpenAuthorizedKeys(ctx, target, key, id)
		if e != nil {
			return nil, e
		}
		return &keyRetirementCheck{KeyUpdater: u, beforeRetire: func() {
			for i, s := range services {
				a, e := s.Get(assets[i].ID)
				require.NoError(t, e)
				assert.NotEqual(t, assets[i].KeyFingerprint, a.KeyFingerprint)
				assert.EqualValues(t, 2, a.CredentialRevision)
			}
		}}, nil
	}
	item, e := services[0].RotateSSHKey(context.Background(), assets[0].ID, "real-shared-key-rotate", 1, "integration.user")
	require.NoError(t, e)
	for i, s := range services {
		a, e := s.Get(assets[i].ID)
		require.NoError(t, e)
		assert.Equal(t, item.KeyFingerprint, a.KeyFingerprint)
		_, target, key, e := s.store.connection(a.ID)
		require.NoError(t, e)
		require.NoError(t, sshclient.VerifyPassword(context.Background(), target, key, time.Second))
		result, e := s.Exec(context.Background(), a.ID, "printf shared-key-ok")
		require.NoError(t, e)
		assert.Equal(t, "shared-key-ok", result.Stdout)
		assert.False(t, s.store.HasPendingSSHKeyChange(a.ID))
	}
	_, target, _, e := services[0].store.connection(assets[0].ID)
	require.NoError(t, e)
	assert.Error(t, sshclient.VerifyPassword(context.Background(), target, sshclient.Credentials{PrivateKey: sshidentity.PEM("")}, time.Second))
	f, e = remote.Open(file)
	require.NoError(t, e)
	contents, e := io.ReadAll(f)
	require.NoError(t, e)
	require.NoError(t, f.Close())
	assert.Contains(t, string(contents), "# preserved shared key fixture")
	assert.Contains(t, string(contents), "no-agent-forwarding ")
	assert.NotContains(t, string(contents), oldLine)
	assert.Empty(t, c.keys.ops)
}

func TestSharedSSHKeyPostgresEncryptedCleanupResumesAcrossStoreReopen(t *testing.T) {
	url := os.Getenv("JMS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for shared SSH key PostgreSQL recovery")
	}
	docs, e := storage.OpenPostgres(context.Background(), url, "shared-key-"+strconv.FormatInt(time.Now().UnixNano(), 10))
	require.NoError(t, e)
	defer docs.Close()
	c, e := OpenPasswordCoordinator(filepath.Join(t.TempDir(), "coordinator.json"), make([]byte, 32), docs)
	require.NoError(t, e)
	old, fp, e := generateSSHKey()
	require.NoError(t, e)
	host := &fakeKeyHost{allowed: map[string]bool{fp: true}, failRetire: true}
	services := []*Service{}
	assetID := "postgres-shared-key"
	for i, scope := range []string{"first", "second"} {
		d, e := docs.Scoped(scope)
		require.NoError(t, e)
		defer d.Delete("assets")
		key := make([]byte, 32)
		key[0] = byte(i)
		st, e := OpenStoreWithDocuments(filepath.Join(t.TempDir(), "assets.json"), key, d)
		require.NoError(t, e)
		_, e = st.CreateCredentials(Asset{ID: assetID, Name: "PG shared key", Host: "host.invalid", Port: 22, Username: "ops", HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", CredentialType: CredentialSSHKey}, old)
		require.NoError(t, e)
		s := NewService(st, nil)
		wireFakeKeys(s, host)
		require.NoError(t, s.CoordinatePasswords(c, scope))
		services = append(services, s)
	}
	_, e = services[0].RotateSSHKey(context.Background(), assetID, "pg-shared-key-rotate", 1, "fixture")
	require.ErrorIs(t, e, ErrSSHKeyRotationFailed)
	require.Len(t, c.keys.ops, 1)
	raw, e := docs.Load("shared-keys")
	require.NoError(t, e)
	assert.True(t, json.Valid(raw))
	assert.NotContains(t, string(raw), assetID)
	assert.NotContains(t, string(raw), "PRIVATE KEY")
	reopened, e := OpenPasswordCoordinator(filepath.Join(t.TempDir(), "coordinator.json"), make([]byte, 32), docs)
	require.NoError(t, e)
	host.failRetire = false
	for i, scope := range []string{"first", "second"} {
		d, e := docs.Scoped(scope)
		require.NoError(t, e)
		key := make([]byte, 32)
		key[0] = byte(i)
		st, e := OpenStoreWithDocuments(filepath.Join(t.TempDir(), "assets.json"), key, d)
		require.NoError(t, e)
		s := NewService(st, nil)
		wireFakeKeys(s, host)
		require.NoError(t, s.CoordinatePasswords(reopened, scope))
		services[i] = s
	}
	services[0].RecoverPendingSSHKeyChanges(context.Background())
	assert.Empty(t, reopened.keys.ops)
	assert.False(t, host.allowed[fp])
	a, e := services[0].Get(assetID)
	require.NoError(t, e)
	b, e := services[1].Get(assetID)
	require.NoError(t, e)
	assert.Equal(t, a.KeyFingerprint, b.KeyFingerprint)
	assert.NotEqual(t, fp, a.KeyFingerprint)
	require.NoError(t, docs.Delete("shared-keys"))
}
