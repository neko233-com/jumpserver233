package main

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
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
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshidentity"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
	xssh "golang.org/x/crypto/ssh"
)

type keyFailoverProof struct {
	ID          string
	Fingerprint string
	Old         sshclient.Credentials
	New         sshclient.Credentials
	Target      sshclient.Target
}

// Seed the dedicated QA namespace immediately before stopping its primary.
// No production path writes through a second asset store while a node is active.
func prepareKeyFailover(t *testing.T, documents *storage.Documents, root string, vaultKey []byte, setCleanup func(func())) *keyFailoverProof {
	return prepareKeyFailoverAccount(t, documents, root, vaultKey, setCleanup, "keyha", "ha-pending-ssh-key")
}
func prepareKeyFailoverAccount(t *testing.T, documents *storage.Documents, root string, vaultKey []byte, setCleanup func(func()), username, assetID string) *keyFailoverProof {
	t.Helper()
	address := os.Getenv("JMS_TEST_KEY_HOST_ADDR")
	if address == "" {
		return nil
	}
	require.True(t, strings.HasPrefix(os.Getenv("JMS_TEST_KEY_HOST_NAME"), "jms233-keyhost-"))
	fingerprint := os.Getenv("JMS_TEST_KEY_HOST_FINGERPRINT")
	host, portText, e := net.SplitHostPort(address)
	require.NoError(t, e)
	port, e := strconv.Atoi(portText)
	require.NoError(t, e)
	connect := func() (*xssh.Client, *sftp.Client, error) {
		client, e := xssh.Dial("tcp", address, &xssh.ClientConfig{User: username, Auth: []xssh.AuthMethod{xssh.Password("synthetic-keyhost-password-233")}, HostKeyCallback: func(_ string, _ net.Addr, key xssh.PublicKey) error {
			if xssh.FingerprintSHA256(key) != fingerprint {
				return errors.New("fixture host key mismatch")
			}
			return nil
		}, Timeout: 5 * time.Second})
		if e != nil {
			return nil, nil, e
		}
		remote, e := sftp.NewClient(client)
		if e != nil {
			_ = client.Close()
			return nil, nil, e
		}
		return client, remote, nil
	}
	client, remote, e := connect()
	require.NoError(t, e)
	defer client.Close()
	defer remote.Close()
	home, e := remote.RealPath(".")
	require.NoError(t, e)
	filename := path.Join(home, ".ssh", "authorized_keys")
	file, e := remote.Open(filename)
	require.NoError(t, e)
	original, e := io.ReadAll(file)
	require.NoError(t, e)
	require.NoError(t, file.Close())
	setCleanup(func() {
		client, remote, e := connect()
		if e != nil {
			t.Errorf("reconnect dedicated HA key fixture: %v", e)
			return
		}
		defer client.Close()
		defer remote.Close()
		_ = remote.Remove(path.Join(home, ".ssh", ".jumpserver233-key.lock"))
		file, e := remote.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		if e == nil {
			_, e = file.Write(original)
			_ = file.Chmod(0600)
			_ = file.Close()
		}
		if e != nil {
			t.Errorf("restore dedicated HA key fixture: %v", e)
		}
	})
	oldKey, oldFingerprint, e := sshclient.ImportPrivateKey(sshidentity.PEM(""), "")
	require.NoError(t, e)
	oldPublic := sshidentity.Signer().PublicKey()
	file, e = remote.OpenFile(filename, os.O_WRONLY|os.O_APPEND)
	require.NoError(t, e)
	_, e = file.Write([]byte("no-agent-forwarding " + strings.TrimSpace(string(xssh.MarshalAuthorizedKey(oldPublic))) + " HA fixture\n"))
	require.NoError(t, e)
	require.NoError(t, file.Sync())
	require.NoError(t, file.Close())
	store, e := coreassets.OpenStoreWithDocuments(filepath.Join(root, "assets.json"), vaultKey, documents)
	require.NoError(t, e)
	now := time.Now().UTC()
	asset, e := store.CreateCredentials(coreassets.Asset{ID: assetID, Name: "HA pending SSH key", Host: host, Port: port, Username: username, HostKeyFingerprint: fingerprint, CredentialType: coreassets.CredentialSSHKey, KeyFingerprint: oldFingerprint, CreatedAt: now, UpdatedAt: now}, sshclient.Credentials{PrivateKey: oldKey})
	require.NoError(t, e)
	_, private, e := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, e)
	block, e := xssh.MarshalPrivateKey(private, "")
	require.NoError(t, e)
	newKey, newFingerprint, e := sshclient.ImportPrivateKey(pem.EncodeToMemory(block), "")
	require.NoError(t, e)
	next := sshclient.Credentials{PrivateKey: newKey}
	p, _, done, e := store.BeginSSHKeyChange(asset.ID, "ha-key-takeover-request", asset.CredentialRevision, "ha-fixture", next, newFingerprint)
	require.NoError(t, e)
	require.False(t, done)
	target := sshclient.Target{Host: host, Port: port, Username: username, HostKeyFingerprint: fingerprint}
	updater, e := sshclient.OpenAuthorizedKeys(context.Background(), target, sshclient.Credentials{PrivateKey: oldKey}, p.OperationID)
	require.NoError(t, e)
	defer updater.Close()
	nextSigner, e := xssh.ParsePrivateKey(newKey)
	require.NoError(t, e)
	plan, e := updater.Prepare(oldPublic.Marshal(), nextSigner.PublicKey().Marshal())
	require.NoError(t, e)
	require.NoError(t, store.SaveSSHKeyPlan(asset.ID, p.OperationID, plan))
	require.NoError(t, updater.Install(plan))
	require.NoError(t, sshclient.VerifyPassword(context.Background(), target, next, time.Second))
	require.NoError(t, store.CommitSSHKeyChange(asset.ID, p.OperationID))
	require.NoError(t, store.RecordSSHKeyAttempt(asset.ID, "", time.Now().Add(-2*time.Hour)))
	return &keyFailoverProof{ID: asset.ID, Fingerprint: newFingerprint, Old: sshclient.Credentials{PrivateKey: oldKey}, New: next, Target: target}
}

func prepareSharedKeyFailover(t *testing.T, documents *storage.Documents, root string, key []byte, organization string, setCleanup func(func())) (*keyFailoverProof, string) {
	proof := prepareKeyFailoverAccount(t, documents, root, key, setCleanup, "sharedkeyha", "ha-shared-ssh-key")
	if proof == nil {
		return nil, ""
	}
	d, e := documents.Scoped(organization)
	require.NoError(t, e)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("jms233/organization-vault/v1\x00" + organization))
	orgKey := mac.Sum(nil)
	st, e := coreassets.OpenStoreWithDocuments(filepath.Join(root, "organizations", organization, "assets.json"), orgKey, d)
	require.NoError(t, e)
	now := time.Now().UTC()
	peer, e := st.CreateCredentials(coreassets.Asset{ID: "ha-shared-ssh-key-peer", Name: "HA shared key peer", Host: proof.Target.Host, Port: proof.Target.Port, Username: proof.Target.Username, HostKeyFingerprint: proof.Target.HostKeyFingerprint, CredentialType: coreassets.CredentialSSHKey, CreatedAt: now, UpdatedAt: now}, proof.Old)
	require.NoError(t, e)
	return proof, peer.ID
}
