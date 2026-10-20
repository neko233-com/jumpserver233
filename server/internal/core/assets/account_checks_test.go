package assets

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/rotationplans"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xssh "golang.org/x/crypto/ssh"
)

type accountCheckSSH struct {
	port          int
	password      atomic.Value
	authenticated atomic.Int32
	channels      atomic.Int32
	fingerprint   string
	privateKey    string
}

func newAccountCheckSSH(t *testing.T, beforeAuth func()) *accountCheckSSH {
	t.Helper()
	public, private, e := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, e)
	signer, e := xssh.NewSignerFromKey(private)
	require.NoError(t, e)
	userPublic, userPrivate, e := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, e)
	userSigner, e := xssh.NewSignerFromKey(userPrivate)
	require.NoError(t, e)
	_ = public
	_ = userPublic
	raw, e := x509.MarshalPKCS8PrivateKey(userPrivate)
	require.NoError(t, e)
	f := &accountCheckSSH{fingerprint: xssh.FingerprintSHA256(signer.PublicKey()), privateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))}
	f.password.Store("synthetic-account-check-password")
	accept := func() {
		if beforeAuth != nil {
			beforeAuth()
		}
		f.authenticated.Add(1)
	}
	config := &xssh.ServerConfig{PasswordCallback: func(meta xssh.ConnMetadata, password []byte) (*xssh.Permissions, error) {
		if meta.User() != "check-user" || string(password) != f.password.Load().(string) {
			return nil, errors.New("synthetic authentication rejected")
		}
		accept()
		return nil, nil
	}, PublicKeyCallback: func(meta xssh.ConnMetadata, key xssh.PublicKey) (*xssh.Permissions, error) {
		if meta.User() != "check-user" || !bytes.Equal(key.Marshal(), userSigner.PublicKey().Marshal()) {
			return nil, errors.New("synthetic key rejected")
		}
		accept()
		return nil, nil
	}}
	config.AddHostKey(signer)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, e)
	_, port, e := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, e)
	f.port, e = strconv.Atoi(port)
	require.NoError(t, e)
	var wg sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			connection, e := listener.Accept()
			if e != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
				server, channels, requests, e := xssh.NewServerConn(connection, config)
				if e != nil {
					return
				}
				defer server.Close()
				go xssh.DiscardRequests(requests)
				for channel := range channels {
					f.channels.Add(1)
					_ = channel.Reject(xssh.Prohibited, "no remote session is permitted")
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-acceptDone; wg.Wait() })
	return f
}
func checkService(t *testing.T, server *accountCheckSSH, key bool) (*Service, *Store, Asset) {
	t.Helper()
	store, e := OpenStore(filepath.Join(t.TempDir(), "assets.json"), make([]byte, 32))
	require.NoError(t, e)
	s := NewService(store, func(context.Context, sshclient.Target, sshclient.Credentials, time.Duration) (sshclient.Metrics, error) {
		return sshclient.Metrics{}, nil
	})
	input := Input{Name: "Synthetic check", Host: "127.0.0.1", Port: server.port, Username: "check-user", HostKeyFingerprint: server.fingerprint, Password: server.password.Load().(string)}
	if key {
		input.Password = ""
		input.CredentialType = "ssh_key"
		input.PrivateKey = server.privateKey
	}
	a, e := s.Create(input)
	require.NoError(t, e)
	return s, store, a
}

func TestAccountCheckRealPasswordAndKeyAuthenticationOpenNoSessionAndChangeNothing(t *testing.T) {
	for _, key := range []bool{false, true} {
		t.Run(map[bool]string{false: "password", true: "key"}[key], func(t *testing.T) {
			server := newAccountCheckSSH(t, nil)
			s, store, a := checkService(t, server, key)
			intent := managedIntent(t, s, a.ID, "", "account-check-auth")
			store.mu.RLock()
			before := store.assets[a.ID].Credential
			store.mu.RUnlock()
			out, e := s.CheckManagedAccount(context.Background(), intent, func() error { return nil })
			require.NoError(t, e)
			assert.Equal(t, "succeeded", out.State)
			assert.Positive(t, out.CheckDurationMS)
			assert.Zero(t, out.Revision)
			current, e := s.Get(a.ID)
			require.NoError(t, e)
			assert.Equal(t, a.CredentialRevision, current.CredentialRevision)
			store.mu.RLock()
			after := store.assets[a.ID].Credential
			store.mu.RUnlock()
			assert.True(t, bytes.Equal(before.Ciphertext, after.Ciphertext) && bytes.Equal(before.Nonce, after.Nonce))
			assert.Zero(t, server.channels.Load())
			assert.Positive(t, server.authenticated.Load())
			public, _ := json.Marshal(out)
			assert.False(t, strings.Contains(string(public), server.privateKey) || strings.Contains(string(public), server.password.Load().(string)))
		})
	}
}

func TestAccountCheckRejectsBadCredentialsPendingWorkRevocationAndClosedAdmission(t *testing.T) {
	server := newAccountCheckSSH(t, nil)
	s, store, a := checkService(t, server, false)
	intent := managedIntent(t, s, a.ID, "", "account-check-negative")
	server.password.Store("different-synthetic-remote-password")
	out, e := s.CheckManagedAccount(context.Background(), intent, func() error { return nil })
	require.Error(t, e)
	assert.Equal(t, "authentication_failed", out.Code)
	assert.Zero(t, server.channels.Load())
	server.password.Store("synthetic-account-check-password")
	_, e = s.CheckManagedAccount(context.Background(), intent, func() error { return rotationplans.ErrDenied })
	assert.ErrorIs(t, e, rotationplans.ErrDenied)
	assert.Zero(t, server.authenticated.Load())
	gate := workgate.New()
	store.SetAdmissionGate(gate)
	gate.SetClosed(true)
	_, e = s.CheckManagedAccount(context.Background(), intent, func() error { return nil })
	require.Error(t, e)
	assert.Zero(t, server.authenticated.Load())
	gate.SetClosed(false)
	require.NoError(t, store.BeginPasswordRotation(a.ID, "synthetic-check-pending-password", time.Now().UTC()))
	out, e = s.CheckManagedAccount(context.Background(), intent, func() error { return nil })
	require.Error(t, e)
	assert.Equal(t, "credential_pending", out.Code)
	assert.Zero(t, server.authenticated.Load())
}

func TestAccountCheckPinsHostKeysAndRejectsMetadataChangedDuringAuthentication(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	server := newAccountCheckSSH(t, func() { once.Do(func() { close(entered); <-release }) })
	s, _, a := checkService(t, server, false)
	intent := managedIntent(t, s, a.ID, "", "account-check-source")
	done := make(chan struct {
		out rotationplans.Outcome
		e   error
	}, 1)
	go func() {
		out, e := s.CheckManagedAccount(context.Background(), intent, func() error { return nil })
		done <- struct {
			out rotationplans.Outcome
			e   error
		}{out, e}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("SSH authentication did not start")
	}
	_, e := s.Update(a.ID, Input{Name: "Changed source metadata", Host: a.Host, Port: a.Port, Username: a.Username, HostKeyFingerprint: a.HostKeyFingerprint})
	close(release)
	require.NoError(t, e)
	result := <-done
	assert.ErrorIs(t, result.e, ErrCredentialChanged)
	assert.Equal(t, "changed", result.out.State)
	assert.Zero(t, server.channels.Load())
	_, private, e := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, e)
	other, e := xssh.NewSignerFromKey(private)
	require.NoError(t, e)
	_, e = s.Update(a.ID, Input{Name: "Wrong host pin", Host: a.Host, Port: a.Port, Username: a.Username, HostKeyFingerprint: xssh.FingerprintSHA256(other.PublicKey())})
	require.NoError(t, e)
	wrong := managedIntent(t, s, a.ID, "", "account-check-pin")
	out, e := s.CheckManagedAccount(context.Background(), wrong, func() error { return nil })
	require.Error(t, e)
	assert.Equal(t, "host_key_mismatch", out.Code)
	assert.Zero(t, server.channels.Load())
}
