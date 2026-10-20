package replaystore

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRealReplayObjectSFTPExclusiveUploadReadbackAndOwnedCleanup(t *testing.T) {
	address := os.Getenv("JMS_TEST_KEY_HOST_ADDR")
	pin := os.Getenv("JMS_TEST_KEY_HOST_FINGERPRINT")
	if address == "" || pin == "" {
		t.Skip("set the disposable OpenSSH fixture address and fingerprint")
	}
	host, p, e := net.SplitHostPort(address)
	require.NoError(t, e)
	port, e := strconv.Atoi(p)
	require.NoError(t, e)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	remote, e := sshclient.OpenSFTP(ctx, sshclient.Target{Host: host, Port: port, Username: "keyqa", HostKeyFingerprint: pin}, sshclient.Credentials{Password: "synthetic-keyhost-password-233"}, 3*time.Second)
	require.NoError(t, e)
	defer remote.Close()
	directory := fmt.Sprintf("replayqa-%d", time.Now().UnixNano())
	backend, e := NewSFTP(remote, directory)
	require.NoError(t, e)
	defer backend.Close()
	key := "session/object.enc"
	owned := path.Join(remote.Root(), directory)
	defer func() {
		clean, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		_ = remote.Remove(clean, path.Join(owned, key))
		_ = remote.RemoveDirectory(clean, path.Join(owned, "session"))
		_ = remote.RemoveDirectory(clean, owned)
	}()
	data := []byte("JMSREC1\nopaque encrypted replay")
	require.NoError(t, backend.Put(ctx, key, bytes.NewReader(data), int64(len(data)), testDigest(data)))
	require.ErrorIs(t, backend.Put(ctx, key, bytes.NewReader(data), int64(len(data)), testDigest(data)), ErrExists)
	r, e := backend.Get(ctx, key)
	require.NoError(t, e)
	actual, e := io.ReadAll(r)
	require.NoError(t, e)
	require.NoError(t, r.Close())
	assert.Equal(t, data, actual)
	_, e = backend.Get(ctx, "../escape")
	assert.ErrorIs(t, e, ErrInvalid)
	assert.ErrorIs(t, backend.Put(ctx, "session/wrong.enc", bytes.NewReader(data), int64(len(data)), strings.Repeat("a", 64)), ErrIntegrity)
	entries, e := remote.ReadDir(ctx, path.Join(owned, "session"))
	require.NoError(t, e)
	require.Len(t, entries, 1)
	assert.Equal(t, "object.enc", entries[0].Name)
}
