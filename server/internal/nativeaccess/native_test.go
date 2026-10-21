package nativeaccess

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNativeSearchTitleDescriptionIPAndAccount(t *testing.T) {
	rows := []assetChoice{{ID: "a", Title: "生产 API", Desc: "Shanghai database", IP: "192.0.2.8", Account: "ops"}, {ID: "b", Title: "staging", Desc: "backup", IP: "198.51.100.2", Account: "root"}}
	for _, query := range []string{"生产", "api", "SHANGHAI", "192.0.2", "生产 database", "ops"} {
		result := filterAssets(rows, query)
		require.Len(t, result, 1)
		require.Equal(t, "a", result[0].ID)
	}
	require.Len(t, filterAssets(rows, ""), 2)
	require.Empty(t, filterAssets(rows, "production root"))
	require.NotContains(t, safeLabel("a\x1b[31m\r\nb"), "\x1b")
	require.NotContains(t, safeLabel("x\n"), "\n")
}
func TestNativeVirtualPathsAndIdentities(t *testing.T) {
	for _, value := range []string{"/../secret", "/asset/../../etc/passwd", "/asset/..", "/asset/a\\b", "/asset/a\x00b", "/%bad/file"} {
		_, _, e := virtualPath(value)
		require.Error(t, e, value)
	}
	id, name, e := virtualPath("/asset-id/folder/中文.txt")
	require.NoError(t, e)
	require.Equal(t, "asset-id", id)
	require.Equal(t, "folder/中文.txt", name)
	user, org, e := splitUsername("root")
	require.NoError(t, e)
	require.Equal(t, "root", user)
	require.Empty(t, org)
	_, _, e = splitUsername("root%bad")
	require.Error(t, e)
	for _, size := range [][2]uint32{{0, 24}, {501, 24}, {80, 0}, {80, 501}} {
		require.False(t, validSize(size[0], size[1]))
	}
	require.True(t, validSize(80, 24))
}
func TestNativeInternalTransportRetainsPeerAndRejectsExternalAuthority(t *testing.T) {
	peer := &net.TCPAddr{IP: net.ParseIP("192.0.2.33"), Port: 23456}
	transport := newHandlerTransport(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, peer.String(), r.RemoteAddr)
		_, _ = io.WriteString(w, r.Host)
	}), peer)
	defer transport.Close()
	r, e := transport.client.Get(apiOrigin + "/probe")
	require.NoError(t, e)
	data, e := io.ReadAll(r.Body)
	r.Body.Close()
	require.NoError(t, e)
	require.Equal(t, "native.ssh.invalid", string(data))
	_, e = transport.client.Get("http://192.0.2.99/")
	require.Error(t, e)
	transport.Close()
	_, e = transport.client.Get(apiOrigin)
	require.Error(t, e)
}
func TestNativeHostKeyAndUploadRangesAreStableAndIsolated(t *testing.T) {
	handler := http.NotFoundHandler()
	key := []byte(strings.Repeat("a", 32))
	a, e := New(handler, key, nil)
	require.NoError(t, e)
	defer a.Close()
	b, e := New(handler, key, nil)
	require.NoError(t, e)
	defer b.Close()
	require.Equal(t, a.Fingerprint(), b.Fingerprint())
	c, e := New(handler, []byte(strings.Repeat("b", 32)), nil)
	require.NoError(t, e)
	defer c.Close()
	require.NotEqual(t, a.Fingerprint(), c.Fingerprint())
	u := &nativeUpload{}
	u.addRange(4, 8)
	u.addRange(0, 4)
	u.addRange(2, 6)
	require.Equal(t, []byteRange{{0, 8}}, u.ranges)
	u.addRange(12, 16)
	require.Len(t, u.ranges, 2)
	u.addRange(8, 12)
	require.Equal(t, []byteRange{{0, 16}}, u.ranges)
	require.NoError(t, a.Close())
	require.NoError(t, a.Close())
	_, e = os.Stat(a.temp)
	require.True(t, os.IsNotExist(e))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	in := &channelInput{ctx: ctx, data: make(chan inputBlock)}
	_, e = in.next(ctx)
	require.ErrorIs(t, e, context.Canceled)
}

func TestNativeSpoolCleanupProtectsLiveLeaseAndRemovesAbandonedOwnedData(t *testing.T) {
	identity := fmt.Sprint(time.Now().UnixNano())
	old, lease, e := openSpool(identity)
	require.NoError(t, e)
	active, live, e := openSpool(identity)
	require.NoError(t, e)
	defer removeSpool(active, live)
	_, e = os.Stat(old)
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(filepath.Join(old, "upload-owned"), []byte("owned test data"), 0600))
	require.NoError(t, lease.Close())
	next, lease2, e := openSpool(identity)
	require.NoError(t, e)
	defer removeSpool(next, lease2)
	_, e = os.Stat(old)
	require.True(t, os.IsNotExist(e))
	_, e = os.Stat(active)
	require.NoError(t, e)
	require.NoError(t, removeSpool(next, lease2))
	require.NoError(t, removeSpool(next, lease2))
}
