package hostplugins

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func sha(raw []byte) string                                           { v := sha256.Sum256(raw); return hex.EncodeToString(v[:]) }
func TestCatalogPinsOfficialArtifactsAndRejectsUnknownPlatforms(t *testing.T) {
	require.Len(t, Catalog(), 2)
	for _, d := range Catalog() {
		for _, a := range d.Artifacts {
			u, e := url.Parse(a.URL)
			require.NoError(t, e)
			require.True(t, releaseURL(u))
			require.True(t, validDigest(a.SHA256))
			require.Contains(t, a.URL, "/v"+d.Version+"/")
		}
	}
	for _, input := range [][2]string{{"Linux", "x86_64"}, {"Darwin", "aarch64"}} {
		_, e := Platform(input[0], input[1])
		require.NoError(t, e)
	}
	for _, input := range [][2]string{{"Linux", "mips"}, {"Windows", "amd64"}, {"Linux; id", "amd64"}} {
		_, e := Platform(input[0], input[1])
		require.ErrorIs(t, e, ErrUnsupported)
	}
	_, e := Lookup("banhack233;id")
	require.ErrorIs(t, e, ErrInvalid)
}
func TestArtifactCacheIntegrityCancellationAndRedirectBoundaries(t *testing.T) {
	c, e := NewCache(t.TempDir())
	require.NoError(t, e)
	content := []byte("synthetic verified executable")
	var requests atomic.Int32
	c.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		requests.Add(1)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(content)), Request: r}, nil
	})
	a := Artifact{URL: "https://github.com/approved/release/executable", SHA256: sha(content)}
	b, e := c.Fetch(context.Background(), a)
	require.NoError(t, e)
	require.Equal(t, sha(content), b.SHA256)
	_, e = c.Fetch(context.Background(), a)
	require.NoError(t, e)
	require.EqualValues(t, 1, requests.Load())
	require.NoError(t, os.WriteFile(b.Path, []byte("damaged cache"), 0600))
	_, e = c.Fetch(context.Background(), a)
	require.NoError(t, e)
	require.EqualValues(t, 2, requests.Load())
	a.SHA256 = strings.Repeat("a", 64)
	_, e = c.Fetch(context.Background(), a)
	require.ErrorIs(t, e, ErrIntegrity)
	for _, u := range []string{"http://github.com/file", "https://github.com@127.0.0.1/file", "https://127.0.0.1/file", "https://github.com:444/file"} {
		a.URL = u
		_, e = c.Fetch(context.Background(), a)
		require.ErrorIs(t, e, ErrInvalid)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = c.Fetch(ctx, a)
	require.ErrorIs(t, e, context.Canceled)
	a.URL = "https://github.com/approved/redirect"
	a.SHA256 = sha(content)
	c.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"http://127.0.0.1/private"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})
	// A different digest forces a network request instead of using the verified cache.
	a.SHA256 = strings.Repeat("b", 64)
	_, e = c.Fetch(context.Background(), a)
	require.Error(t, e)
}
func archiveFixture(t *testing.T, headers []tar.Header, payload []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tr := tar.NewWriter(gz)
	for _, h := range headers {
		require.NoError(t, tr.WriteHeader(&h))
		if h.Typeflag == tar.TypeReg {
			_, e := tr.Write(payload[:int(h.Size)])
			require.NoError(t, e)
		}
	}
	require.NoError(t, tr.Close())
	require.NoError(t, gz.Close())
	return b.Bytes()
}
func TestArchiveSelectsExactBinaryAndRejectsTraversalLinksDuplicatesOrDamage(t *testing.T) {
	root := t.TempDir()
	entry := "tool-1.linux-amd64/tool"
	payload := []byte("native ELF fixture")
	header := tar.Header{Name: entry, Typeflag: tar.TypeReg, Size: int64(len(payload)), Mode: 0755}
	write := func(raw []byte) string {
		p := filepath.Join(t.TempDir(), "input.tar.gz")
		require.NoError(t, os.WriteFile(p, raw, 0600))
		return p
	}
	archive := archiveFixture(t, []tar.Header{header}, payload)
	destination := filepath.Join(root, "executable")
	b, e := unpackArtifact(write(archive), destination, entry)
	require.NoError(t, e)
	require.Equal(t, sha(payload), b.SHA256)
	// A concurrent uploader can keep the cached executable open on Windows.
	f, e := os.Open(destination)
	require.NoError(t, e)
	defer f.Close()
	_, e = unpackArtifact(write(archive), destination, entry)
	require.NoError(t, e)
	for _, bad := range []tar.Header{{Name: "../escape", Typeflag: tar.TypeReg, Size: 1}, {Name: "/absolute", Typeflag: tar.TypeReg, Size: 1}, {Name: entry, Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}} {
		_, e = unpackArtifact(write(archiveFixture(t, []tar.Header{bad}, payload)), filepath.Join(t.TempDir(), "out"), entry)
		require.ErrorIs(t, e, ErrIntegrity)
	}
	_, e = unpackArtifact(write(archiveFixture(t, []tar.Header{header, header}, payload)), filepath.Join(t.TempDir(), "out"), entry)
	require.ErrorIs(t, e, ErrIntegrity)
	_, e = unpackArtifact(write(archive[:len(archive)-5]), filepath.Join(t.TempDir(), "out"), entry)
	require.ErrorIs(t, e, ErrIntegrity)
}
