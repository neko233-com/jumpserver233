package updates

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type transport func(*http.Request) (*http.Response, error)

func (t transport) Do(r *http.Request) (*http.Response, error) { return t(r) }
func metadata(payload []byte) map[string]any {
	sum := sha256.Sum256(payload)
	v := "v1.2.3"
	name := ArchiveName(v, "linux", "amd64")
	return map[string]any{"tag_name": v, "draft": false, "prerelease": false, "published_at": "2026-10-18T12:00:00Z", "html_url": "https://github.com/" + Repository + "/releases/tag/" + v, "assets": []map[string]any{{"name": name, "state": "uploaded", "size": len(payload), "digest": "sha256:" + hex.EncodeToString(sum[:]), "browser_download_url": "https://github.com/" + Repository + "/releases/download/" + v + "/" + name}}}
}
func respond(status int, body []byte) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}
}
func feedFor(t *testing.T, value map[string]any, payload []byte, calls *atomic.Int32) *Feed {
	t.Helper()
	body, e := json.Marshal(value)
	require.NoError(t, e)
	return NewFeed("v1.0.0", "linux", "amd64", transport(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		assert.Empty(t, r.Header.Get("Authorization"))
		assert.Equal(t, "https", r.URL.Scheme)
		if r.URL.Host == "api.github.com" {
			return respond(200, body), nil
		}
		return respond(200, payload), nil
	}))
}
func TestStableVersionsAndOfficialPlatformSelection(t *testing.T) {
	for _, v := range []string{"v1.2.3", "1.2.3", "v0.0.0"} {
		_, ok := Version(v)
		assert.True(t, ok)
	}
	for _, v := range []string{"dev", "v01.2.3", "v1.2.3-rc.1", "v1.2", "v1.2.3+foo", "../1.2.3", "v9999999999.0.0"} {
		_, ok := Version(v)
		assert.False(t, ok)
	}
	assert.True(t, newer("v1.10.0", "v1.9.9"))
	assert.False(t, newer("v1.0.0", "v2.0.0"))
	var calls atomic.Int32
	f := feedFor(t, metadata([]byte("package")), []byte("package"), &calls)
	for _, c := range []struct{ version, status string }{{"v1.0.0", "update_available"}, {"v1.2.3", "up_to_date"}, {"v2.0.0", "up_to_date"}, {"source-sha", "current_unknown"}} {
		f.current = c.version
		r, e := f.Check(context.Background(), "")
		require.NoError(t, e)
		assert.Equal(t, c.status, r.Status)
		require.NotNil(t, r.Artifact)
		assert.Equal(t, 7, int(r.Artifact.Bytes))
	}
	f.arch = "arm64"
	r, e := f.Check(context.Background(), "")
	require.NoError(t, e)
	assert.Nil(t, r.Artifact)
}
func TestReleaseMetadataFailsClosed(t *testing.T) {
	for _, kind := range []string{"draft", "prerelease", "version", "release-url", "published-at", "artifact-url", "digest", "oversize", "duplicate", "not-uploaded", "requested-version"} {
		t.Run(kind, func(t *testing.T) {
			m := metadata([]byte("package"))
			asset := m["assets"].([]map[string]any)[0]
			tag := ""
			switch kind {
			case "draft":
				m["draft"] = true
			case "prerelease":
				m["prerelease"] = true
			case "version":
				m["tag_name"] = "v1.2.3-rc.1"
			case "release-url":
				m["html_url"] = "https://evil.example/"
			case "published-at":
				m["published_at"] = nil
			case "artifact-url":
				asset["browser_download_url"] = "https://github.com/another/repo/file"
			case "digest":
				asset["digest"] = ""
			case "oversize":
				asset["size"] = maxArchiveBytes + 1
			case "duplicate":
				m["assets"] = []map[string]any{asset, asset}
			case "not-uploaded":
				asset["state"] = "new"
			case "requested-version":
				tag = "v1.2.2"
			}
			var calls atomic.Int32
			_, e := feedFor(t, m, nil, &calls).Check(context.Background(), tag)
			assert.ErrorIs(t, e, ErrFeed)
		})
	}
	for _, code := range []int{404, 403, 429, 500} {
		f := NewFeed("v1.0.0", "linux", "amd64", transport(func(*http.Request) (*http.Response, error) { return respond(code, nil), nil }))
		r, e := f.Check(context.Background(), "")
		if code == 404 {
			require.NoError(t, e)
			assert.Equal(t, "no_release", r.Status)
		} else {
			assert.Error(t, e)
		}
	}
}
func TestVerifiedDownloadIsAtomicAndNeverReplacesAFile(t *testing.T) {
	payload := []byte("synthetic-native-archive")
	var calls atomic.Int32
	f := feedFor(t, metadata(payload), payload, &calls)
	dir := t.TempDir()
	path := filepath.Join(dir, "archive.tar.gz")
	a, e := f.Download(context.Background(), "v1.2.3", path)
	require.NoError(t, e)
	assert.Len(t, a.SHA256, 64)
	actual, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.Equal(t, payload, actual)
	_, e = f.Download(context.Background(), "v1.2.3", path)
	assert.ErrorIs(t, e, ErrExists)
	matches, e := filepath.Glob(filepath.Join(dir, ".jms233-update-*"))
	require.NoError(t, e)
	assert.Empty(t, matches)
	var badCalls atomic.Int32
	bad := feedFor(t, metadata(payload), []byte("changed"), &badCalls)
	badPath := filepath.Join(dir, "bad.tar.gz")
	_, e = bad.Download(context.Background(), "v1.2.3", badPath)
	assert.ErrorIs(t, e, ErrIntegrity)
	assert.NoFileExists(t, badPath)
}
func TestDefaultTransportRejectsUnsafeRedirectsAndBoundsMetadata(t *testing.T) {
	f := NewFeed("dev", "linux", "amd64", nil)
	client := f.client.(*http.Client)
	assert.Equal(t, 5*time.Minute, client.Timeout)
	for _, url := range []string{"http://github.com/file", "https://evil.example/file", "https://user:password@github.com/file", "https://github.com:443/file"} {
		req, e := http.NewRequest("GET", url, nil)
		require.NoError(t, e)
		assert.Error(t, client.CheckRedirect(req, nil))
	}
	req, e := http.NewRequest("GET", "https://release-assets.githubusercontent.com/file", nil)
	require.NoError(t, e)
	assert.NoError(t, client.CheckRedirect(req, nil))
	assert.Error(t, client.CheckRedirect(req, make([]*http.Request, 6)))
	f = NewFeed("dev", "linux", "amd64", transport(func(*http.Request) (*http.Response, error) {
		return respond(200, []byte(strings.Repeat(" ", (2<<20)+1))), nil
	}))
	_, e = f.Check(context.Background(), "")
	assert.ErrorIs(t, e, ErrFeed)
}
