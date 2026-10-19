package releasebundle

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fixture(t *testing.T, kind string) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "native.tar.gz")
	f, e := os.Create(path)
	require.NoError(t, e)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	m := Manifest{Schema: 1, Version: "v1.2.3", Commit: strings.Repeat("a", 40), BuiltAt: time.Now().UTC(), Platform: "linux", Architecture: "amd64", Files: map[string]File{}}
	names := []string{"jms", "jms233-server", "web/index.html"}
	if strings.HasPrefix(kind, "install") {
		m.Platform = runtime.GOOS
		m.Architecture = runtime.GOARCH
		m.PreflightProtocol = 1
		m.ActivationProtocol = 1
		if strings.HasPrefix(kind, "install-v") {
			m.Version = strings.TrimPrefix(kind, "install-")
		}
		if kind == "install-legacy" {
			m.PreflightProtocol = 0
		}
		if m.Platform == "windows" {
			names[0] += ".exe"
			names[1] += ".exe"
		}
	}
	if kind == "traversal" {
		names[2] = "../outside"
	}
	if kind == "case-collision" {
		names = append(names, "WEB/index.html")
	}
	for _, name := range names {
		body := []byte("synthetic-" + name)
		executable := !strings.Contains(name, "/")
		if executable {
			body = make([]byte, 128)
			copy(body, "\x7fELF")
			body[4] = 2
			body[5] = 1
			binary.LittleEndian.PutUint16(body[16:18], 2)
			binary.LittleEndian.PutUint16(body[18:20], 62)
			if m.Architecture == "arm64" {
				binary.LittleEndian.PutUint16(body[18:20], 183)
			}
			if m.Platform == "darwin" {
				binary.LittleEndian.PutUint32(body[:4], 0xfeedfacf)
				cpu := uint32(0x01000007)
				if m.Architecture == "arm64" {
					cpu = 0x0100000c
				}
				binary.LittleEndian.PutUint32(body[4:8], cpu)
				binary.LittleEndian.PutUint32(body[12:16], 2)
			}
			if m.Platform == "windows" {
				copy(body, "MZ")
				binary.LittleEndian.PutUint32(body[60:64], 64)
				copy(body[64:68], "PE\x00\x00")
				machine := uint16(0x8664)
				if m.Architecture == "arm64" {
					machine = 0xaa64
				}
				binary.LittleEndian.PutUint16(body[68:70], machine)
				binary.LittleEndian.PutUint16(body[88:90], 0x20b)
			}
			if kind == "wrong-binary" {
				binary.LittleEndian.PutUint16(body[18:20], 183)
			}
		}
		sum := sha256.Sum256(body)
		mode := int64(0600)
		if executable {
			mode = 0700
		}
		typ := byte(tar.TypeReg)
		link := ""
		if kind == "symlink" && name == "jms" {
			typ = tar.TypeSymlink
			link = "outside"
			body = nil
		}
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(body)), Typeflag: typ, Linkname: link}))
		_, e = tw.Write(body)
		require.NoError(t, e)
		m.Files[name] = File{SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(body)), Executable: executable}
	}
	if kind == "hash" {
		item := m.Files["jms"]
		item.SHA256 = strings.Repeat("0", 64)
		m.Files["jms"] = item
	}
	if kind == "missing-file" {
		delete(m.Files, "jms")
	}
	if kind == "future" {
		m.Schema = 2
	}
	if kind != "missing-manifest" {
		body, e := json.Marshal(m)
		require.NoError(t, e)
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(body)), Typeflag: tar.TypeReg}))
		_, e = tw.Write(body)
		require.NoError(t, e)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	require.NoError(t, f.Close())
	if kind == "trailing" {
		f, e = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
		require.NoError(t, e)
		_, e = f.WriteString("junk")
		require.NoError(t, e)
		require.NoError(t, f.Close())
	}
	data, e := os.ReadFile(path)
	require.NoError(t, e)
	sum := sha256.Sum256(data)
	return path, hex.EncodeToString(sum[:])
}
func TestNativeArchiveValidatesAllFilesWithoutExtracting(t *testing.T) {
	path, sha := fixture(t, "")
	m, e := Verify(path, sha, "linux", "amd64")
	require.NoError(t, e)
	assert.Len(t, m.Files, 3)
	_, e = Verify(path, sha, "darwin", "arm64")
	assert.ErrorIs(t, e, ErrInvalid)
	_, e = Verify(path, strings.Repeat("0", 64), "linux", "amd64")
	assert.ErrorIs(t, e, ErrInvalid)
}
func TestNativeArchiveRejectsUnsafeOrInconsistentEnvelopes(t *testing.T) {
	for _, kind := range []string{"traversal", "case-collision", "symlink", "hash", "missing-file", "missing-manifest", "future", "trailing", "wrong-binary"} {
		t.Run(kind, func(t *testing.T) {
			path, sha := fixture(t, kind)
			_, e := Verify(path, sha, "linux", "amd64")
			assert.ErrorIs(t, e, ErrInvalid)
		})
	}
}
func TestPortableReleaseNamesExcludeWindowsAliasesAndTraversal(t *testing.T) {
	for _, name := range []string{"../escape", "web/CON.txt", "web/AUX", "web/file.", "web/a:b", "web/ümlaut", "web/a\\b"} {
		assert.False(t, ValidPath(name), name)
	}
	assert.True(t, ValidPath("web/assets/index-hash.js"))
}
