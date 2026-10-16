package hostplugins

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const artifactLimit int64 = 64 << 20

type Blob struct {
	Path   string
	SHA256 string
	Size   int64
}
type Cache struct {
	root   string
	client *http.Client
	gate   chan struct{}
}

func NewCache(root string) (*Cache, error) {
	root = filepath.Join(root, "plugin-artifacts")
	if e := os.MkdirAll(root, 0700); e != nil {
		return nil, e
	}
	return &Cache{root: root, gate: make(chan struct{}, 1), client: &http.Client{Timeout: 120 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 || !releaseURL(r.URL) {
			return ErrIntegrity
		}
		return nil
	}}}, nil
}
func releaseURL(u *url.URL) bool {
	if u == nil || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return false
	}
	switch u.Hostname() {
	case "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com":
		return true
	}
	return false
}
func digestFile(file string) (string, int64, error) {
	f, e := os.Open(file)
	if e != nil {
		return "", 0, e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, artifactLimit+1))
	if e != nil || n > artifactLimit {
		return "", 0, ErrIntegrity
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
func validDigest(v string) bool {
	raw, e := hex.DecodeString(v)
	return e == nil && len(raw) == 32 && hex.EncodeToString(raw) == v
}
func (c *Cache) Fetch(ctx context.Context, a Artifact) (Blob, error) {
	if err := ctx.Err(); err != nil {
		return Blob{}, err
	}
	u, e := url.Parse(a.URL)
	if e != nil || !releaseURL(u) || !validDigest(a.SHA256) {
		return Blob{}, ErrInvalid
	}
	select {
	case c.gate <- struct{}{}:
		defer func() { <-c.gate }()
	case <-ctx.Done():
		return Blob{}, ctx.Err()
	}
	dir := filepath.Join(c.root, a.SHA256)
	if e = os.MkdirAll(dir, 0700); e != nil {
		return Blob{}, e
	}
	archive := filepath.Join(dir, "artifact")
	actual, _, e := digestFile(archive)
	if e != nil || actual != a.SHA256 {
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
		if e != nil {
			return Blob{}, e
		}
		req.Header.Set("User-Agent", "jumpserver233-host-plugins")
		response, e := c.client.Do(req)
		if e != nil {
			return Blob{}, e
		}
		if response.StatusCode != 200 {
			response.Body.Close()
			return Blob{}, ErrIntegrity
		}
		f, e := os.CreateTemp(dir, "download-*.tmp")
		if e != nil {
			response.Body.Close()
			return Blob{}, e
		}
		name := f.Name()
		defer os.Remove(name)
		h := sha256.New()
		n, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(response.Body, artifactLimit+1))
		response.Body.Close()
		syncErr := f.Sync()
		closeErr := f.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || n > artifactLimit || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
			return Blob{}, ErrIntegrity
		}
		if e = os.Rename(name, archive); e != nil {
			return Blob{}, e
		}
	}
	if a.ArchiveEntry == "" {
		hash, size, e := digestFile(archive)
		if e != nil || hash != a.SHA256 {
			return Blob{}, ErrIntegrity
		}
		return Blob{Path: archive, SHA256: hash, Size: size}, nil
	}
	return unpackArtifact(archive, filepath.Join(dir, "executable"), a.ArchiveEntry)
}
func unpackArtifact(source, destination, entry string) (Blob, error) {
	if path.Clean(entry) != entry || strings.HasPrefix(entry, "/") || strings.Contains(entry, "\\") {
		return Blob{}, ErrInvalid
	}
	f, e := os.Open(source)
	if e != nil {
		return Blob{}, e
	}
	defer f.Close()
	gz, e := gzip.NewReader(f)
	if e != nil {
		return Blob{}, ErrIntegrity
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out, e := os.CreateTemp(filepath.Dir(destination), "extract-*.tmp")
	if e != nil {
		return Blob{}, e
	}
	name := out.Name()
	defer os.Remove(name)
	defer out.Close()
	hash := sha256.New()
	var size, total int64
	found := false
	for count := 0; ; count++ {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil || count >= 64 {
			return Blob{}, ErrIntegrity
		}
		clean := path.Clean(h.Name)
		if clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") || strings.Contains(h.Name, "\\") || h.Size < 0 || h.Size > artifactLimit || h.Typeflag != tar.TypeDir && h.Typeflag != tar.TypeReg {
			return Blob{}, ErrIntegrity
		}
		total += h.Size
		if total > 2*artifactLimit {
			return Blob{}, ErrIntegrity
		}
		if h.Name == entry {
			if found || h.Typeflag != tar.TypeReg {
				return Blob{}, ErrIntegrity
			}
			found = true
			size, e = io.Copy(io.MultiWriter(out, hash), io.LimitReader(tr, artifactLimit+1))
			if e != nil || size != h.Size || size > artifactLimit {
				return Blob{}, ErrIntegrity
			}
		}
	}
	// Consume the gzip trailer so corrupt compressed streams cannot be cached.
	if n, tailErr := io.Copy(io.Discard, io.LimitReader(gz, artifactLimit+1)); tailErr != nil || n > artifactLimit || !found || size == 0 {
		return Blob{}, ErrIntegrity
	}
	if e = out.Sync(); e != nil {
		return Blob{}, e
	}
	if e = out.Close(); e != nil {
		return Blob{}, e
	}
	expected := hex.EncodeToString(hash.Sum(nil))
	if current, n, readErr := digestFile(destination); readErr == nil && current == expected && n == size {
		return Blob{Path: destination, SHA256: expected, Size: size}, nil
	}
	if e = os.Rename(name, destination); e != nil {
		return Blob{}, e
	}
	return Blob{Path: destination, SHA256: expected, Size: size}, nil
}
