// Package updates checks published stable releases and verifies native downloads.
package updates

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const Repository = "neko233-com/jumpserver233"
const releaseAPI = "https://api.github.com/repos/" + Repository + "/releases/"
const maxArchiveBytes int64 = 256 << 20

var (
	ErrInvalid    = errors.New("invalid update input")
	ErrFeed       = errors.New("invalid official release metadata")
	ErrNetwork    = errors.New("official release check unavailable")
	ErrLimited    = errors.New("release check rate limited")
	ErrConflict   = errors.New("update settings revision changed")
	ErrExists     = errors.New("update destination already exists; refusing replacement")
	ErrBusy       = errors.New("release check in progress")
	ErrIntegrity  = errors.New("release artifact integrity check failed")
	stableVersion = regexp.MustCompile(`^v?(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)
	shaPattern    = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

func Version(value string) (string, bool) {
	if !stableVersion.MatchString(value) {
		return "", false
	}
	return "v" + strings.TrimPrefix(value, "v"), true
}
func newer(a, b string) bool {
	x, y := strings.Split(strings.TrimPrefix(a, "v"), "."), strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := range x {
		n, _ := strconv.Atoi(x[i])
		m, _ := strconv.Atoi(y[i])
		if n != m {
			return n > m
		}
	}
	return false
}
func Supported(platform, arch string) bool {
	return (platform == "linux" || platform == "darwin" || platform == "windows") && (arch == "amd64" || arch == "arm64")
}
func ArchiveName(version, platform, arch string) string {
	return "jumpserver233-" + version + "-" + platform + "-" + arch + ".tar.gz"
}

type Artifact struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}
type Result struct {
	Status      string    `json:"status"`
	Version     string    `json:"version,omitempty"`
	ReleaseURL  string    `json:"release_url,omitempty"`
	PublishedAt time.Time `json:"published_at,omitempty"`
	Artifact    *Artifact `json:"artifact,omitempty"`
}
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}
type Feed struct {
	client                  HTTPClient
	current, platform, arch string
}

func NewFeed(current, platform, arch string, client HTTPClient) *Feed {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 5 || req.URL.Scheme != "https" || req.URL.User != nil {
				return ErrNetwork
			}
			switch req.URL.Host {
			case "api.github.com", "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com", "github-releases.githubusercontent.com":
				return nil
			}
			return ErrNetwork
		}}
	}
	return &Feed{client: client, current: current, platform: platform, arch: arch}
}

func (f *Feed) request(ctx context.Context, target string, binary bool) (*http.Response, error) {
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if e != nil {
		return nil, ErrInvalid
	}
	req.Header.Set("User-Agent", "jumpserver233-updater")
	if binary {
		req.Header.Set("Accept", "application/octet-stream")
	} else {
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	}
	r, e := f.client.Do(req)
	if e != nil {
		return nil, ErrNetwork
	}
	return r, nil
}

func (f *Feed) Check(ctx context.Context, tag string) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if !Supported(f.platform, f.arch) {
		return Result{}, ErrInvalid
	}
	endpoint := "latest"
	if tag != "" {
		v, ok := Version(tag)
		if !ok {
			return Result{}, ErrInvalid
		}
		endpoint = "tags/" + v
		tag = v
	}
	r, e := f.request(ctx, releaseAPI+endpoint, false)
	if e != nil {
		return Result{}, e
	}
	defer r.Body.Close()
	if r.StatusCode == 404 {
		return Result{Status: "no_release"}, nil
	}
	if r.StatusCode == 403 || r.StatusCode == 429 {
		return Result{}, ErrLimited
	}
	if r.StatusCode != 200 {
		return Result{}, ErrNetwork
	}
	var release struct {
		Tag        string    `json:"tag_name"`
		Draft      bool      `json:"draft"`
		Prerelease bool      `json:"prerelease"`
		Published  time.Time `json:"published_at"`
		URL        string    `json:"html_url"`
		Assets     []struct {
			Name   string `json:"name"`
			URL    string `json:"browser_download_url"`
			Digest string `json:"digest"`
			Size   int64  `json:"size"`
			State  string `json:"state"`
		} `json:"assets"`
	}
	data, e := io.ReadAll(io.LimitReader(r.Body, 2<<20+1))
	if e != nil || len(data) > 2<<20 || json.Unmarshal(data, &release) != nil {
		return Result{}, ErrFeed
	}
	version, ok := Version(release.Tag)
	if !ok || release.Tag != version || release.Draft || release.Prerelease || release.Published.IsZero() || len(release.Assets) > 100 || tag != "" && version != tag {
		return Result{}, ErrFeed
	}
	releaseURL := "https://github.com/" + Repository + "/releases/tag/" + version
	if release.URL != releaseURL {
		return Result{}, ErrFeed
	}
	out := Result{Status: "current_unknown", Version: version, ReleaseURL: releaseURL, PublishedAt: release.Published}
	if current, known := Version(f.current); known {
		out.Status = "up_to_date"
		if newer(version, current) {
			out.Status = "update_available"
		}
	}
	name := ArchiveName(version, f.platform, f.arch)
	for _, a := range release.Assets {
		if a.Name != name {
			continue
		}
		if out.Artifact != nil {
			return Result{}, ErrFeed
		}
		digest := strings.TrimPrefix(a.Digest, "sha256:")
		if a.Digest != "sha256:"+digest || !shaPattern.MatchString(digest) || a.State != "uploaded" || a.Size <= 0 || a.Size > maxArchiveBytes || a.URL != "https://github.com/"+Repository+"/releases/download/"+version+"/"+name {
			return Result{}, ErrFeed
		}
		out.Artifact = &Artifact{Name: name, URL: a.URL, SHA256: digest, Bytes: a.Size}
	}
	return out, nil
}

// Download authenticates metadata through the fixed official HTTPS feed, checks
// the asset digest, then atomically publishes a previously nonexistent file.
// It does not unpack or execute the archive and never opens the business data.
func (f *Feed) Download(ctx context.Context, version, destination string) (Artifact, error) {
	result, e := f.Check(ctx, version)
	if e != nil {
		return Artifact{}, e
	}
	if result.Artifact == nil {
		return Artifact{}, ErrFeed
	}
	a := *result.Artifact
	path, e := filepath.Abs(destination)
	if e != nil || destination == "" {
		return Artifact{}, ErrInvalid
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(path))
	if e != nil {
		return Artifact{}, ErrInvalid
	}
	path = filepath.Join(parent, filepath.Base(path))
	if _, e = os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
		return Artifact{}, ErrExists
	}
	tmp, e := os.CreateTemp(parent, ".jms233-update-*")
	if e != nil {
		return Artifact{}, e
	}
	temporary := tmp.Name()
	defer os.Remove(temporary)
	defer tmp.Close()
	if e = tmp.Chmod(0600); e != nil {
		return Artifact{}, e
	}
	r, e := f.request(ctx, a.URL, true)
	if e != nil {
		return Artifact{}, e
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return Artifact{}, ErrNetwork
	}
	if r.ContentLength >= 0 && r.ContentLength != a.Bytes {
		return Artifact{}, ErrIntegrity
	}
	hash := sha256.New()
	n, e := io.Copy(io.MultiWriter(tmp, hash), io.LimitReader(r.Body, a.Bytes+1))
	if e != nil || n != a.Bytes || hex.EncodeToString(hash.Sum(nil)) != a.SHA256 {
		return Artifact{}, ErrIntegrity
	}
	if e = tmp.Sync(); e != nil {
		return Artifact{}, e
	}
	if e = tmp.Close(); e != nil {
		return Artifact{}, e
	}
	if e = os.Link(temporary, path); e != nil {
		if errors.Is(e, os.ErrExist) {
			return Artifact{}, ErrExists
		}
		return Artifact{}, e
	}
	return a, nil
}

func ErrorCode(e error) string {
	switch {
	case errors.Is(e, ErrLimited):
		return "rate_limited"
	case errors.Is(e, ErrFeed):
		return "invalid_release"
	case errors.Is(e, ErrIntegrity):
		return "integrity"
	case errors.Is(e, ErrNetwork):
		return "network"
	case errors.Is(e, context.Canceled):
		return "canceled"
	}
	return "unavailable"
}

// ValidateArtifactURL is also used when reopening persisted release evidence.
func ValidateArtifactURL(a Artifact, version, platform, arch string) bool {
	u, e := url.Parse(a.URL)
	return e == nil && u.User == nil && a.Name == ArchiveName(version, platform, arch) && a.URL == "https://github.com/"+Repository+"/releases/download/"+version+"/"+a.Name && shaPattern.MatchString(a.SHA256) && a.Bytes > 0 && a.Bytes <= maxArchiveBytes
}
