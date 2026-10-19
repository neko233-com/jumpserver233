package releasebundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"

	"github.com/neko233-com/jumpserver233/server/internal/maintenance"
)

var ErrStageConflict = errors.New("release staging directory is unmanaged, changed or incompatible")

const stageRootFile = ".jms233-releases.json"
const stageReceiptFile = ".jms233-release.json"

var stageName = regexp.MustCompile(`^\.jms233-stage-[a-f0-9]{32}$`)
var stageWriteName = regexp.MustCompile(`^\.jms233-write-[a-f0-9]{32}$`)

type stageOwner struct {
	Schema       int    `json:"schema"`
	ID           string `json:"id"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
}
type stageReceipt struct {
	Schema         int    `json:"schema"`
	Owner          string `json:"owner"`
	Token          string `json:"token"`
	ArchiveSHA256  string `json:"archive_sha256"`
	ManifestSHA256 string `json:"manifest_sha256,omitempty"`
}

// Staged is a verified immutable candidate, never an active installation.
// No server is executed, no current-version pointer or application data is opened.
type Staged struct {
	Directory     string   `json:"directory"`
	ArchiveSHA256 string   `json:"archive_sha256"`
	Manifest      Manifest `json:"manifest"`
	Unchanged     bool     `json:"unchanged"`
	CleanedStages int      `json:"cleaned_stages"`
}
type stagingRoot struct {
	path  string
	owner stageOwner
	root  *os.Root
	lock  *maintenance.Lock
}

func (s *stagingRoot) close() { s.root.Close(); s.lock.Close() }

func stageID() (string, error) {
	var b [16]byte
	_, e := rand.Read(b[:])
	return hex.EncodeToString(b[:]), e
}
func validID(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 16 && strings.ToLower(s) == s
}
func supportedTarget(platform, arch string) bool {
	return (platform == "linux" || platform == "darwin" || platform == "windows") && (arch == "amd64" || arch == "arm64")
}

func openStagingRoot(path, platform, arch string, create bool) (_ *stagingRoot, err error) {
	if path == "" || !supportedTarget(platform, arch) {
		return nil, ErrInvalid
	}
	abs, e := filepath.Abs(path)
	if e != nil || filepath.Dir(abs) == abs {
		return nil, ErrInvalid
	}
	if create {
		if e = os.MkdirAll(abs, 0700); e != nil {
			return nil, e
		}
	}
	info, e := os.Lstat(abs)
	if e != nil {
		return nil, e
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrStageConflict
	}
	// Refuse application data, source checkouts and arbitrary directories before
	// acquiring the lock (which itself creates a private control directory).
	rows, e := os.ReadDir(abs)
	if e != nil {
		return nil, e
	}
	for _, row := range rows {
		if row.Name() != stageRootFile && row.Name() != ".jms233-maintenance" && row.Name() != "releases" && row.Name() != installationFile && row.Name() != upgradeJournalFile && row.Name() != scheduleFile && row.Name() != automaticFile && row.Name() != "backups" && !stageName.MatchString(row.Name()) && !stageWriteName.MatchString(row.Name()) {
			return nil, ErrStageConflict
		}
		if row.Type()&os.ModeSymlink != 0 {
			return nil, ErrStageConflict
		}
	}
	lock, e := maintenance.Acquire(abs)
	if e != nil {
		return nil, e
	}
	s := &stagingRoot{path: lock.DataDir, lock: lock}
	defer func() {
		if err != nil {
			if s.root != nil {
				s.root.Close()
			}
			lock.Close()
		}
	}()
	s.root, e = os.OpenRoot(s.path)
	if e != nil {
		return nil, e
	}
	e = readStageJSON(s.root, stageRootFile, &s.owner)
	if errors.Is(e, os.ErrNotExist) && create {
		rows, e = fs.ReadDir(s.root.FS(), ".")
		if e != nil {
			return nil, e
		}
		for _, row := range rows {
			if row.Name() != ".jms233-maintenance" {
				return nil, ErrStageConflict
			}
		}
		id, e := stageID()
		if e != nil {
			return nil, e
		}
		s.owner = stageOwner{Schema: 1, ID: id, Platform: platform, Architecture: arch}
		if e = writeStageJSON(s.root, stageRootFile, s.owner, true); e != nil {
			return nil, e
		}
	} else if e != nil {
		return nil, e
	}
	if s.owner.Schema != 1 || !validID(s.owner.ID) || s.owner.Platform != platform || s.owner.Architecture != arch {
		return nil, ErrStageConflict
	}
	if e = s.root.Mkdir("releases", 0700); e != nil && !errors.Is(e, os.ErrExist) {
		return nil, e
	}
	info, e = s.root.Lstat("releases")
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrStageConflict
	}
	if e = syncStageDirectory(s.path); e != nil {
		return nil, e
	}
	return s, nil
}

func readStageJSON(root *os.Root, name string, into any) error {
	info, e := root.Lstat(name)
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || info.Size() > 8<<20 {
		return ErrStageConflict
	}
	f, e := root.Open(name)
	if e != nil {
		return e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) {
		return ErrStageConflict
	}
	d := json.NewDecoder(io.LimitReader(f, (8<<20)+1))
	d.DisallowUnknownFields()
	if d.Decode(into) != nil || d.Decode(new(any)) != io.EOF {
		return ErrStageConflict
	}
	return nil
}
func writeStageJSON(root *os.Root, name string, body any, exclusive bool) error {
	data, e := json.Marshal(body)
	if e != nil {
		return e
	}
	if len(data) > 8<<20 {
		return ErrStageConflict
	}
	target := name
	if !exclusive {
		id, e := stageID()
		if e != nil {
			return e
		}
		target = filepath.Join(filepath.Dir(name), ".jms233-write-"+id)
		defer root.Remove(target)
	}
	f, e := root.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if !exclusive {
		return root.Rename(target, name)
	}
	return nil
}
func syncStageDirectory(path string) error {
	// Windows has no portable directory fsync; retain exact receipts and use
	// same-volume rename, without claiming Unix power-loss durability.
	if runtime.GOOS == "windows" {
		return nil
	}
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}

type stageReader struct {
	ctx context.Context
	r   io.Reader
}

func (r stageReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.r.Read(p)
}

func (s *stagingRoot) clean(ctx context.Context) (int, error) {
	rows, e := fs.ReadDir(s.root.FS(), ".")
	if e != nil {
		return 0, e
	}
	removed := 0
	for _, row := range rows {
		if e = ctx.Err(); e != nil {
			return removed, e
		}
		if !stageName.MatchString(row.Name()) {
			continue
		}
		if !row.IsDir() || row.Type()&os.ModeSymlink != 0 {
			return removed, ErrStageConflict
		}
		var receipt stageReceipt
		if e = readStageJSON(s.root, row.Name()+"/"+stageReceiptFile, &receipt); e != nil {
			return removed, ErrStageConflict
		}
		if !s.owns(receipt) || row.Name() != ".jms233-stage-"+receipt.Token {
			return removed, ErrStageConflict
		}
		// Check the complete resolved deletion target and refuse junctions/links.
		if e = s.removeStage(row.Name()); e != nil {
			return removed, e
		}
		removed++
	}
	return removed, syncStageDirectory(s.path)
}
func (s *stagingRoot) owns(r stageReceipt) bool {
	return r.Schema == 1 && r.Owner == s.owner.ID && validID(r.Token) && digest.MatchString(r.ArchiveSHA256) && (r.ManifestSHA256 == "" || digest.MatchString(r.ManifestSHA256))
}
func (s *stagingRoot) removeStage(name string) error {
	if !stageName.MatchString(name) {
		return ErrStageConflict
	}
	target := filepath.Join(s.path, name)
	resolved, e := filepath.EvalSymlinks(target)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil || !strings.EqualFold(resolved, target) || filepath.Dir(target) != s.path {
		return ErrStageConflict
	}
	if e = fs.WalkDir(s.root.FS(), name, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 || !d.IsDir() && !d.Type().IsRegular() {
			return ErrStageConflict
		}
		return nil
	}); e != nil {
		return e
	}
	return s.root.RemoveAll(name)
}

// Stage creates a private copy of the pinned archive, fully verifies it, then
// extracts into a confined sibling directory. Only the complete verified tree
// is renamed into releases/SHA256. Retries recheck every already-staged byte.
func Stage(ctx context.Context, archive, sha, platform, arch, path string) (result Staged, err error) {
	if !digest.MatchString(sha) || !supportedTarget(platform, arch) {
		return result, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return result, e
	}
	info, e := os.Lstat(archive)
	if e != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 256<<20 {
		return result, ErrInvalid
	}
	input, e := os.Open(archive)
	if e != nil {
		return result, e
	}
	defer input.Close()
	opened, e := input.Stat()
	if e != nil || !os.SameFile(info, opened) {
		return result, ErrInvalid
	}
	s, e := openStagingRoot(path, platform, arch, true)
	if e != nil {
		return result, e
	}
	defer s.close()
	result.CleanedStages, e = s.clean(ctx)
	if e != nil {
		return result, e
	}
	id, e := stageID()
	if e != nil {
		return result, e
	}
	temporary := ".jms233-stage-" + id
	if e = s.root.Mkdir(temporary, 0700); e != nil {
		return result, e
	}
	defer func() {
		if e := s.removeStage(temporary); e != nil && !errors.Is(e, os.ErrNotExist) {
			err = errors.Join(err, e)
		}
	}()
	receipt := stageReceipt{Schema: 1, Owner: s.owner.ID, Token: id, ArchiveSHA256: sha}
	if e = writeStageJSON(s.root, temporary+"/"+stageReceiptFile, receipt, true); e != nil {
		return result, e
	}
	if e = syncStageDirectory(filepath.Join(s.path, temporary)); e != nil {
		return result, e
	}
	if e = syncStageDirectory(s.path); e != nil {
		return result, e
	}
	copyName := temporary + "/archive.tar.gz"
	copyFile, e := s.root.OpenFile(copyName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return result, e
	}
	n, e := io.Copy(copyFile, io.LimitReader(stageReader{ctx, input}, (256<<20)+1))
	if e == nil && n != info.Size() {
		e = ErrInvalid
	}
	if e == nil {
		e = copyFile.Sync()
	}
	ce := copyFile.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return result, e
	}
	m, e := Verify(filepath.Join(s.path, copyName), sha, platform, arch)
	if e != nil {
		return result, e
	}
	if e = ctx.Err(); e != nil {
		return result, e
	}
	destination := "releases/" + sha
	if _, e = s.root.Lstat(destination); e == nil {
		old, e := s.inspect(ctx, destination, sha)
		if e != nil {
			return result, e
		}
		if !reflect.DeepEqual(old, m) {
			return result, ErrStageConflict
		}
		result.Directory = filepath.Join(s.path, filepath.FromSlash(destination))
		result.ArchiveSHA256 = sha
		result.Manifest = m
		result.Unchanged = true
		return result, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return result, e
	}
	if e = s.extract(ctx, temporary, copyName, m); e != nil {
		return result, e
	}
	if e = s.root.Remove(copyName); e != nil {
		return result, e
	}
	body, e := json.Marshal(m)
	if e != nil {
		return result, e
	}
	manifestSum := sha256.Sum256(body)
	receipt.ManifestSHA256 = hex.EncodeToString(manifestSum[:])
	if e = writeStageJSON(s.root, temporary+"/"+stageReceiptFile, receipt, false); e != nil {
		return result, e
	}
	if _, e = s.inspect(ctx, temporary, sha); e != nil {
		return result, e
	}
	if e = ctx.Err(); e != nil {
		return result, e
	}
	if e = s.root.Rename(temporary, destination); e != nil {
		return result, e
	}
	if e = syncStageDirectory(filepath.Join(s.path, "releases")); e != nil {
		return result, e
	}
	if e = syncStageDirectory(s.path); e != nil {
		return result, e
	}
	result.Directory = filepath.Join(s.path, filepath.FromSlash(destination))
	result.ArchiveSHA256 = sha
	result.Manifest = m
	return result, nil
}

func (s *stagingRoot) extract(ctx context.Context, folder, archive string, m Manifest) error {
	f, e := s.root.Open(archive)
	if e != nil {
		return e
	}
	defer f.Close()
	gz, e := gzip.NewReader(stageReader{ctx, f})
	if e != nil {
		return e
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if !ValidPath(h.Name) || h.Typeflag != tar.TypeReg || h.Linkname != "" {
			return ErrInvalid
		}
		file, ok := m.Files[h.Name]
		if h.Name == "manifest.json" {
			body, e := json.Marshal(m)
			if e != nil {
				return e
			}
			if e = s.writeExtracted(folder+"/manifest.json", bytes.NewReader(body), int64(len(body)), 0600); e != nil {
				return e
			}
			continue
		}
		if !ok || file.Bytes != h.Size {
			return ErrInvalid
		}
		path := folder + "/" + h.Name
		if e = s.root.MkdirAll(filepath.Dir(path), 0700); e != nil {
			return e
		}
		mode := fs.FileMode(0600)
		if file.Executable {
			mode = 0700
		}
		if e = s.writeExtracted(path, stageReader{ctx, tr}, h.Size, mode); e != nil {
			return e
		}
	}
	return nil
}
func (s *stagingRoot) writeExtracted(name string, input io.Reader, size int64, mode fs.FileMode) error {
	f, e := s.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if e != nil {
		return e
	}
	n, e := io.Copy(f, io.LimitReader(input, size+1))
	if e == nil && n != size {
		e = ErrInvalid
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}

func (s *stagingRoot) inspect(ctx context.Context, folder, sha string) (Manifest, error) {
	var m Manifest
	var receipt stageReceipt
	info, e := s.root.Lstat(folder)
	if e != nil {
		return m, e
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return m, ErrStageConflict
	}
	if e = readStageJSON(s.root, folder+"/"+stageReceiptFile, &receipt); e != nil || !s.owns(receipt) || receipt.ArchiveSHA256 != sha {
		return m, ErrStageConflict
	}
	if e = readStageJSON(s.root, folder+"/manifest.json", &m); e != nil || !m.Valid() || m.Platform != s.owner.Platform || m.Architecture != s.owner.Architecture {
		return m, ErrStageConflict
	}
	body, _ := json.Marshal(m)
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != receipt.ManifestSHA256 {
		return m, ErrStageConflict
	}
	seen := map[string]bool{}
	directories := map[string]bool{folder: true}
	for name := range m.Files {
		for d := filepath.ToSlash(filepath.Dir(name)); d != "."; d = filepath.ToSlash(filepath.Dir(d)) {
			directories[folder+"/"+d] = true
		}
	}
	e = fs.WalkDir(s.root.FS(), folder, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		if d.Type()&os.ModeSymlink != 0 {
			return ErrStageConflict
		}
		if d.IsDir() {
			if !directories[path] {
				return ErrStageConflict
			}
			return syncStageDirectory(filepath.Join(s.path, filepath.FromSlash(path)))
		}
		if !d.Type().IsRegular() {
			return ErrStageConflict
		}
		name := strings.TrimPrefix(path, folder+"/")
		if name == "manifest.json" || name == stageReceiptFile {
			return nil
		}
		expected, ok := m.Files[name]
		if !ok || seen[name] {
			return ErrStageConflict
		}
		seen[name] = true
		info, e := s.root.Lstat(path)
		if e != nil || !info.Mode().IsRegular() || info.Size() != expected.Bytes {
			return ErrStageConflict
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 && !expected.Executable || runtime.GOOS != "windows" && expected.Executable && info.Mode().Perm() != 0700 {
			return ErrStageConflict
		}
		f, e := s.root.Open(path)
		if e != nil {
			return e
		}
		defer f.Close()
		opened, e := f.Stat()
		if e != nil || !os.SameFile(info, opened) {
			return ErrStageConflict
		}
		hash := sha256.New()
		prefix := make([]byte, 0)
		if expected.Executable {
			prefix = make([]byte, min(expected.Bytes, 4096))
			if _, e = io.ReadFull(f, prefix); e != nil {
				return ErrStageConflict
			}
			hash.Write(prefix)
			if !binaryTarget(prefix, m.Platform, m.Architecture) {
				return ErrStageConflict
			}
		}
		n, e := io.Copy(hash, stageReader{ctx, f})
		if e != nil {
			return e
		}
		if n+int64(len(prefix)) != expected.Bytes || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
			return ErrStageConflict
		}
		return nil
	})
	if e != nil {
		return m, e
	}
	if len(seen) != len(m.Files) {
		return m, ErrStageConflict
	}
	return m, nil
}

// InspectStage rechecks the full candidate tree. The receipt is a local
// integrity record; it is not a signature or independent provenance attestation.
func InspectStage(ctx context.Context, path, sha, platform, arch string) (Staged, error) {
	var result Staged
	if !digest.MatchString(sha) {
		return result, ErrInvalid
	}
	s, e := openStagingRoot(path, platform, arch, false)
	if e != nil {
		return result, e
	}
	defer s.close()
	m, e := s.inspect(ctx, "releases/"+sha, sha)
	if e != nil {
		return result, e
	}
	return Staged{Directory: filepath.Join(s.path, "releases", sha), ArchiveSHA256: sha, Manifest: m, Unchanged: true}, nil
}

// CleanStages removes only interrupted staging directories with matching root
// ownership receipts. Published releases, unknown files and data are retained.
func CleanStages(ctx context.Context, path, platform, arch string) (int, error) {
	s, e := openStagingRoot(path, platform, arch, false)
	if e != nil {
		return 0, e
	}
	defer s.close()
	return s.clean(ctx)
}
