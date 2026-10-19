package maintenance

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	manifestName     = ".jms233-backup-manifest.json"
	receiptName      = ".jms233-restore-receipt.json"
	maxEntries       = 200000
	maxDataBytes     = int64(64 << 30)
	maxManifestBytes = int64(64 << 20)
)

type Options struct {
	DataDir, File, Version, ExternalVaultKey string
	Passphrase                               []byte
	Replace                                  bool
}
type Result struct {
	BackupID            string    `json:"backup_id"`
	Version             string    `json:"source_version"`
	CreatedAt           time.Time `json:"created_at"`
	Files               int       `json:"files"`
	Bytes               int64     `json:"bytes"`
	ArchiveSHA256       string    `json:"archive_sha256,omitempty"`
	ExternalKeyIncluded bool      `json:"external_key_included"`
	Unchanged           bool      `json:"unchanged"`
	PreviousDataDir     string    `json:"previous_data_dir,omitempty"`
}
type entry struct {
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256,omitempty"`
	Directory bool   `json:"directory,omitempty"`
	Mode      int64  `json:"mode"`
}
type manifest struct {
	Format  int     `json:"format"`
	Result  Result  `json:"backup"`
	Entries []entry `json:"entries"`
}

func randomID() (string, error) {
	var b [16]byte
	_, e := rand.Read(b[:])
	return hex.EncodeToString(b[:]), e
}
func reserved(name string) bool {
	return strings.EqualFold(name, manifestName) || strings.EqualFold(name, receiptName) || strings.EqualFold(strings.SplitN(name, "/", 2)[0], controlName)
}

// Case aliases of the actual control directory are valid on Windows/macOS.
// A distinct directory with the same folded name on Linux cannot be portable.
func actualControl(dataDir, name string) bool {
	current, e := os.Lstat(filepath.Join(dataDir, name))
	canonical, ce := os.Lstat(filepath.Join(dataDir, controlName))
	return e == nil && ce == nil && current.IsDir() && canonical.IsDir() && current.Mode()&os.ModeSymlink == 0 && canonical.Mode()&os.ModeSymlink == 0 && os.SameFile(current, canonical)
}
func safeName(name string) bool {
	if !fs.ValidPath(name) || name == "." || len(name) > 1024 || !utf8.ValidString(name) || strings.ContainsAny(name, "\\:") {
		return false
	}
	for _, c := range name {
		if unicode.IsControl(c) {
			return false
		}
	}
	for _, part := range strings.Split(name, "/") {
		if strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return false
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
			return false
		}
	}
	return true
}
func contextReader(ctx context.Context, r io.Reader) io.Reader { return &cancelReader{ctx, r} }

type cancelReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *cancelReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.r.Read(p)
}
func inside(parent, child string) bool {
	r, e := filepath.Rel(parent, child)
	return e == nil && (r == "." || r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator)))
}

// Create captures a stopped, initialized standalone store. The data lock is
// shared with server startup, so no application writer can race the snapshot.
func Create(ctx context.Context, opt Options) (result Result, err error) {
	if e := ctx.Err(); e != nil {
		return result, e
	}
	lock, e := Acquire(opt.DataDir)
	if e != nil {
		return result, e
	}
	defer lock.Close()
	if e = standaloneMode(lock.DataDir, true); e != nil {
		return result, e
	}
	if exists(journalPath(lock.DataDir)) {
		return result, ErrConflict
	}
	if opt.File == "" || len(opt.Version) > 128 {
		return result, ErrInvalid
	}
	destination, e := filepath.Abs(opt.File)
	if e != nil {
		return result, e
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(destination))
	if e != nil {
		return result, e
	}
	destination = filepath.Join(parent, filepath.Base(destination))
	if inside(lock.DataDir, destination) {
		return result, fmt.Errorf("backup output must be outside the data directory: %w", ErrInvalid)
	}
	if exists(destination) {
		return result, os.ErrExist
	}
	root, e := os.OpenRoot(lock.DataDir)
	if e != nil {
		return result, e
	}
	defer root.Close()
	var external []byte
	if opt.ExternalVaultKey != "" {
		external, e = base64.StdEncoding.DecodeString(opt.ExternalVaultKey)
		if e != nil || len(external) != 32 {
			return result, ErrInvalid
		}
		defer clear(external)
	}
	key := external
	if key == nil {
		f, e := root.Open("vault.key")
		if e != nil {
			return result, e
		}
		key, e = readBounded(f, 32)
		f.Close()
		if e != nil {
			return result, e
		}
		defer clear(key)
	}
	modeBody, e := root.ReadFile(modeFile)
	if e != nil {
		return result, e
	}
	var sourceMode modeRecord
	keySum := sha256.Sum256(key)
	if len(key) != 32 || json.Unmarshal(modeBody, &sourceMode) != nil || sourceMode.VaultKeySHA256 != hex.EncodeToString(keySum[:]) {
		return result, fmt.Errorf("vault key not validated by this server version; start the standalone service once: %w", ErrInvalid)
	}
	f, e := os.CreateTemp(parent, ".jms233-backup-*")
	if e != nil {
		return result, e
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	if e = f.Chmod(0600); e != nil {
		return result, e
	}
	digest := sha256.New()
	encrypted, e := newEncryptedWriter(io.MultiWriter(f, digest), opt.Passphrase)
	if e != nil {
		return result, e
	}
	compressed := gzip.NewWriter(encrypted)
	writer := tar.NewWriter(compressed)
	id, e := randomID()
	if e != nil {
		return result, e
	}
	result = Result{BackupID: id, Version: opt.Version, CreatedAt: time.Now().UTC(), ExternalKeyIncluded: len(external) > 0}
	m := manifest{Format: 1, Result: result, Entries: []entry{}}
	seen := map[string]bool{}
	writeEntry := func(name string, info fs.FileInfo, replacement []byte) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if !safeName(name) || len(m.Entries) >= maxEntries || seen[strings.ToLower(name)] {
			return ErrInvalid
		}
		seen[strings.ToLower(name)] = true
		item := entry{Name: name, Mode: 0600, Directory: info.IsDir()}
		if item.Directory {
			item.Mode = 0700
		} else if info.Mode()&0100 != 0 {
			item.Mode = 0700
		}
		if !item.Directory {
			item.Size = info.Size()
			if replacement != nil {
				item.Size = int64(len(replacement))
			}
			if item.Size < 0 || item.Size > maxDataBytes-result.Bytes {
				return ErrInvalid
			}
		}
		header := &tar.Header{Name: name, Mode: item.Mode, Size: item.Size, ModTime: info.ModTime(), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if item.Directory {
			header.Typeflag = tar.TypeDir
		}
		if e := writer.WriteHeader(header); e != nil {
			return e
		}
		if !item.Directory {
			hash := sha256.New()
			if replacement != nil {
				if _, e := io.MultiWriter(writer, hash).Write(replacement); e != nil {
					return e
				}
			} else {
				input, e := root.Open(name)
				if e != nil {
					return e
				}
				defer input.Close()
				current, e := input.Stat()
				named, ne := root.Lstat(name)
				if e != nil || ne != nil || !current.Mode().IsRegular() || !named.Mode().IsRegular() || !os.SameFile(current, named) || current.Size() != item.Size {
					return ErrInvalid
				}
				if _, e = io.CopyN(io.MultiWriter(writer, hash), contextReader(ctx, input), item.Size); e != nil {
					return e
				}
				var extra [1]byte
				n, re := input.Read(extra[:])
				if n != 0 || re != io.EOF {
					return ErrInvalid
				}
				after, e := input.Stat()
				if e != nil || after.Size() != current.Size() || !after.ModTime().Equal(current.ModTime()) {
					return ErrInvalid
				}
			}
			item.SHA256 = hex.EncodeToString(hash.Sum(nil))
			result.Files++
			result.Bytes += item.Size
		}
		m.Entries = append(m.Entries, item)
		return nil
	}
	keyWritten := false
	e = fs.WalkDir(root.FS(), ".", func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "." {
			return nil
		}
		if strings.EqualFold(name, controlName) {
			if !actualControl(lock.DataDir, name) {
				return ErrInvalid
			}
			return fs.SkipDir
		}
		if reserved(name) {
			if d.IsDir() {
				return ErrInvalid
			}
			return nil
		}
		info, e := root.Lstat(name)
		if e != nil {
			return e
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("special files and symlinks are not supported: %w", ErrInvalid)
		}
		var replacement []byte
		if name == "vault.key" {
			if info.Size() != 32 && external == nil {
				return ErrInvalid
			}
			replacement = external
			keyWritten = true
		}
		return writeEntry(name, info, replacement)
	})
	if e != nil {
		return result, e
	}
	if !keyWritten {
		if external == nil {
			return result, fmt.Errorf("vault key is missing: %w", ErrInvalid)
		}
		if e = writeEntry("vault.key", keyFileInfo{}, external); e != nil {
			return result, e
		}
	}
	m.Result = result
	body, e := json.Marshal(m)
	if e != nil || int64(len(body)) > maxManifestBytes {
		return result, ErrInvalid
	}
	if e = writer.WriteHeader(&tar.Header{Name: manifestName, Mode: 0600, Size: int64(len(body)), Typeflag: tar.TypeReg}); e != nil {
		return result, e
	}
	if _, e = writer.Write(body); e != nil {
		return result, e
	}
	if e = writer.Close(); e != nil {
		return result, e
	}
	if e = compressed.Close(); e != nil {
		return result, e
	}
	if e = encrypted.Close(); e != nil {
		return result, e
	}
	if e = f.Sync(); e != nil {
		return result, e
	}
	if e = f.Close(); e != nil {
		return result, e
	}
	f = nil
	// Link publishes without replacing a concurrent destination. All files share
	// one filesystem; unsupported filesystems fail without touching existing data.
	if e = os.Link(temporary, destination); e != nil {
		return result, e
	}
	if e = syncDirectory(parent); e != nil {
		return result, e
	}
	result.ArchiveSHA256 = hex.EncodeToString(digest.Sum(nil))
	return result, nil
}

type keyFileInfo struct{}

func (keyFileInfo) Name() string       { return "vault.key" }
func (keyFileInfo) Size() int64        { return 32 }
func (keyFileInfo) Mode() fs.FileMode  { return 0600 }
func (keyFileInfo) ModTime() time.Time { return time.Time{} }
func (keyFileInfo) IsDir() bool        { return false }
func (keyFileInfo) Sys() any           { return nil }
func exists(path string) bool {
	_, e := os.Lstat(path)
	return e == nil || !errors.Is(e, os.ErrNotExist)
}

// Verify authenticates every frame and validates the complete tar manifest. No
// runtime data directory or plaintext archive is created by this operation.
func Verify(ctx context.Context, opt Options) (Result, error) {
	m, _, e := readArchive(ctx, opt, nil)
	return m.Result, e
}
func readArchive(ctx context.Context, opt Options, target *os.Root) (m manifest, manifestSHA string, err error) {
	if e := ctx.Err(); e != nil {
		return m, "", e
	}
	f, e := os.Open(opt.File)
	if e != nil {
		return m, "", e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() {
		return m, "", ErrInvalid
	}
	digest := sha256.New()
	encrypted, e := newEncryptedReader(contextReader(ctx, io.TeeReader(f, digest)), opt.Passphrase)
	if e != nil {
		return m, "", e
	}
	compressed, e := gzip.NewReader(encrypted)
	if e != nil {
		return m, "", ErrIntegrity
	}
	defer compressed.Close()
	compressed.Multistream(false)
	limited := &io.LimitedReader{R: compressed, N: maxDataBytes + int64(maxEntries+2)*2048 + maxManifestBytes}
	reader := tar.NewReader(limited)
	observed := []entry{}
	seen := map[string]bool{}
	directories := map[string]bool{}
	var total int64
	files := 0
	found := false
	var sourceMode modeRecord
	vaultHash := ""
	for {
		if e = ctx.Err(); e != nil {
			return m, "", e
		}
		h, e := reader.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return m, "", ErrIntegrity
		}
		if found {
			return m, "", ErrIntegrity
		}
		if h.Name == manifestName {
			if h.Typeflag != tar.TypeReg || h.Size < 1 || h.Size > maxManifestBytes {
				return m, "", ErrIntegrity
			}
			body, e := readBounded(reader, maxManifestBytes)
			if e != nil {
				return m, "", ErrIntegrity
			}
			d := json.NewDecoder(strings.NewReader(string(body)))
			d.DisallowUnknownFields()
			if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF {
				return m, "", ErrIntegrity
			}
			sum := sha256.Sum256(body)
			manifestSHA = hex.EncodeToString(sum[:])
			found = true
			continue
		}
		if !safeName(h.Name) || reserved(h.Name) || seen[strings.ToLower(h.Name)] || len(observed) >= maxEntries || h.Size < 0 || h.Size > maxDataBytes-total || h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir || h.Linkname != "" {
			return m, "", ErrIntegrity
		}
		seen[strings.ToLower(h.Name)] = true
		item := entry{Name: h.Name, Size: h.Size, Directory: h.Typeflag == tar.TypeDir, Mode: h.Mode}
		if parent := path.Dir(h.Name); parent != "." && !directories[parent] {
			return m, "", ErrIntegrity
		}
		if item.Directory {
			if item.Size != 0 || item.Mode != 0700 {
				return m, "", ErrIntegrity
			}
			directories[h.Name] = true
			if target != nil {
				if e = target.MkdirAll(h.Name, 0700); e != nil {
					return m, "", e
				}
			}
		} else {
			if item.Mode != 0600 && item.Mode != 0700 {
				return m, "", ErrIntegrity
			}
			hash := sha256.New()
			var out io.Writer = hash
			var output *os.File
			var mode bytes.Buffer
			if h.Name == modeFile {
				if h.Size > 1024 {
					return m, "", ErrIntegrity
				}
				out = io.MultiWriter(out, &mode)
			}
			if target != nil {
				if e = target.MkdirAll(path.Dir(h.Name), 0700); e != nil {
					return m, "", e
				}
				output, e = target.OpenFile(h.Name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fs.FileMode(item.Mode))
				if e != nil {
					return m, "", e
				}
				out = io.MultiWriter(hash, output)
			}
			if target != nil && h.Name == modeFile {
				out = io.MultiWriter(hash, output, &mode)
			}
			_, copyErr := io.CopyN(out, contextReader(ctx, reader), h.Size)
			if output != nil {
				if copyErr == nil {
					copyErr = output.Sync()
				}
				closeErr := output.Close()
				if copyErr == nil {
					copyErr = closeErr
				}
			}
			if copyErr != nil {
				return m, "", copyErr
			}
			if h.Name == modeFile && (standaloneModeData(mode.Bytes()) != nil || json.Unmarshal(mode.Bytes(), &sourceMode) != nil) {
				return m, "", ErrIntegrity
			}
			item.SHA256 = hex.EncodeToString(hash.Sum(nil))
			if h.Name == "vault.key" {
				vaultHash = item.SHA256
			}
			total += h.Size
			files++
		}
		observed = append(observed, item)
	}
	// Finish gzip validation and then consume the authenticated terminal frame.
	// Only tar's bounded zero padding may remain after its end markers.
	trailing, e := readBounded(limited, 1024)
	if e != nil || limited.N == 0 {
		return m, "", ErrIntegrity
	}
	for _, b := range trailing {
		if b != 0 {
			return m, "", ErrIntegrity
		}
	}
	extra, e := readBounded(encrypted, 0)
	if e != nil || len(extra) != 0 || !encrypted.final {
		return m, "", ErrIntegrity
	}
	if !found || m.Format != 1 || len(m.Result.BackupID) != 32 || m.Result.CreatedAt.IsZero() || len(m.Result.Version) > 128 || m.Result.Files != files || m.Result.Bytes != total || m.Result.ArchiveSHA256 != "" || m.Result.PreviousDataDir != "" || m.Result.Unchanged || len(m.Entries) != len(observed) || !seen[modeFile] || !seen["vault.key"] || directories[modeFile] || directories["vault.key"] || sourceMode.VaultKeySHA256 != vaultHash {
		return m, "", ErrIntegrity
	}
	if _, e = hex.DecodeString(m.Result.BackupID); e != nil {
		return m, "", ErrIntegrity
	}
	for i, item := range observed {
		if item != m.Entries[i] {
			return m, "", ErrIntegrity
		}
		if item.Name == "vault.key" && (item.Directory || item.Size != 32) {
			return m, "", ErrIntegrity
		}
	}
	m.Result.ArchiveSHA256 = hex.EncodeToString(digest.Sum(nil))
	return m, manifestSHA, nil
}
