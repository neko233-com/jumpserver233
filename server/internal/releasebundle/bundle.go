// Package releasebundle defines portable, immutable native release archives.
package releasebundle

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"time"
)

var ErrInvalid = errors.New("invalid native release archive")
var safePath = regexp.MustCompile(`^[A-Za-z0-9_./-]+$`)
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var version = regexp.MustCompile(`^v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)
var commit = regexp.MustCompile(`^[a-f0-9]{40}$`)

type File struct {
	SHA256     string `json:"sha256"`
	Bytes      int64  `json:"bytes"`
	Executable bool   `json:"executable"`
}
type Manifest struct {
	Schema       int             `json:"schema"`
	Version      string          `json:"version"`
	Commit       string          `json:"commit"`
	BuiltAt      time.Time       `json:"built_at"`
	Platform     string          `json:"platform"`
	Architecture string          `json:"architecture"`
	Files        map[string]File `json:"files"`
}

func ValidPath(name string) bool {
	if !fs.ValidPath(name) || name == "." || len(name) > 512 || !safePath.MatchString(name) {
		return false
	}
	for _, p := range strings.Split(name, "/") {
		if strings.HasSuffix(p, ".") {
			return false
		}
		base := strings.ToUpper(strings.SplitN(p, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
			return false
		}
	}
	return true
}
func (m Manifest) Valid() bool {
	if m.Schema != 1 || !version.MatchString(m.Version) || !commit.MatchString(m.Commit) || m.BuiltAt.IsZero() || len(m.Files) < 3 || len(m.Files) > 20000 || (m.Platform != "linux" && m.Platform != "darwin" && m.Platform != "windows") || (m.Architecture != "amd64" && m.Architecture != "arm64") {
		return false
	}
	suffix := ""
	if m.Platform == "windows" {
		suffix = ".exe"
	}
	seen := map[string]bool{}
	var total int64
	for name, f := range m.Files {
		if !ValidPath(name) || name == "manifest.json" || seen[strings.ToLower(name)] || !digest.MatchString(f.SHA256) || f.Bytes < 0 || f.Bytes > (512<<20)-total {
			return false
		}
		seen[strings.ToLower(name)] = true
		total += f.Bytes
		binary := name == "jms"+suffix || name == "jms233-server"+suffix
		if !binary && !strings.HasPrefix(name, "web/") || binary != f.Executable {
			return false
		}
	}
	for name := range m.Files {
		parts := strings.Split(strings.ToLower(name), "/")
		for i := 1; i < len(parts); i++ {
			if seen[strings.Join(parts[:i], "/")] {
				return false
			}
		}
	}
	a, aok := m.Files["jms"+suffix]
	b, bok := m.Files["jms233-server"+suffix]
	_, web := m.Files["web/index.html"]
	return aok && bok && web && a.Bytes > 0 && b.Bytes > 0
}

// Verify checks every file and the exact archive digest without extracting data.
func Verify(path, sha, platform, arch string) (Manifest, error) {
	var m Manifest
	if !digest.MatchString(sha) {
		return m, ErrInvalid
	}
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Size() > 256<<20 {
		return m, ErrInvalid
	}
	f, e := os.Open(path)
	if e != nil {
		return m, e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) {
		return m, ErrInvalid
	}
	hash := sha256.New()
	n, e := io.Copy(hash, io.LimitReader(f, (256<<20)+1))
	if e != nil || n != info.Size() || hex.EncodeToString(hash.Sum(nil)) != sha {
		return m, ErrInvalid
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return m, e
	}
	input := bufio.NewReader(f)
	gz, e := gzip.NewReader(input)
	if e != nil {
		return m, ErrInvalid
	}
	defer gz.Close()
	gz.Multistream(false)
	tr := tar.NewReader(gz)
	observed := map[string]File{}
	headers := map[string][]byte{}
	seen := map[string]bool{}
	manifestRead := false
	var total int64
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil || manifestRead || h.Typeflag != tar.TypeReg || h.Linkname != "" || !ValidPath(h.Name) || seen[strings.ToLower(h.Name)] || h.Size < 0 || h.Size > (512<<20)-total || len(observed) > 20000 {
			return m, ErrInvalid
		}
		seen[strings.ToLower(h.Name)] = true
		total += h.Size
		if h.Name == "manifest.json" {
			if h.Size > 8<<20 {
				return m, ErrInvalid
			}
			decoder := json.NewDecoder(io.LimitReader(tr, (8<<20)+1))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&m) != nil || decoder.Decode(new(any)) != io.EOF {
				return m, ErrInvalid
			}
			manifestRead = true
			continue
		}
		if h.Mode != 0600 && h.Mode != 0700 {
			return m, ErrInvalid
		}
		sum := sha256.New()
		var prefix []byte
		if h.Mode == 0700 {
			prefix = make([]byte, min(h.Size, 4096))
			if _, e = io.ReadFull(tr, prefix); e != nil {
				return m, ErrInvalid
			}
			sum.Write(prefix)
			headers[h.Name] = prefix
		}
		size, e := io.Copy(sum, tr)
		size += int64(len(prefix))
		if e != nil || size != h.Size {
			return m, ErrInvalid
		}
		observed[h.Name] = File{SHA256: hex.EncodeToString(sum.Sum(nil)), Bytes: size, Executable: h.Mode == 0700}
	}
	// tar may leave zero block padding; authenticate the gzip footer and reject
	// another compressed member, nonzero trailing plaintext or physical junk.
	padding, e := io.ReadAll(io.LimitReader(gz, (1<<20)+1))
	if e != nil || len(padding) > 1<<20 {
		return m, ErrInvalid
	}
	for _, b := range padding {
		if b != 0 {
			return m, ErrInvalid
		}
	}
	if _, e = input.ReadByte(); e != io.EOF {
		return m, ErrInvalid
	}
	if !manifestRead || !m.Valid() || m.Platform != platform || m.Architecture != arch || len(m.Files) != len(observed) {
		return m, ErrInvalid
	}
	for name, expected := range m.Files {
		if observed[name] != expected {
			return m, ErrInvalid
		}
		if expected.Executable && !binaryTarget(headers[name], platform, arch) {
			return m, ErrInvalid
		}
	}
	return m, nil
}

func binaryTarget(b []byte, platform, arch string) bool {
	if len(b) < 64 {
		return false
	}
	switch platform {
	case "linux":
		machine := uint16(62)
		if arch == "arm64" {
			machine = 183
		}
		kind := binary.LittleEndian.Uint16(b[16:18])
		return string(b[:4]) == "\x7fELF" && b[4] == 2 && b[5] == 1 && binary.LittleEndian.Uint16(b[18:20]) == machine && (kind == 2 || kind == 3)
	case "darwin":
		cpu := uint32(0x01000007)
		if arch == "arm64" {
			cpu = 0x0100000c
		}
		return binary.LittleEndian.Uint32(b[:4]) == 0xfeedfacf && binary.LittleEndian.Uint32(b[4:8]) == cpu && binary.LittleEndian.Uint32(b[12:16]) == 2
	case "windows":
		p := int(binary.LittleEndian.Uint32(b[60:64]))
		if p < 64 || p > len(b)-26 {
			return false
		}
		machine := uint16(0x8664)
		if arch == "arm64" {
			machine = 0xaa64
		}
		return string(b[:2]) == "MZ" && string(b[p:p+4]) == "PE\x00\x00" && binary.LittleEndian.Uint16(b[p+4:p+6]) == machine && binary.LittleEndian.Uint16(b[p+24:p+26]) == 0x20b
	}
	return false
}
