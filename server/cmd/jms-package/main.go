// jms-package builds native release artifacts; it never publishes a release.
package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/updates"
	"github.com/neko233-com/jumpserver233/server/internal/releasebundle"
)

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run(args []string) (resultErr error) {
	flags := flag.NewFlagSet("jms-package", flag.ContinueOnError)
	v := flags.String("version", "", "")
	commit := flags.String("commit", "", "")
	built := flags.String("built-at", "", "")
	target := flags.String("target", "", "")
	web := flags.String("web-dir", "../web/dist", "")
	output := flags.String("out", "../dist", "")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return errors.New("invalid package arguments")
	}
	version, ok := updates.Version(*v)
	parts := strings.Split(*target, "/")
	at, e := time.Parse(time.RFC3339, *built)
	if !ok || *v != version || len(parts) != 2 || !updates.Supported(parts[0], parts[1]) || e != nil {
		return errors.New("stable version, commit, RFC3339 build time and OS/architecture are required")
	}
	m := releasebundle.Manifest{Schema: 1, Version: version, Commit: *commit, BuiltAt: at, Platform: parts[0], Architecture: parts[1], PreflightProtocol: 1, ActivationProtocol: 1, Files: map[string]releasebundle.File{}}
	// Validate metadata before compiling anything.
	m.Files = map[string]releasebundle.File{"web/index.html": {SHA256: strings.Repeat("0", 64)}, "jms": {SHA256: strings.Repeat("0", 64), Bytes: 1, Executable: true}, "jms233-server": {SHA256: strings.Repeat("0", 64), Bytes: 1, Executable: true}}
	if m.Platform == "windows" {
		m.Files["jms.exe"] = m.Files["jms"]
		delete(m.Files, "jms")
		m.Files["jms233-server.exe"] = m.Files["jms233-server"]
		delete(m.Files, "jms233-server")
	}
	if !m.Valid() {
		return errors.New("invalid package metadata")
	}
	m.Files = map[string]releasebundle.File{}
	if e = os.MkdirAll(*output, 0700); e != nil {
		return e
	}
	canonical, e := filepath.Abs(*output)
	if e != nil {
		return e
	}
	canonical, e = filepath.EvalSymlinks(canonical)
	if e != nil {
		return e
	}
	*output = canonical
	destination := filepath.Join(*output, updates.ArchiveName(version, parts[0], parts[1]))
	for _, path := range []string{destination, destination + ".sha256"} {
		if _, e = os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
			return updates.ErrExists
		}
	}
	stage, e := os.MkdirTemp(*output, ".jms233-package-*")
	if e != nil {
		return e
	}
	defer func() {
		resolved, e := filepath.EvalSymlinks(stage)
		if errors.Is(e, os.ErrNotExist) {
			return
		}
		if e != nil || resolved != stage || filepath.Dir(stage) != canonical || !strings.HasPrefix(filepath.Base(stage), ".jms233-package-") {
			resultErr = errors.Join(resultErr, releasebundle.ErrInvalid)
			return
		}
		resultErr = errors.Join(resultErr, os.RemoveAll(stage))
	}()
	suffix := ""
	if parts[0] == "windows" {
		suffix = ".exe"
	}
	binaries := map[string]string{"jms" + suffix: "./cmd/jms", "jms233-server" + suffix: "./cmd/server"}
	for name, source := range binaries {
		ld := "-s -w -X github.com/neko233-com/jumpserver233/server/internal/buildinfo.Version=" + version + " -X github.com/neko233-com/jumpserver233/server/internal/buildinfo.Commit=" + m.Commit + " -X github.com/neko233-com/jumpserver233/server/internal/buildinfo.BuiltAt=" + at.UTC().Format(time.RFC3339)
		command := exec.CommandContext(context.Background(), "go", "build", "-trimpath", "-buildvcs=false", "-ldflags", ld, "-o", filepath.Join(stage, name), source)
		// Set target values once, independent of inherited cross-build variables.
		for _, value := range os.Environ() {
			key, _, _ := strings.Cut(value, "=")
			if key != "GOOS" && key != "GOARCH" && key != "CGO_ENABLED" {
				command.Env = append(command.Env, value)
			}
		}
		command.Env = append(command.Env, "GOOS="+parts[0], "GOARCH="+parts[1], "CGO_ENABLED=0")
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		if e = command.Run(); e != nil {
			return errors.New("native release compilation failed")
		}
	}
	files := map[string]string{}
	for name := range binaries {
		files[name] = filepath.Join(stage, name)
	}
	e = filepath.WalkDir(*web, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		info, e := d.Info()
		if e != nil || !info.Mode().IsRegular() {
			return releasebundle.ErrInvalid
		}
		rel, e := filepath.Rel(*web, path)
		if e != nil {
			return e
		}
		name := "web/" + filepath.ToSlash(rel)
		if !releasebundle.ValidPath(name) {
			return releasebundle.ErrInvalid
		}
		files[name] = path
		return nil
	})
	if e != nil {
		return e
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	archive, e := os.OpenFile(filepath.Join(stage, "archive.tar.gz"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer archive.Close()
	gz := gzip.NewWriter(archive)
	tw := tar.NewWriter(gz)
	for _, name := range names {
		file, e := os.Open(files[name])
		if e != nil {
			return e
		}
		info, e := file.Stat()
		if e != nil {
			file.Close()
			return e
		}
		mode := int64(0600)
		_, executable := binaries[name]
		if executable {
			mode = 0700
		}
		if e = tw.WriteHeader(&tar.Header{Name: name, Size: info.Size(), Mode: mode, ModTime: at, Typeflag: tar.TypeReg}); e != nil {
			file.Close()
			return e
		}
		sum := sha256.New()
		n, e := io.Copy(io.MultiWriter(tw, sum), file)
		file.Close()
		if e != nil || n != info.Size() {
			return releasebundle.ErrInvalid
		}
		m.Files[name] = releasebundle.File{SHA256: hex.EncodeToString(sum.Sum(nil)), Bytes: n, Executable: executable}
	}
	if !m.Valid() {
		return releasebundle.ErrInvalid
	}
	body, e := json.Marshal(m)
	if e != nil {
		return e
	}
	if e = tw.WriteHeader(&tar.Header{Name: "manifest.json", Size: int64(len(body)), Mode: 0600, ModTime: at, Typeflag: tar.TypeReg}); e != nil {
		return e
	}
	if _, e = tw.Write(body); e != nil {
		return e
	}
	if e = tw.Close(); e != nil {
		return e
	}
	if e = gz.Close(); e != nil {
		return e
	}
	if e = archive.Sync(); e != nil {
		return e
	}
	if e = archive.Close(); e != nil {
		return e
	}
	f, e := os.Open(archive.Name())
	if e != nil {
		return e
	}
	hash := sha256.New()
	_, e = io.Copy(hash, f)
	f.Close()
	if e != nil {
		return e
	}
	sha := hex.EncodeToString(hash.Sum(nil))
	if _, e = releasebundle.Verify(archive.Name(), sha, m.Platform, m.Architecture); e != nil {
		return e
	}
	if e = os.Link(archive.Name(), destination); e != nil {
		return e
	}
	checksum, e := os.OpenFile(destination+".sha256", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	if _, e = checksum.WriteString(sha + "  " + filepath.Base(destination) + "\n"); e != nil {
		checksum.Close()
		return e
	}
	if e = checksum.Close(); e != nil {
		return e
	}
	fmt.Println(filepath.Base(destination) + " " + sha)
	return nil
}
