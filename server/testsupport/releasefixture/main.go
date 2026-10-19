// Build a local synthetic QA archive using a replacement native server.
// This command cannot publish or alter a formal Release.
package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/neko233-com/jumpserver233/server/internal/releasebundle"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "synthetic release fixture failed")
		os.Exit(1)
	}
}
func run() error {
	base := flag.String("base-dir", "", "")
	binary := flag.String("server-binary", "", "")
	output := flag.String("out", "", "")
	version := flag.String("version", "", "")
	flag.Parse()
	if *base == "" || *binary == "" || *output == "" || flag.NArg() != 0 {
		return errors.New("invalid arguments")
	}
	root, e := os.OpenRoot(*base)
	if e != nil {
		return e
	}
	defer root.Close()
	body, e := root.ReadFile("manifest.json")
	if e != nil {
		return e
	}
	var m releasebundle.Manifest
	if json.Unmarshal(body, &m) != nil || !m.Valid() {
		return errors.New("invalid manifest")
	}
	m.Version = *version
	m.ActivationProtocol = 1
	names := make([]string, 0, len(m.Files))
	for name := range m.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	f, e := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, name := range names {
		var input *os.File
		if name == "jms233-server" || name == "jms233-server.exe" {
			input, e = os.Open(*binary)
		} else {
			input, e = root.Open(name)
		}
		if e != nil {
			return e
		}
		info, e := input.Stat()
		if e != nil || !info.Mode().IsRegular() {
			input.Close()
			return errors.New("invalid fixture file")
		}
		item := m.Files[name]
		mode := int64(0600)
		if item.Executable {
			mode = 0700
		}
		if e = tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: info.Size(), Typeflag: tar.TypeReg, ModTime: m.BuiltAt}); e != nil {
			input.Close()
			return e
		}
		sum := sha256.New()
		n, e := io.Copy(io.MultiWriter(tw, sum), input)
		input.Close()
		if e != nil {
			return e
		}
		item.Bytes = n
		item.SHA256 = hex.EncodeToString(sum.Sum(nil))
		m.Files[name] = item
	}
	if !m.Valid() {
		return errors.New("invalid fixture manifest")
	}
	body, e = json.Marshal(m)
	if e != nil {
		return e
	}
	if e = tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(body)), Typeflag: tar.TypeReg}); e != nil {
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
	return f.Sync()
}
