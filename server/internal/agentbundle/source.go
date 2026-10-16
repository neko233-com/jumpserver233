package agentbundle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SourceDigest binds a generated bundle to its local authoritative source. It
// is used by generation and tests, never required on a deployed target host.
func SourceDigest(root string) (string, error) {
	var names []string
	for _, dir := range []string{"internal/hostagent", "cmd/jms-agent", "internal/agentbundle/generate"} {
		entries, e := os.ReadDir(filepath.Join(root, dir))
		if e != nil {
			return "", e
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") && !strings.HasSuffix(entry.Name(), "_test.go") {
				names = append(names, filepath.ToSlash(filepath.Join(dir, entry.Name())))
			}
		}
	}
	names = append(names, "go.mod", "go.sum", "internal/agentbundle/source.go", "internal/agentbundle/bundle.go")
	sort.Strings(names)
	h := sha256.New()
	for _, name := range names {
		b, e := os.ReadFile(filepath.Join(root, name))
		if e != nil {
			return "", e
		}
		fmt.Fprintf(h, "%s\x00%d\x00", name, len(b))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
