// The generator builds both supported native helpers before embedding them.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/neko233-com/jumpserver233/server/internal/agentbundle"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
)

func generate() error {
	wd, e := os.Getwd()
	if e != nil {
		return e
	}
	root := filepath.Clean(filepath.Join(wd, "../.."))
	if b, e := os.ReadFile(filepath.Join(root, "go.mod")); e != nil || !strings.HasPrefix(strings.ReplaceAll(string(b), "\r\n", "\n"), "module github.com/neko233-com/jumpserver233/server\n") {
		return fmt.Errorf("run from internal/agentbundle using go generate")
	}
	digest, e := agentbundle.SourceDigest(root)
	if e != nil {
		return e
	}
	manifest := agentbundle.Manifest{Version: hostagent.Version, SourceSHA256: digest}
	var existing agentbundle.Manifest
	if data, e := os.ReadFile(filepath.Join(wd, "artifacts/manifest.json")); e == nil && json.Unmarshal(data, &existing) == nil && existing.Version == manifest.Version && existing.SourceSHA256 == digest {
		valid := true
		for _, platform := range []string{"linux-amd64", "linux-arm64"} {
			if _, e := agentbundle.Get(platform); e != nil {
				valid = false
			}
		}
		if valid {
			fmt.Println("Native agent bundle is current")
			return nil
		}
	}
	for _, arch := range []string{"amd64", "arm64"} {
		platform := "linux-" + arch
		name := "jms-agent-" + platform
		output := filepath.Join(wd, "artifacts", name)
		tmp, e := os.CreateTemp(filepath.Join(wd, "artifacts"), ".build-*")
		if e != nil {
			return e
		}
		tempName := tmp.Name()
		tmp.Close()
		defer os.Remove(tempName)
		command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=", "-o", tempName, "./cmd/jms-agent")
		command.Dir = root
		for _, value := range os.Environ() {
			key, _, _ := strings.Cut(value, "=")
			switch key {
			case "GOOS", "GOARCH", "CGO_ENABLED", "GOAMD64", "GOARM64", "GOFLAGS":
				continue
			}
			command.Env = append(command.Env, value)
		}
		command.Env = append(command.Env, "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0", "GOAMD64=v1", "GOARM64=v8.0", "GOFLAGS=")
		if b, e := command.CombinedOutput(); e != nil {
			return fmt.Errorf("native %s build: %w: %s", platform, e, b)
		}
		data, e := os.ReadFile(tempName)
		if e != nil {
			return e
		}
		sum := sha256.Sum256(data)
		if old, e := os.Lstat(output); e == nil && (!old.Mode().IsRegular() || old.Mode()&os.ModeSymlink != 0) {
			return fmt.Errorf("unexpected agent build output")
		}
		// WriteFile works across Windows and Linux when replacing an old bundle.
		if e = os.WriteFile(output, data, 0600); e != nil {
			return e
		}
		manifest.Artifacts = append(manifest.Artifacts, agentbundle.Artifact{Platform: platform, File: name, SHA256: hex.EncodeToString(sum[:]), Size: len(data)})
	}
	data, _ := json.MarshalIndent(manifest, "", "  ")
	if e = os.WriteFile(filepath.Join(wd, "artifacts/manifest.json"), append(data, '\n'), 0600); e != nil {
		return e
	}
	fmt.Println("Built verified linux-amd64 and linux-arm64 native agent bundle")
	return nil
}

func main() {
	if e := generate(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
