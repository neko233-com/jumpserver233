// Package agentbundle embeds native recovery helpers in the server binary.
package agentbundle

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
)

//go:generate go run ./generate
//go:embed artifacts/*
var files embed.FS

var ErrUnavailable = errors.New("native agent bundle unavailable; run go generate ./internal/agentbundle before building the server")

type Artifact struct {
	Platform string `json:"platform"`
	File     string `json:"file"`
	SHA256   string `json:"sha256"`
	Size     int    `json:"size"`
}
type Manifest struct {
	Version      string     `json:"version"`
	SourceSHA256 string     `json:"source_sha256"`
	Artifacts    []Artifact `json:"artifacts"`
}
type Binary struct {
	Data    []byte
	SHA256  string
	Version string
}

func Get(platform string) (Binary, error) {
	if platform != "linux-amd64" && platform != "linux-arm64" {
		return Binary{}, ErrUnavailable
	}
	raw, e := files.ReadFile("artifacts/manifest.json")
	if e != nil || len(raw) > 4096 {
		return Binary{}, ErrUnavailable
	}
	var m Manifest
	if json.Unmarshal(raw, &m) != nil || m.Version != hostagent.Version {
		return Binary{}, ErrUnavailable
	}
	for _, a := range m.Artifacts {
		if a.Platform != platform {
			continue
		}
		if a.File != "jms-agent-"+platform || a.Size < 1 || a.Size > 16<<20 {
			return Binary{}, ErrUnavailable
		}
		data, e := files.ReadFile("artifacts/" + a.File)
		if e != nil || len(data) != a.Size {
			return Binary{}, ErrUnavailable
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != a.SHA256 {
			return Binary{}, ErrUnavailable
		}
		if len(data) < 20 || string(data[:4]) != "\x7fELF" || data[4] != 2 || data[5] != 1 || platform == "linux-amd64" && data[18] != 62 || platform == "linux-arm64" && data[18] != 183 {
			return Binary{}, ErrUnavailable
		}
		return Binary{Data: data, SHA256: a.SHA256, Version: m.Version}, nil
	}
	return Binary{}, fmt.Errorf("%w: %s", ErrUnavailable, platform)
}
