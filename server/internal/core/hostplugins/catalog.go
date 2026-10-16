// Package hostplugins defines the managed SSH host tools and their immutable
// release artifacts. Remote credentials stay in the asset connector.
package hostplugins

import (
	"errors"
	"strings"
)

var (
	ErrInvalid     = errors.New("invalid host plugin operation")
	ErrUnsupported = errors.New("host plugin platform is unsupported")
	ErrIntegrity   = errors.New("host plugin artifact integrity check failed")
	ErrConflict    = errors.New("host plugin state conflicts with the request")
	ErrAutostart   = errors.New("host plugin cron supervisor is unavailable")
	ErrProtection  = errors.New("host protection prerequisites or management-source protection failed")
	ErrRecovery    = errors.New("native host recovery bundle is unavailable")
)

type Artifact struct {
	Platform     string `json:"platform"`
	URL          string `json:"url"`
	SHA256       string `json:"sha256"`
	ArchiveEntry string `json:"archive_entry,omitempty"`
}
type Definition struct {
	ID             string     `json:"id"`
	Version        string     `json:"version"`
	Source         string     `json:"source"`
	NameKey        string     `json:"name_key"`
	DescriptionKey string     `json:"description_key"`
	Executable     string     `json:"executable"`
	Actions        []string   `json:"actions"`
	Artifacts      []Artifact `json:"artifacts"`
	Releases       []Release  `json:"releases,omitempty"`
}

type Release struct {
	Version   string     `json:"version"`
	Source    string     `json:"source"`
	Artifacts []Artifact `json:"artifacts"`
}

// Catalog values were checked against official GitHub release asset digests on
// 2026-10-16. Installation never resolves "latest" at execution time.
func Catalog() []Definition {
	ban := Definition{ID: "banhack233", Version: "0.2.3", Source: "https://github.com/neko233-com/banhack233/releases/tag/v0.2.3", NameKey: "hostPlugins.banhack233Name", DescriptionKey: "hostPlugins.banhack233Description", Executable: "banhack233", Actions: []string{"detect", "install", "status", "start", "stop", "doctor", "scan", "keepalive_preview", "keepalive_apply", "autostart_enable", "autostart_disable", "uninstall"}}
	for _, v := range [][2]string{
		{"linux-amd64", "c637e41412912db29a62c46a66d8b0c139cea5eb97963f592703c2e9aaa4803f"},
		{"linux-arm64", "be4d80f9534484d40e2fb5d04a40c950533449d4be9097ee9d0738cb2a1bbb01"},
		{"darwin-amd64", "c1dff046cf8af4867d0377ccba9e838eb19b194791c39b531731be10a9147220"},
		{"darwin-arm64", "a623ac6341e54918ca7e3d3d67df2c7d48432270114b45d3df77ce501d7ebece"},
	} {
		ban.Artifacts = append(ban.Artifacts, Artifact{Platform: v[0], SHA256: v[1], URL: "https://github.com/neko233-com/banhack233/releases/download/v0.2.3/banhack233-" + v[0]})
	}
	node := Definition{ID: "node_exporter", Version: "1.12.1", Source: "https://github.com/prometheus/node_exporter/releases/tag/v1.12.1", NameKey: "hostPlugins.nodeExporterName", DescriptionKey: "hostPlugins.nodeExporterDescription", Executable: "node_exporter", Actions: []string{"detect", "install", "status", "start", "stop", "metrics", "autostart_enable", "autostart_disable", "uninstall"}}
	for _, v := range [][2]string{
		{"linux-amd64", "b51d8a76aa2a9156a55d501aca6276fae09e262259a5e4e831d2c2222f084e63"},
		{"linux-arm64", "ad35b605f9954b9f1ffddf5ba054bdc5a98d790b9eae5291e1eeb83f1ecbd0e7"},
		{"darwin-amd64", "3506a6d788b768a3c2cd1f58dc97b9ff3fecc5ac9196623d582982db2aa9d0f6"},
		{"darwin-arm64", "35b246a34af55a8f0c3f11067f17aecf9836cfd4689bde364776b3a4ad3a84d6"},
	} {
		name := "node_exporter-1.12.1." + v[0]
		node.Artifacts = append(node.Artifacts, Artifact{Platform: v[0], SHA256: v[1], URL: "https://github.com/prometheus/node_exporter/releases/download/v1.12.1/" + name + ".tar.gz", ArchiveEntry: name + "/node_exporter"})
	}
	ban.Releases = []Release{previousRelease("banhack233", "0.2.2", "neko233-com/banhack233", [][2]string{
		{"linux-amd64", "296b6be814a0a96840c903a8cb6558be42eeb4552a0ff10c762b3ffc84beb60f"},
		{"linux-arm64", "acbf965f58938a4ffb07a142b81ad631fde0ce3e0feee847144a7bcdb916a9f8"},
	})}
	node.Releases = []Release{previousRelease("node_exporter", "1.12.0", "prometheus/node_exporter", [][2]string{
		{"linux-amd64", "b206d98e98a431f2687d4c217abb4b15c46a6b272896113ce9a1585cf1a75d1f"},
		{"linux-arm64", "4ea211ce95224acb7f7c932693cb25f91f7fbe202c86bf6dc943c8569b3f6bac"},
	})}
	for _, d := range []*Definition{&ban, &node} {
		d.Actions = append(d.Actions, "upgrade", "rollback", "systemd_status", "systemd_enable", "systemd_disable")
	}
	ban.Actions = append(ban.Actions, "protection_status", "protection_apply", "protection_rollback", "agent_update", "events", "events_collect")
	return []Definition{ban, node}
}

func previousRelease(id, version, repo string, hashes [][2]string) Release {
	r := Release{Version: version, Source: "https://github.com/" + repo + "/releases/tag/v" + version}
	for _, entry := range hashes {
		name := id + "-" + entry[0]
		a := Artifact{Platform: entry[0], SHA256: entry[1]}
		if id == "node_exporter" {
			name = id + "-" + version + "." + entry[0]
			a.ArchiveEntry = name + "/node_exporter"
			name += ".tar.gz"
		}
		a.URL = "https://github.com/" + repo + "/releases/download/v" + version + "/" + name
		r.Artifacts = append(r.Artifacts, a)
	}
	return r
}

func LookupVersion(id, version string) (Definition, error) {
	d, e := Lookup(id)
	if e != nil {
		return Definition{}, e
	}
	if version == d.Version {
		return d, nil
	}
	for _, r := range d.Releases {
		if r.Version == version {
			d.Version, d.Source, d.Artifacts = r.Version, r.Source, r.Artifacts
			return d, nil
		}
	}
	return Definition{}, ErrInvalid
}

// Catalog order defines the only supported forward transition. Rollback needs
// a verified on-host checkpoint, not a caller-selected downgrade.
func CanUpgrade(id, from, to string) bool {
	d, e := Lookup(id)
	if e != nil || to != d.Version || from == to {
		return false
	}
	_, e = LookupVersion(id, from)
	return e == nil
}
func Lookup(id string) (Definition, error) {
	for _, d := range Catalog() {
		if d.ID == id {
			return d, nil
		}
	}
	return Definition{}, ErrInvalid
}
func (d Definition) Artifact(platform string) (Artifact, error) {
	for _, a := range d.Artifacts {
		if a.Platform == platform {
			return a, nil
		}
	}
	return Artifact{}, ErrUnsupported
}
func (d Definition) Allows(action string) bool {
	for _, a := range d.Actions {
		if a == action {
			return true
		}
	}
	return false
}
func Platform(osName, architecture string) (string, error) {
	osName = strings.ToLower(strings.TrimSpace(osName))
	architecture = strings.ToLower(strings.TrimSpace(architecture))
	switch osName {
	case "linux", "darwin":
	default:
		return "", ErrUnsupported
	}
	switch architecture {
	case "x86_64", "amd64":
		architecture = "amd64"
	case "aarch64", "arm64":
		architecture = "arm64"
	default:
		return "", ErrUnsupported
	}
	return osName + "-" + architecture, nil
}
