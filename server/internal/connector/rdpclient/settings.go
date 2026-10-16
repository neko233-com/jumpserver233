package rdpclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"strings"
	"unicode/utf8"
)

var (
	ErrInvalid           = errors.New("invalid RDP configuration or input")
	ErrUnavailable       = errors.New("RDP session unavailable")
	ErrProtocol          = errors.New("invalid RDP stream")
	ErrReadOnly          = errors.New("RDP asset is read only")
	ErrClipboard         = errors.New("RDP clipboard is not available")
	ErrClipboardNotReady = errors.New("remote RDP clipboard text is not ready")
	ErrTextUnsupported   = errors.New("remote RDP server did not advertise Unicode input")
)

const MaxPixels = 3840 * 2160
const MaxClipboard = 64 * 1024

type Settings struct {
	Security   string `json:"security"`
	Domain     string `json:"domain,omitempty"`
	ServerName string `json:"server_name,omitempty"`
	RootCAPEM  string `json:"root_ca_pem,omitempty"`
	Width      int    `json:"width"`
	Height     int    `json:"height"`
	ReadOnly   bool   `json:"read_only"`
	Clipboard  bool   `json:"clipboard"`
}
type Target struct {
	Host string
	Port int
	Settings
	Gateways []sshclient.Hop
}

func Normalize(s Settings) (Settings, error) {
	if s.Security == "" {
		s.Security = "nla"
	}
	if s.Width == 0 {
		s.Width = 1280
	}
	if s.Height == 0 {
		s.Height = 720
	}
	if s.Security != "nla" && s.Security != "tls" || !validSize(s.Width, s.Height) || len(s.Domain) > 128 || strings.ContainsAny(s.Domain, "\x00\r\n/\\") || len(s.ServerName) > 253 || strings.ContainsAny(s.ServerName, "\x00\r\n /\\@:") || len(s.RootCAPEM) > 64*1024 {
		return Settings{}, ErrInvalid
	}
	if s.RootCAPEM != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(s.RootCAPEM)) {
		return Settings{}, ErrInvalid
	}
	return s, nil
}
func validSize(w, h int) bool {
	return w >= 320 && w <= 3840 && h >= 200 && h <= 2160 && w*h <= MaxPixels
}
func ValidCredential(s string) bool {
	return s != "" && len(s) <= 4096 && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
}
func tlsConfig(t Target) (*tls.Config, error) {
	name := t.ServerName
	if name == "" {
		name = t.Host
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name}
	if t.RootCAPEM != "" {
		pool, e := x509.SystemCertPool()
		if e != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(t.RootCAPEM)) {
			return nil, ErrInvalid
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

type Input struct {
	Type     string `json:"type"`
	Action   string `json:"action,omitempty"`
	X        int    `json:"x,omitempty"`
	Y        int    `json:"y,omitempty"`
	Button   string `json:"button,omitempty"`
	Down     bool   `json:"down,omitempty"`
	Delta    int    `json:"delta,omitempty"`
	Code     int    `json:"code,omitempty"`
	Extended bool   `json:"extended,omitempty"`
	Text     string `json:"text,omitempty"`
}
